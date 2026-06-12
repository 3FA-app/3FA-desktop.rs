//! Slint GUI controller: binds the declarative `ui/app.slint` shell to the
//! `threefa_core` library. Owns the live app state (passcode buffer, unlocked
//! vault + DEK, session timers) and refreshes OTP codes once per second.
//!
//! This module only exists in `gui` builds.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use slint::{ModelRc, Timer, TimerMode, VecModel};
use zeroize::{Zeroize, Zeroizing};

/// How long a copied OTP code is allowed to sit on the clipboard before we wipe
/// it (if it hasn't already been replaced by something the user copied).
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(20);

use threefa_core::auth::{FactorProof, PolicyEngine};
use threefa_core::crypto::SecretKey;
use threefa_core::otp::uri::OtpAccount;
use threefa_core::session::{PollResult, Session};
use threefa_core::vault::{StoredAccount, VaultData, VaultFile};
use threefa_core::{data_dir, VAULT_FILENAME};

slint::include_modules!();

/// Live application state, shared into Slint callbacks via `Rc<RefCell<…>>`.
struct AppState {
    vault_path: std::path::PathBuf,
    file: Option<VaultFile>,
    data: Option<VaultData>,
    dek: Option<SecretKey>,
    session: Session,
    /// In-progress passcode entry.
    entry: String,
    /// True when no vault exists yet and we are choosing a new passcode.
    setup: bool,
}

impl AppState {
    fn lock(&mut self) {
        // Drop decrypted material; SecretKey/VaultData zeroize on drop.
        self.data = None;
        self.dek = None;
        // Wipe the passcode buffer's bytes, not just reset its length.
        self.entry.zeroize();
        self.session.lock();
    }

    fn policy_engine(&self) -> PolicyEngine {
        let policy = self
            .data
            .as_ref()
            .map(|d| d.policy)
            .unwrap_or_default();
        PolicyEngine::new(policy)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Entry point invoked from `main.rs`.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = {
        let dir = data_dir();
        let _ = std::fs::create_dir_all(&dir);
        // Restrict the data directory to the owner so other local accounts can't
        // read the (encrypted, but salt-bearing) vault for an offline guess.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        dir.join(VAULT_FILENAME)
    };

    // Load any existing sealed vault file (still locked).
    let file = std::fs::read(&vault_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<VaultFile>(&bytes).ok());
    let setup = file.is_none();

    let state = Rc::new(RefCell::new(AppState {
        vault_path,
        file,
        data: None,
        dek: None,
        session: Session::new(),
        // Pre-size to the passcode length so pushing digits never reallocates
        // (a realloc would copy the secret into a freed heap block we can't wipe).
        entry: String::with_capacity(8),
        setup,
    }));

    let app = AppWindow::new()?;
    app.set_screen(if setup { "setup".into() } else { "lock".into() });
    // Native factors are stubbed for now (see auth::biometric); hide their
    // buttons until a real backend reports availability.
    app.set_biometric_available(false);
    app.set_passkey_available(false);
    app.set_voice_available(false);

    wire_callbacks(&app, &state);
    spawn_tick(&app, &state);

    app.run()?;
    Ok(())
}

fn wire_callbacks(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    let weak = app.as_weak();

    // --- digit pressed on the passcode pad ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_key_pressed(move |digit| {
            let Some(app) = weak.upgrade() else { return };
            let auto_submit;
            {
                let mut s = state.borrow_mut();
                if s.entry.len() < 6 {
                    s.entry.push_str(&digit);
                }
                app.set_entered_length(s.entry.len() as i32);
                auto_submit = s.entry.len() == 6;
            }
            if auto_submit {
                handle_passcode_submit(&app, &state);
            }
        });
    }

    // --- backspace ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_key_backspace(move || {
            let Some(app) = weak.upgrade() else { return };
            let mut s = state.borrow_mut();
            s.entry.pop();
            app.set_entered_length(s.entry.len() as i32);
        });
    }

    // --- add account from otpauth:// uri ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_add_account(move |uri| {
            let Some(app) = weak.upgrade() else { return };
            match OtpAccount::from_uri(uri.as_str()) {
                Ok(acct) => {
                    {
                        let mut s = state.borrow_mut();
                        // Copy out the DEK and path so we don't hold overlapping
                        // borrows of `s` while resealing/persisting.
                        let dek = match s.dek.as_ref() {
                            Some(d) => **d,
                            None => return,
                        };
                        let path = s.vault_path.clone();
                        if let Some(data) = s.data.as_mut() {
                            data.accounts.push(StoredAccount::from(&acct));
                        }
                        let snapshot = match s.data.as_ref() {
                            Some(d) => d.clone(),
                            None => return,
                        };
                        if let Some(file) = s.file.as_mut() {
                            let _ = file.reseal(&dek, &snapshot);
                            persist(&path, file);
                        }
                    }
                    app.set_status("Account added".into());
                    refresh_vault(&app, &state);
                }
                Err(e) => app.set_status(format!("Bad otpauth URI: {e}").into()),
            }
        });
    }

    // --- copy a code to the clipboard ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_copy_code(move |id| {
            let Some(app) = weak.upgrade() else { return };
            let s = state.borrow();
            if let Some(data) = s.data.as_ref() {
                if let Some(acct) = data.accounts.iter().find(|a| a.id == id.as_str()) {
                    if let Ok(code) = acct.current_code(now_unix()) {
                        set_clipboard(&code);
                        app.set_status("Copied to clipboard".into());
                    }
                }
            }
        });
    }

    // --- lock now ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_lock_now(move || {
            let Some(app) = weak.upgrade() else { return };
            state.borrow_mut().lock();
            app.set_screen("lock".into());
            app.set_entered_length(0);
            app.set_status("Locked".into());
        });
    }

    // --- extend session (requires a distinct extra factor) ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_extend_session(move || {
            let Some(app) = weak.upgrade() else { return };
            let mut s = state.borrow_mut();
            let engine = s.policy_engine();
            // With native factors stubbed, the only available extra factor today
            // is re-presenting the passcode out-of-band. A real biometric/passkey
            // proof would be collected here.
            let proofs: Vec<FactorProof> = collect_available_factor_proofs();
            let ok = s.session.try_extend(Instant::now(), &engine, &proofs);
            drop(s);
            app.set_status(
                if ok {
                    "Session extended"
                } else {
                    "Need a second factor to extend"
                }
                .into(),
            );
        });
    }

    // Native factor buttons — wired but inert until backends report available.
    {
        let weak = weak.clone();
        app.on_use_biometric(move || {
            if let Some(app) = weak.upgrade() {
                app.set_status("Biometric backend not yet enabled".into());
            }
        });
    }
    {
        let weak = weak.clone();
        app.on_use_passkey(move || {
            if let Some(app) = weak.upgrade() {
                app.set_status("Passkey backend not yet enabled".into());
            }
        });
    }
    {
        let weak = weak.clone();
        app.on_use_voice(move || {
            if let Some(app) = weak.upgrade() {
                app.set_status("Voice backend not yet enabled".into());
            }
        });
    }
}

/// Try to unlock (or, in setup mode, create) the vault with the 6-digit entry.
fn handle_passcode_submit(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    let mut s = state.borrow_mut();
    // Move the passcode out and guarantee it is wiped when this function returns,
    // on every path (success, wrong passcode, or vault-create error).
    let entry = Zeroizing::new(std::mem::take(&mut s.entry));
    app.set_entered_length(0);

    if s.setup {
        // Create a fresh vault sealed under this passcode.
        let data = VaultData::default();
        match VaultFile::create(entry.as_bytes(), &data) {
            Ok((file, dek)) => {
                persist(&s.vault_path, &file);
                s.file = Some(file);
                s.data = Some(data);
                s.dek = Some(dek);
                s.setup = false;
                s.session.unlock(Instant::now());
                drop(s);
                app.set_screen("vault".into());
                app.set_status("Vault created".into());
                refresh_vault(app, state);
            }
            Err(e) => app.set_status(format!("Could not create vault: {e}").into()),
        }
        return;
    }

    let Some(file) = s.file.clone() else {
        app.set_status("No vault found".into());
        return;
    };
    match file.unlock(entry.as_bytes()) {
        Ok((data, dek)) => {
            s.data = Some(data);
            s.dek = Some(dek);
            s.session.unlock(Instant::now());
            drop(s);
            app.set_screen("vault".into());
            app.set_status("".into());
            refresh_vault(app, state);
        }
        Err(_) => {
            app.set_status("Wrong passcode".into());
        }
    }
}

/// Rebuild the account list model and push it to the window.
fn refresh_vault(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    let s = state.borrow();
    let Some(data) = s.data.as_ref() else { return };
    let unix = now_unix();
    let rows: Vec<AccountView> = data
        .accounts
        .iter()
        .map(|a| {
            let code = a.current_code(unix).unwrap_or_else(|_| "------".into());
            let period = a.period.max(1);
            let remaining = period - (unix % period);
            AccountView {
                id: a.id.clone().into(),
                issuer: a.issuer.clone().into(),
                label: a.label.clone().into(),
                code: code.into(),
                seconds: remaining as i32,
                progress: remaining as f32 / period as f32,
            }
        })
        .collect();
    let model: ModelRc<AccountView> = ModelRc::new(VecModel::from(rows));
    app.set_accounts(model);
    app.set_session_seconds(s.session.session_seconds_remaining(Instant::now()) as i32);
}

/// 1 Hz tick: refresh codes/countdowns and drive the auto-lock state machine.
fn spawn_tick(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    let weak = app.as_weak();
    let state = state.clone();
    let timer = Timer::default();
    timer.start(
        TimerMode::Repeated,
        std::time::Duration::from_secs(1),
        move || {
            let Some(app) = weak.upgrade() else { return };
            let poll = state.borrow_mut().session.poll(Instant::now());
            match poll {
                PollResult::JustLocked => {
                    state.borrow_mut().lock();
                    app.set_screen("lock".into());
                    app.set_entered_length(0);
                    app.set_status("Auto-locked".into());
                }
                PollResult::Active => {
                    // Only the codes/countdown need refreshing while unlocked.
                    if app.get_screen() == "vault" {
                        refresh_vault(&app, &state);
                    }
                }
                PollResult::Locked => {}
            }
        },
    );
    // Keep the timer alive for the program's lifetime.
    std::mem::forget(timer);
}



/// Today the only collectable factor in the GUI is the passcode (native factors
/// stubbed). Returns an empty set so `try_extend` correctly demands a real second
/// factor; this is the seam where a biometric/passkey/voice proof gets added.
fn collect_available_factor_proofs() -> Vec<FactorProof> {
    Vec::new()
}

/// Atomically write the sealed vault with owner-only permissions.
///
/// The payload is already AEAD-encrypted, but the file still carries the KDF salt
/// and parameters, so we (a) restrict it to mode 0600 to deny other local users a
/// copy for offline passcode guessing, and (b) write-temp-then-`rename` so a crash
/// mid-write can never truncate the live vault into an unparseable state — which
/// the loader would treat as "no vault", silently dropping every enrolled account.
fn persist(path: &std::path::Path, file: &VaultFile) {
    // Crash-safe, owner-only write so a power loss mid-save can't truncate the
    // user's only copy of their seeds (see `threefa_core::write_private_atomic`).
    if let Ok(bytes) = serde_json::to_vec(file) {
        if let Err(e) = threefa_core::write_private_atomic(path, &bytes) {
            eprintln!("3fa: failed to persist vault to {}: {e}", path.display());
        }
    }
}

fn set_clipboard(text: &str) {
    if let Ok(mut cb) = arboard::Clipboard::new() {
        if cb.set_text(text.to_string()).is_ok() {
            schedule_clipboard_clear(text.to_string());
        }
    }
}

/// Wipe the clipboard a short while after copying an OTP code, so a one-time code
/// doesn't linger (and sync to other devices via Universal/Cloud Clipboard). Only
/// clears if our code is still there, to avoid clobbering whatever the user copied
/// in the meantime.
fn schedule_clipboard_clear(value: String) {
    let timer = Timer::default();
    timer.start(TimerMode::SingleShot, CLIPBOARD_CLEAR_AFTER, move || {
        if let Ok(mut cb) = arboard::Clipboard::new() {
            if cb.get_text().map(|c| c == value).unwrap_or(false) {
                let _ = cb.set_text(String::new());
            }
        }
    });
    // Keep the one-shot timer alive until it fires.
    std::mem::forget(timer);
}
