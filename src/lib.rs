//! `threefa_core` — the platform-independent heart of the 3FA desktop
//! authenticator: OTP generation, the encrypted vault, authentication factors,
//! the session/auto-lock state machine, and the zero-knowledge sync client.
//!
//! The GUI binary (`main.rs`) is a thin Slint shell over this library; keeping
//! the logic here means it is all unit-testable without a display server.

pub mod auth;
pub mod crypto;
pub mod otp;
pub mod protocol;
pub mod session;
pub mod sync;
pub mod vault;

/// Default on-disk vault filename within the app's data directory.
pub const VAULT_FILENAME: &str = "default.vault";

/// Resolve the per-user data directory where the vault is stored. Uses platform
/// conventions; falls back to the current directory if none is discoverable.
pub fn data_dir() -> std::path::PathBuf {
    // XDG / Application Support / AppData, without pulling a crate: read the
    // documented env vars directly.
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return std::path::Path::new(&home)
                .join("Library/Application Support/3FA");
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return std::path::Path::new(&appdata).join("3FA");
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return std::path::Path::new(&xdg).join("3fa");
        }
        if let Ok(home) = std::env::var("HOME") {
            return std::path::Path::new(&home).join(".local/share/3fa");
        }
    }
    std::path::PathBuf::from(".")
}
