//! Real network transport for the zero-knowledge sync protocol (feature
//! `sync-net`).
//!
//! Wraps `reqwest` (blocking) over the backend's `/v1/*` routes. The bearer token
//! is issued per device by `register`/`login` and stored in the OS keychain (via
//! [`keystore`]) — never in the vault file. Everything on the wire is either a
//! credential to `/v1/login|register` or an opaque [`SealedBlob`]; the account's
//! E2E key (which actually decrypts the vault) is derived locally and never sent.

use super::{SyncError, Transport};
use crate::protocol::{PullResponse, PushRequest, PushResponse};
use serde::{Deserialize, Serialize};

/// Default sync server (the deployed 3fa-backend). Overridable in Settings.
pub const DEFAULT_SERVER_URL: &str = "https://3fa-sync.example.com";

#[derive(Serialize)]
struct CredsRequest<'a> {
    username: &'a str,
    password: &'a str,
    device_name: &'a str,
}

/// Server response to `register` / `login`: the new device id + its one-time
/// bearer token (the account/device ids are UUID strings).
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub account_id: String,
    pub device_id: String,
    pub sync_token: String,
}

fn client() -> Result<reqwest::blocking::Client, SyncError> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(concat!("3fa-desktop/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| SyncError::Transport(e.to_string()))
}

fn err<E: std::fmt::Display>(e: E) -> SyncError {
    SyncError::Transport(e.to_string())
}

/// Reject any sync/identity endpoint that is not `https://`. The account/session
/// credentials and the Supabase JWT travel in these requests; a plain-`http`
/// endpoint (a typo, a tampered `config.json`, or an attacker-supplied URL) would
/// send them in cleartext and permit a downgrade. `localhost` over http is allowed
/// only for developer testing.
fn require_secure(base_url: &str) -> Result<(), SyncError> {
    let u = base_url.trim();
    if u.starts_with("https://") {
        return Ok(());
    }
    // Local-dev exemption: only a genuine loopback host, and only in debug builds.
    // The host must be followed by a port/path/end boundary so a public host like
    // `localhost.evil.com` can't sneak past the prefix check.
    let is_local_http = ["http://localhost", "http://127.0.0.1", "http://[::1]"]
        .iter()
        .any(|p| {
            u.strip_prefix(p)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        });
    if is_local_http && cfg!(debug_assertions) {
        return Ok(());
    }
    Err(SyncError::Transport(format!(
        "refusing to use insecure sync URL {u:?}: only https:// is allowed"
    )))
}

/// Trim a trailing slash so `{base}/v1/...` never doubles up.
fn join(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

/// Create a new account and enroll this device. Returns the device token.
pub fn register(
    base_url: &str,
    username: &str,
    password: &str,
    device_name: &str,
) -> Result<TokenResponse, SyncError> {
    post_creds(base_url, "/v1/register", username, password, device_name)
}

/// Authenticate an existing account and enroll this device. Returns the token.
pub fn login(
    base_url: &str,
    username: &str,
    password: &str,
    device_name: &str,
) -> Result<TokenResponse, SyncError> {
    post_creds(base_url, "/v1/login", username, password, device_name)
}

fn post_creds(
    base_url: &str,
    path: &str,
    username: &str,
    password: &str,
    device_name: &str,
) -> Result<TokenResponse, SyncError> {
    require_secure(base_url)?;
    let resp = client()?
        .post(join(base_url, path))
        .json(&CredsRequest {
            username,
            password,
            device_name,
        })
        .send()
        .map_err(err)?;
    if !resp.status().is_success() {
        return Err(SyncError::Transport(format!("server returned {}", resp.status())));
    }
    resp.json::<TokenResponse>().map_err(err)
}

/// Enroll this device against the backend using a Supabase access JWT (from
/// [`supabase::sign_in`] / [`supabase::refresh`]). The JWT authenticates; the
/// backend maps it to an account and returns a long-lived sync token. The
/// password never leaves Supabase — this is the zero-knowledge login path.
pub fn enroll_supabase(
    base_url: &str,
    access_jwt: &str,
    device_name: &str,
) -> Result<TokenResponse, SyncError> {
    require_secure(base_url)?;
    #[derive(Serialize)]
    struct EnrollBody<'a> {
        device_name: &'a str,
    }
    let resp = client()?
        .post(join(base_url, "/v1/auth/supabase"))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {access_jwt}"))
        .json(&EnrollBody { device_name })
        .send()
        .map_err(err)?;
    if !resp.status().is_success() {
        return Err(SyncError::Transport(format!("server returned {}", resp.status())));
    }
    resp.json::<TokenResponse>().map_err(err)
}

/// An authenticated transport bound to one account's device token.
pub struct HttpTransport {
    client: reqwest::blocking::Client,
    base_url: String,
    token: String,
}

impl HttpTransport {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self, SyncError> {
        let base_url = base_url.into();
        require_secure(&base_url)?;
        Ok(Self {
            client: client()?,
            base_url,
            token: token.into(),
        })
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", self.token)
    }
}

impl Transport for HttpTransport {
    fn push(&mut self, req: &PushRequest) -> Result<PushResponse, SyncError> {
        let resp = self
            .client
            .post(join(&self.base_url, "/v1/vault"))
            .header(reqwest::header::AUTHORIZATION, self.bearer())
            .json(req)
            .send()
            .map_err(err)?;
        if !resp.status().is_success() {
            return Err(SyncError::Transport(format!("push failed: {}", resp.status())));
        }
        resp.json::<PushResponse>().map_err(err)
    }

    fn pull(&mut self) -> Result<PullResponse, SyncError> {
        let resp = self
            .client
            .get(join(&self.base_url, "/v1/vault"))
            .header(reqwest::header::AUTHORIZATION, self.bearer())
            .send()
            .map_err(err)?;
        if !resp.status().is_success() {
            return Err(SyncError::Transport(format!("pull failed: {}", resp.status())));
        }
        resp.json::<PullResponse>().map_err(err)
    }
}

/// Persist the per-device bearer token in the OS keychain (Keychain / Credential
/// Manager / Secret Service), keyed by server URL. Kept out of the vault file so a
/// stolen vault still can't sync, and out of any plaintext config.
pub mod keystore {
    use super::SyncError;

    const SERVICE: &str = "3fa-desktop-sync";

    fn entry(base_url: &str) -> Result<keyring::Entry, SyncError> {
        keyring::Entry::new(SERVICE, base_url).map_err(|e| SyncError::Transport(e.to_string()))
    }

    pub fn save_token(base_url: &str, token: &str) -> Result<(), SyncError> {
        entry(base_url)?
            .set_password(token)
            .map_err(|e| SyncError::Transport(e.to_string()))
    }

    pub fn load_token(base_url: &str) -> Option<String> {
        entry(base_url).ok()?.get_password().ok()
    }

    pub fn clear_token(base_url: &str) -> Result<(), SyncError> {
        match entry(base_url)?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(SyncError::Transport(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_trims_trailing_slash() {
        assert_eq!(join("https://x.test/", "/v1/vault"), "https://x.test/v1/vault");
        assert_eq!(join("https://x.test", "/v1/vault"), "https://x.test/v1/vault");
    }

    #[test]
    fn require_secure_allows_https_and_rejects_http() {
        assert!(require_secure("https://sync.example.com").is_ok());
        assert!(require_secure("http://sync.example.com").is_err());
        assert!(require_secure("ftp://sync.example.com").is_err());
        // A public host that merely contains "localhost" in a later segment must
        // not slip through the local-dev exemption.
        assert!(require_secure("http://localhost.evil.com").is_err());
    }

    #[test]
    fn http_transport_rejects_insecure_url() {
        assert!(HttpTransport::new("http://sync.example.com", "tok").is_err());
    }
}
