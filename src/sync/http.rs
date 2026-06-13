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

/// An authenticated transport bound to one account's device token.
pub struct HttpTransport {
    client: reqwest::blocking::Client,
    base_url: String,
    token: String,
}

impl HttpTransport {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self, SyncError> {
        Ok(Self {
            client: client()?,
            base_url: base_url.into(),
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
}
