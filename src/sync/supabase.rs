//! Supabase Auth client (feature `sync-net`).
//!
//! Talks to Supabase's GoTrue token endpoint to turn an email/password into a
//! session (`sign_in`) and to trade a refresh token for a fresh access token
//! (`refresh`). The access token is then presented to our backend's
//! `/v1/auth/supabase` (see [`super::http::enroll_supabase`]) to obtain a sync
//! token; the refresh token is sealed locally under the 6-digit PIN (see
//! [`crate::pin_session`]) so an expired access token never forces a full
//! re-login — the user just re-enters the PIN.
//!
//! Only the `anon`/publishable key is used here (the same key a browser client
//! would use); no service-role key ever touches the desktop app.

use super::SyncError;
use serde::Deserialize;

/// A Supabase session: the short-lived access JWT plus the long-lived refresh
/// token and the access token's lifetime in seconds.
#[derive(Debug, Clone, Deserialize)]
pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub expires_in: u64,
}

/// Configuration for reaching a Supabase project: its base URL and the public
/// `anon` key. Both are non-secret (they ship in any client).
#[derive(Debug, Clone)]
pub struct SupabaseConfig {
    pub project_url: String,
    pub anon_key: String,
}

impl SupabaseConfig {
    fn token_url(&self, grant_type: &str) -> String {
        format!(
            "{}/auth/v1/token?grant_type={grant_type}",
            self.project_url.trim_end_matches('/')
        )
    }
}

fn client() -> Result<reqwest::blocking::Client, SyncError> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(concat!("3fa-desktop/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| SyncError::Transport(e.to_string()))
}

fn require_https(url: &str) -> Result<(), SyncError> {
    // Scheme comparison is case-insensitive (RFC 3986).
    let scheme = url
        .trim()
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .unwrap_or_default();
    if scheme == "https" {
        Ok(())
    } else {
        Err(SyncError::Transport(format!(
            "refusing insecure Supabase URL {url:?}: only https:// is allowed"
        )))
    }
}

fn post_token(
    cfg: &SupabaseConfig,
    grant_type: &str,
    body: &serde_json::Value,
) -> Result<Session, SyncError> {
    require_https(&cfg.project_url)?;
    let resp = client()?
        .post(cfg.token_url(grant_type))
        .header("apikey", &cfg.anon_key)
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", cfg.anon_key),
        )
        .json(body)
        .send()
        .map_err(|e| SyncError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        // Deliberately coarse: don't echo Supabase's body (it distinguishes
        // "wrong password" from "no such user" — an enumeration signal).
        return Err(SyncError::Transport(format!(
            "supabase auth failed: {}",
            resp.status()
        )));
    }
    resp.json::<Session>()
        .map_err(|e| SyncError::Transport(e.to_string()))
}

/// Sign in with email + password. Returns a fresh session.
pub fn sign_in(cfg: &SupabaseConfig, email: &str, password: &str) -> Result<Session, SyncError> {
    post_token(
        cfg,
        "password",
        &serde_json::json!({ "email": email, "password": password }),
    )
}

/// Exchange a refresh token for a new session. Used when the access JWT has
/// expired and the user has unlocked the sealed session with their PIN.
pub fn refresh(cfg: &SupabaseConfig, refresh_token: &str) -> Result<Session, SyncError> {
    post_token(
        cfg,
        "refresh_token",
        &serde_json::json!({ "refresh_token": refresh_token }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SupabaseConfig {
        SupabaseConfig {
            project_url: "https://proj.supabase.co".into(),
            anon_key: "anon-key".into(),
        }
    }

    #[test]
    fn token_url_is_built_correctly() {
        assert_eq!(
            cfg().token_url("password"),
            "https://proj.supabase.co/auth/v1/token?grant_type=password"
        );
        // Trailing slash on the project URL doesn't double up.
        let c = SupabaseConfig {
            project_url: "https://proj.supabase.co/".into(),
            anon_key: "k".into(),
        };
        assert_eq!(
            c.token_url("refresh_token"),
            "https://proj.supabase.co/auth/v1/token?grant_type=refresh_token"
        );
    }

    #[test]
    fn insecure_project_url_is_rejected() {
        assert!(require_https("http://proj.supabase.co").is_err());
        assert!(require_https("https://proj.supabase.co").is_ok());
        // Case-insensitive scheme.
        assert!(require_https("HTTPS://proj.supabase.co").is_ok());
        assert!(require_https("ftp://proj.supabase.co").is_err());
    }

    #[test]
    fn session_deserializes_from_supabase_shape() {
        let json = r#"{
            "access_token": "jwt.abc.def",
            "refresh_token": "rt-xyz",
            "expires_in": 3600,
            "token_type": "bearer"
        }"#;
        let s: Session = serde_json::from_str(json).unwrap();
        assert_eq!(s.access_token, "jwt.abc.def");
        assert_eq!(s.refresh_token, "rt-xyz");
        assert_eq!(s.expires_in, 3600);
    }
}
