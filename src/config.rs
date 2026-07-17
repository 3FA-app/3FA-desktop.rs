//! Small, **non-secret** device configuration stored beside the vault.
//!
//! Holds only what's needed to find and address the sync server: its URL, the
//! account username (a label, not a credential), and a stable per-install device
//! id used as this device's key in the sync version vector. The bearer token and
//! the account password live in the OS keychain / in memory, never here. Written
//! 0600 anyway (defence in depth) via the same atomic writer as the vault.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncConfig {
    /// Base URL of the 3fa-backend sync server (e.g. `https://3fa-sync.example.com`).
    pub server_url: String,
    /// Account username (display/label only — not a secret).
    pub username: String,
    /// Stable random id for this install; this device's key in the version vector.
    pub device_id: String,
    /// Supabase project URL (e.g. `https://<ref>.supabase.co`). Non-secret.
    /// Empty ⇒ fall back to the build-time default, if any.
    #[serde(default)]
    pub supabase_url: String,
    /// Supabase publishable/anon key. Non-secret (ships in every client).
    /// Empty ⇒ fall back to the build-time default, if any.
    #[serde(default)]
    pub supabase_anon_key: String,
}

/// Build-time defaults for the Supabase project, injected by CI for release
/// builds (`THREEFA_SUPABASE_URL` / `THREEFA_SUPABASE_ANON_KEY`). Both values are
/// public identifiers, not secrets. `config.json` overrides them when non-empty.
const DEFAULT_SUPABASE_URL: Option<&str> = option_env!("THREEFA_SUPABASE_URL");
const DEFAULT_SUPABASE_ANON_KEY: Option<&str> = option_env!("THREEFA_SUPABASE_ANON_KEY");

impl SyncConfig {
    /// Load config from `path`, or return defaults if it is missing/unreadable.
    pub fn load(path: &std::path::Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Persist config atomically with owner-only permissions.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        crate::write_private_atomic(path, &bytes)
    }

    /// Ensure `device_id` is set, generating a fresh random one if absent.
    pub fn ensure_device_id(&mut self) -> &str {
        if self.device_id.is_empty() {
            self.device_id = new_device_id();
        }
        &self.device_id
    }

    /// Effective Supabase project URL: config value, else build-time default.
    /// `None` when neither is set (Supabase login unavailable).
    pub fn supabase_url(&self) -> Option<&str> {
        if !self.supabase_url.is_empty() {
            return Some(&self.supabase_url);
        }
        DEFAULT_SUPABASE_URL.filter(|s| !s.is_empty())
    }

    /// Effective Supabase anon key: config value, else build-time default.
    pub fn supabase_anon_key(&self) -> Option<&str> {
        if !self.supabase_anon_key.is_empty() {
            return Some(&self.supabase_anon_key);
        }
        DEFAULT_SUPABASE_ANON_KEY.filter(|s| !s.is_empty())
    }
}

/// Standard config path within the per-user data dir.
pub fn config_path() -> std::path::PathBuf {
    crate::data_dir().join("config.json")
}

/// A 128-bit random, URL-safe device id (matches `protocol::device_id_is_valid`).
fn new_device_id() -> String {
    use rand::RngCore;
    let mut raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut raw);
    let mut s = String::with_capacity(32);
    for b in raw {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_is_stable_once_set_and_valid() {
        let mut c = SyncConfig::default();
        let id = c.ensure_device_id().to_string();
        assert_eq!(c.ensure_device_id(), id, "id must not change once set");
        assert!(crate::protocol::device_id_is_valid(&id));
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn round_trips_through_disk() {
        let mut p = std::env::temp_dir();
        p.push(format!("3fa-cfg-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let mut c = SyncConfig {
            server_url: "https://s.test".into(),
            username: "alice".into(),
            ..Default::default()
        };
        c.ensure_device_id();
        c.save(&p).unwrap();
        let back = SyncConfig::load(&p);
        assert_eq!(back.server_url, "https://s.test");
        assert_eq!(back.username, "alice");
        assert_eq!(back.device_id, c.device_id);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn supabase_accessors_prefer_config_then_fall_back() {
        // Explicit config values are returned.
        let c = SyncConfig {
            supabase_url: "https://proj.supabase.co".into(),
            supabase_anon_key: "anon-key".into(),
            ..Default::default()
        };
        assert_eq!(c.supabase_url(), Some("https://proj.supabase.co"));
        assert_eq!(c.supabase_anon_key(), Some("anon-key"));

        // Empty config falls back to the build-time default (None unless the env
        // vars were set at compile time — CI sets them for release builds).
        let empty = SyncConfig::default();
        assert_eq!(empty.supabase_url(), super::DEFAULT_SUPABASE_URL.filter(|s| !s.is_empty()));
    }

    #[test]
    fn new_config_fields_default_to_empty() {
        let c = SyncConfig::default();
        assert!(c.supabase_url.is_empty() && c.supabase_anon_key.is_empty());
    }
}
