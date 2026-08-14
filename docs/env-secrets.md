# Desktop release environment

This repository uses the canonical `ores-sops` layout: only
`env/enc/dev.env.enc` and `env/enc/prod.env.enc` are committed; decrypted files
under `env/dec/` and the managed `.env` symlink are ignored.

Desktop configuration differs from server secrets. The Supabase publishable
key, project URL, sync-server URL, telemetry collector **public** key, rotation
key ID, and Realtime channel are public client configuration. Cargo captures
them through Rust `option_env!` during compilation, so `just build-release prod`
decrypts through a FIFO, validates an exact public allowlist, strips unrelated
ambient credentials, rejects Supabase secret/service-role keys, and only then
starts Cargo. A collector private key or backend credential is never valid in a
desktop environment.

```sh
nix develop
just verify
just edit dev
just run dev
just build-release prod
just lock
```

Per-install device configuration may still override public defaults in
`config.json`; bearer and refresh tokens remain in the OS keychain. Do not add
`env/dec` to application resources, package decrypted dotenv files, or pass
secret values through `option_env!`/`include_str!`.

The bootstrap policy has one local age recipient. Add a separate production/CI
recipient and rekey before treating `prod.env.enc` as release-authoritative.
