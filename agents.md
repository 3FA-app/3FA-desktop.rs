# Agent instructions

Read [`COMPANION_DESKTOP.md`](COMPANION_DESKTOP.md) before planning desktop-facing work.

## Paired desktop delivery

This repository is the live Rust + Slint desktop implementation. Its current Flutter companion is [`ORESoftware/3fa-client-ui.dart`](https://github.com/ORESoftware/3fa-client-ui.dart). The intended organization-local Flutter target is `3FA-app/3fa-desktop-flutter`, but it must not be treated as published until verified.

For a desktop-facing feature:

1. inspect both this Rust repository and the current Flutter companion;
2. define shared acceptance criteria and identify affected interfaces, schemas, fixtures, assets, vault/sync formats, and cross-compatibility behavior;
3. normally update both implementations;
4. when only one changes, record the companion impact, no-change rationale, parity gap, and follow-up work in the issue and pull request;
5. test Rust and Flutter independently and report platform status separately; and
6. keep reciprocal documentation and the current-versus-target Flutter migration state accurate.

Do not count a web server, CLI, generated runner, or test harness as product parity.

## Rust validation

At minimum, run the relevant subset of:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test --no-default-features
```

Run native UI, secure-storage, packaging, and operating-system-specific checks when those surfaces change.

## Security

Never commit credentials, TOTP/HOTP seeds, vault material, recovery secrets, synchronization passphrases, personal access tokens, signing keys, production account data, or unredacted private fixtures.
