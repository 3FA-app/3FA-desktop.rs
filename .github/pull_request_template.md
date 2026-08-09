## Summary

Describe the user-visible and architectural change.

## Validation

- [ ] `cargo fmt --all -- --check`
- [ ] relevant `cargo clippy` and `cargo test` suites
- [ ] relevant native/platform packaging tests, or a documented reason they do not apply
- [ ] no credential, vault secret, token, signing key, or private fixture was committed

## Rust desktop toolkit

Selected kit: **Slint**, fully native, **no WebView**.

- [ ] This change preserves the Slint/no-WebView decision, or includes an approved ADR.
- [ ] Security-sensitive state and deep-link authorization remain in Rust rather than Slint markup.
- [ ] `docs/DESKTOP_TOOLKIT.md` remains accurate.

## Companion desktop impact

Current Flutter companion: [`ORESoftware/3fa-client-ui.dart`](https://github.com/ORESoftware/3fa-client-ui.dart)

Canonical organization-owned target: `3FA-app/3fa-flutter` (planned; do not claim it exists until verified).

- [ ] I inspected the Flutter companion before deciding scope.
- [ ] The Flutter companion has a corresponding change or issue.
- [ ] No Flutter change is required; the rationale is recorded below.
- [ ] Shared contracts, schemas, fixtures, assets, cryptographic formats, deep-link routes, and release notes were evaluated.
- [ ] Rust and Flutter delivery/platform status is reported separately.
- [ ] Reciprocal repository links and the current-versus-target Flutter migration state remain accurate.

## HTTPS-first deep-link impact

- [ ] The route is defined or updated in `3fa-interfaces` with shared fixtures.
- [ ] Both `https://<verified-3fa-owned-host>/open/...` and `threefa://...` behavior were assessed.
- [ ] Cold start, running-instance delivery, authentication resume, replay rejection, and browser fallback were tested as applicable.
- [ ] No password, token, TOTP/HOTP seed, recovery secret, vault material, private account data, or encryption key appears in a URL or log.
- [ ] Security-sensitive actions reached from a link require explicit confirmation.

### Companion rationale / parity gaps

<!-- State what changes in the Flutter implementation, or why it intentionally does not change. Record any parity gap and follow-up issue. -->
