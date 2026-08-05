## Summary

Describe the user-visible and architectural change.

## Validation

- [ ] `cargo fmt --all -- --check`
- [ ] relevant `cargo clippy` and `cargo test` suites
- [ ] relevant native/platform packaging tests, or a documented reason they do not apply
- [ ] no credential, vault secret, token, signing key, or private fixture was committed

## Companion desktop impact

Current Flutter companion: [`ORESoftware/3fa-client-ui.dart`](https://github.com/ORESoftware/3fa-client-ui.dart)

- [ ] I inspected the Flutter companion before deciding scope.
- [ ] The Flutter companion has a corresponding change or issue.
- [ ] No Flutter change is required; the rationale is recorded below.
- [ ] Shared contracts, schemas, fixtures, assets, cryptographic formats, and release notes were evaluated.
- [ ] Rust and Flutter delivery/platform status is reported separately.
- [ ] Reciprocal repository links and the current-versus-target Flutter migration state remain accurate.

### Companion rationale / parity gaps

<!-- State what changes in the Flutter implementation, or why it intentionally does not change. Record any parity gap and follow-up issue. -->
