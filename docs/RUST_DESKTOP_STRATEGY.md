# Rust desktop strategy: Slint

Verified **2026-08-06**.

## Decision

The 3FA Rust desktop application uses **Slint**. Keep the existing Slint architecture rather than starting a second Rust desktop repository or adding a webview framework.

Current repository: [`3FA-app/3FA-desktop.rs`](https://github.com/3FA-app/3FA-desktop.rs)

An eventual lowercase rename to `3FA-app/3fa-desktop.rs` may improve naming consistency, but it must be a history-preserving repository rename. Do **not** create a duplicate Rust implementation.

## Why Slint fits 3FA

3FA is a security-sensitive authenticator that should remain small, responsive, native, and easy to audit. Slint provides a declarative native UI without Electron or a browser DOM, while the application already keeps OTP, vault, cryptography, session, synchronization, and policy behavior in a headless Rust core that can be tested without a display.

The selected pattern is:

```text
threefa_core and generated 3FA interfaces
                 │
                 ├── Slint Rust desktop shell
                 └── Flutter product application
```

The Slint shell should remain thin. Authentication policy, TOTP/HOTP behavior, vault formats, recovery, synchronization, device state, and cryptographic compatibility do not belong in `.slint` presentation files.

## Flutter companion

- Current Flutter implementation: [`ORESoftware/3fa-client-ui.dart`](https://github.com/ORESoftware/3fa-client-ui.dart)
- Intended organization-local target: `3FA-app/3fa-flutter`

The current cross-owner Flutter repository remains first-class until a history-preserving migration is complete. The former target name `3fa-desktop-flutter` is deprecated in favor of the simpler cross-platform name `3fa-flutter`, because the Flutter application also serves mobile targets.

## Why both applications remain active

The Rust and Flutter applications are developed side-by-side to compare:

- native security and credential-store integration;
- memory, CPU, startup, and installer footprint;
- platform packaging and release reliability;
- accessibility and keyboard workflows;
- implementation velocity and regression rate;
- mobile/desktop code sharing in Flutter;
- native Rust maintainability and auditability; and
- user experience and support burden.

Neither application is a throwaway prototype. A desktop feature must normally be evaluated and implemented in both. A one-sided change requires an explicit no-change rationale, parity-gap note, and follow-up issue.

## No-React rule

React is not permitted in this repository or in the Flutter companion migration. Slint remains the Rust UI strategy. Do not add Tauri, Dioxus, a browser webview, or a JavaScript UI framework as a second shell.

## Platform and release gates

- Build and test macOS, Windows, and Linux separately.
- Keep `--no-default-features` headless core tests green.
- Validate OS keyring, clipboard, file picker, camera/QR, notifications, and packaging on each claimed platform.
- Review Slint licensing for every distribution model.
- Report generated/buildable targets separately from signed and supported releases.

## Required feature workflow

1. Inspect this repository and the current Flutter companion.
2. Define shared acceptance criteria and affected interfaces/fixtures.
3. Implement both sides or document the exception.
4. Run cross-language fixture and serialization compatibility tests.
5. Report Rust and Flutter platform status separately.
6. Keep README, `AGENTS.md`, pull-request templates, Linear, Project 1, and the portfolio registry reciprocal.

## References

- Slint desktop documentation: https://docs.slint.dev/latest/docs/slint/guide/platforms/desktop/
- Portfolio strategy matrix: https://github.com/ORESoftware/project-registry/blob/main/docs/rust-desktop-strategies.md
- GitHub Project 1: https://github.com/orgs/3FA-app/projects/1
- Linear rollout: https://linear.app/denman/issue/DEN-2469/roll-out-paired-rust-flutter-desktop-repositories-across-the-portfolio
