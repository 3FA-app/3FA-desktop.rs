# Companion desktop implementation

This repository is the **live Rust desktop implementation** for 3FA.

## Current and target pair

- Rust: [`3FA-app/3FA-desktop.rs`](https://github.com/3FA-app/3FA-desktop.rs) — **live**; this repository.
- Flutter, current: [`ORESoftware/3fa-client-ui.dart`](https://github.com/ORESoftware/3fa-client-ui.dart) — the **current cross-owner Flutter product implementation** with native Linux, macOS, and Windows runner projects.
- Flutter, target: [`3FA-app/3fa-desktop-flutter`](https://github.com/3FA-app/3fa-desktop-flutter) — **planned organization-local target** and not yet verified as a published repository.

Until the organization-local target is published and its history or replacement path is explicitly reconciled, desktop-facing Flutter work belongs in `ORESoftware/3fa-client-ui.dart`. The target URL is an allocation, not proof that the remote exists.

## Feature-delivery contract

For every desktop-facing feature:

1. inspect this Rust implementation and the current Flutter implementation before deciding scope;
2. define shared acceptance criteria and identify affected authentication flows, TOTP/HOTP behavior, Signal and multi-device state, vault/sync formats, schemas, clients, assets, and fixtures;
3. create or update work for both implementations, or record an explicit implementation-specific no-change rationale;
4. keep cross-language cryptographic and serialization behavior covered by shared fixtures or conformance tests where practical;
5. test and report Rust and Flutter delivery status separately, including the actual operating-system matrix exercised; and
6. keep reciprocal repository references and migration state current.

Semantic product parity is required; internal architecture, UI framework, and platform-native behavior may differ.

## Migration contract

Moving or replacing the cross-owner Flutter implementation must preserve history and traceability. A migration must update, in the same delivery:

- this repository;
- `ORESoftware/3fa-client-ui.dart`;
- the target Flutter repository;
- the 3FA organization documentation;
- the Linear project and rollout issue;
- the GitHub Project references; and
- `ORESoftware/project-registry/registry/desktop-applications.json`.

Do not archive the current Flutter repository or mark the target `live` until builds, tests, platform runners, package identity, release/signing configuration, and reciprocal links have been verified.

## Project routing

- GitHub Project: [`3FA-app-project` — Project 1](https://github.com/orgs/3FA-app/projects/1)
- Linear project: [`github.com/3FA-app`](https://linear.app/denman/project/githubcom3fa-app-c3db52220894)
- Canonical portfolio registry: [`ORESoftware/project-registry`](https://github.com/ORESoftware/project-registry/blob/main/registry/desktop-applications.json)
- Linear rollout: [`DEN-2469`](https://linear.app/denman/issue/DEN-2469/roll-out-paired-rust-flutter-desktop-repositories-across-the-portfolio)
