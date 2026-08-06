# Companion desktop implementation

This repository is the **live Rust desktop implementation** for 3FA.

## Current and target pair

- Rust: [`3FA-app/3FA-desktop.rs`](https://github.com/3FA-app/3FA-desktop.rs) — **live**; this repository.
- Flutter, current: [`ORESoftware/3fa-client-ui.dart`](https://github.com/ORESoftware/3fa-client-ui.dart) — the **current cross-owner Flutter product implementation** with native Linux, macOS, and Windows runner projects.
- Flutter, canonical target: `3FA-app/3fa-flutter` — **planned organization-local target** and not yet verified as a published repository.

Until the organization-local target is published and its history or replacement path is explicitly reconciled, desktop-facing Flutter work belongs in `ORESoftware/3fa-client-ui.dart`. The target name is an allocation, not proof that a remote exists.

## Rust toolkit

The Rust app uses **Slint** as a fully native compiled UI. A WebView is prohibited for this security-sensitive application. See [`docs/DESKTOP_TOOLKIT.md`](docs/DESKTOP_TOOLKIT.md) for the toolkit decision, privilege boundary, HTTPS-first deep-link contract, platform adapters, and test matrix.

## Why both implementations remain active

The Rust and Flutter applications are developed side-by-side to compare security, startup and memory use, OS integration, accessibility, developer velocity, mobile reuse, release engineering, and long-term maintenance using the same production features. Neither implementation is a disposable prototype or a maintenance-only fallback.

## Feature-delivery contract

For every desktop-facing feature:

1. inspect this Rust implementation and the current Flutter implementation before deciding scope;
2. define shared acceptance criteria and identify affected authentication flows, TOTP/HOTP behavior, Signal and multi-device state, vault/sync formats, deep-link routes, schemas, clients, assets, and fixtures;
3. create or update work for both implementations, or record an explicit implementation-specific no-change rationale;
4. keep cross-language cryptographic, serialization, and route behavior covered by shared fixtures or conformance tests where practical;
5. test and report Rust and Flutter delivery status separately, including the actual operating-system matrix exercised; and
6. keep reciprocal repository references, toolkit documentation, and migration state current.

Semantic product parity is required; internal architecture, UI framework, and platform-native behavior may differ.

## Deep-link contract

- Canonical form: `https://<verified-3fa-owned-host>/open/<route>?<bounded-query>`.
- Fallback scheme: `threefa://`.
- Route types and fixtures belong in `3fa-interfaces`.
- URLs are untrusted input and must never carry passwords, tokens, TOTP/HOTP seeds, recovery secrets, vault material, or encryption keys.
- Authentication and transfer links use short-lived, single-use, audience-bound codes.
- Both apps must handle cold start, already-running delivery, authentication resume, replay rejection, and browser fallback.

## Migration contract

Moving or replacing the cross-owner Flutter implementation must preserve history and traceability. A migration must update, in the same delivery:

- this repository;
- `ORESoftware/3fa-client-ui.dart`;
- the target Flutter repository;
- the 3FA organization documentation;
- the Linear project and rollout issue;
- the GitHub Project references; and
- the canonical desktop registry and strategy documents.

Do not archive the current Flutter repository or mark the target `live` until builds, tests, platform runners, package identity, release/signing configuration, deep-link handlers, and reciprocal links have been verified.

## Project routing

- GitHub Project: [`3FA-app-project` — Project 1](https://github.com/orgs/3FA-app/projects/1)
- Linear project: [`github.com/3FA-app`](https://linear.app/denman/project/githubcom3fa-app-c3db52220894)
- Canonical portfolio registry: [`ORESoftware/project-registry`](https://github.com/ORESoftware/project-registry/blob/main/registry/desktop-applications.json)
- Toolkit assignments: [`rust-desktop-strategies.md`](https://github.com/ORESoftware/project-registry/blob/main/docs/rust-desktop-strategies.md)
- Linear rollout: [`DEN-2469`](https://linear.app/denman/issue/DEN-2469/roll-out-paired-rust-flutter-desktop-repositories-across-the-portfolio)
