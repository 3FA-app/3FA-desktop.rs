# 3FA Rust desktop toolkit

Verified **2026-08-06**.

## Decision

The 3FA Rust desktop application uses **Slint**.

- **Renderer policy:** native compiled UI.
- **WebView policy:** prohibited.
- **Current repository:** `3FA-app/3FA-desktop.rs`.
- **Current Flutter companion:** `ORESoftware/3fa-client-ui.dart`.
- **Canonical Flutter migration target:** `3FA-app/3fa-flutter`.

Changing this decision requires an architecture decision record and coordinated updates to this repository, the Flutter companion, `3FA-app/.github`, Linear, and the central portfolio strategy.

## Why Slint

3FA handles TOTP/HOTP seeds, encrypted vaults, recovery state, device enrollment, authentication, and secure local storage. The desktop UI must be fully native for security, startup performance, memory use, deterministic behavior, and direct operating-system integration.

Slint is retained because it compiles the UI, keeps application and security-sensitive state in Rust, avoids an embedded browser/DOM surface, has a small runtime footprint, and already underpins the working application.

Tauri and Dioxus Desktop are not acceptable substitutions for this repository because they introduce a system WebView. GPUI or Qt would require a separate evidence-backed ADR and migration plan; they are not implicit fallbacks.

## Responsibility boundary

Rust owns:

- vault encryption, key handling, and zeroization;
- authentication and factor policy;
- TOTP/HOTP parsing and generation;
- synchronization, recovery, device state, persistence, and networking;
- deep-link parsing, authorization, and dispatch;
- platform credential and secure-storage adapters; and
- audit-safe logging and error redaction.

Slint owns declarative presentation and user interaction. Slint markup must never contain credentials, seeds, recovery material, access tokens, or serialized vault contents.

OS-specific integration belongs behind small Rust platform modules. The view layer must not decide whether a deep link, external file, or authentication return is trusted.

## Paired Flutter program

The Rust and Flutter apps are both first-class implementations. They are developed side-by-side to compare security, performance, OS integration, accessibility, developer velocity, mobile reuse, packaging/signing, and long-term maintenance using the same features.

Every desktop-facing feature must inspect both repositories and share acceptance criteria, interfaces, test vectors, and route fixtures. Normally both implementations change. A one-sided change requires a written no-change rationale, a parity assessment, and any follow-up issue.

Completion in this repository is not full desktop completion while the Flutter companion remains unchanged.

## HTTPS-first deep-link contract

### Canonical URL

The product must reserve an owned and verified HTTPS route family:

```text
https://<verified-3fa-owned-host>/open/<route>?<bounded-query>
```

The exact host must be documented only after ownership and deployment are verified. Do not guess or hard-code a production domain.

### Fallback scheme

```text
threefa://<route>?<bounded-query>
```

A scheme cannot begin with a digit, so `threefa://` is used rather than `3fa://`.

### Shared route model

The route enum/types, parser behavior, identifier validation, and golden fixtures belong in `3fa-interfaces`. Rust and Flutter must consume the same contract.

Expected initial route families may include account enrollment, device review, recovery continuation, settings, and authenticated notification targets, but no route becomes public until it is versioned and tested in the interfaces repository.

### Security requirements

Every incoming URL is untrusted input.

- Validate the exact HTTPS host, path, route version, identifier format, action, and bounded query parameters.
- Reject unknown routes, duplicate security-sensitive parameters, unsafe return URLs, and ambiguous encodings.
- Never put passwords, bearer/refresh tokens, TOTP/HOTP seeds, recovery secrets, vault contents, private account data, or encryption keys in URLs.
- Authentication and device-transfer handoffs must use short-lived, single-use, audience-bound codes that are redeemed through an authenticated channel.
- Persist only the validated pending route while authentication is completed; never persist sensitive URL query data.
- Require explicit confirmation before enrollment, recovery, device removal, import, or other security-sensitive actions.
- Log route names and bounded request identifiers only; never log raw URLs when they may contain user-provided data.

### Platform delivery

Implement URL delivery through narrow Rust adapters:

- **macOS:** bundled URL scheme and associated-domain/universal-link configuration; deliver open-URL events into the Rust parser.
- **Windows:** packaged protocol/app-URI registration; forward activation arguments to the existing process.
- **Linux:** `.desktop`/MIME scheme registration and single-instance forwarding.

The application must handle:

1. cold start from a URL;
2. delivery while already running;
3. authentication-required resume;
4. duplicate/replayed URL rejection;
5. unsupported route fallback; and
6. browser fallback when the application is absent.

## Test matrix

At minimum:

- route parser unit tests and golden fixtures from `3fa-interfaces`;
- malformed, oversized, duplicate, hostile-return, and replayed-link tests;
- cold-start and running-instance tests on macOS, Windows, and Linux;
- parity tests against Flutter Android/iOS app links and desktop handlers;
- security tests proving URLs cannot import seeds, vault material, tokens, or arbitrary files; and
- installer/package tests proving the registered handlers target the intended signed application.

## Related documents

- [`COMPANION_DESKTOP.md`](../COMPANION_DESKTOP.md)
- [`AGENTS.md`](../AGENTS.md)
- [3FA organization desktop allocation](https://github.com/3FA-app/.github/blob/main/docs/DESKTOP_APPLICATIONS.md)
- [Portfolio toolkit assignments](https://github.com/ORESoftware/project-registry/blob/main/docs/rust-desktop-strategies.md)
- [DEN-2469 rollout](https://linear.app/denman/issue/DEN-2469/roll-out-paired-rust-flutter-desktop-repositories-across-the-portfolio)
