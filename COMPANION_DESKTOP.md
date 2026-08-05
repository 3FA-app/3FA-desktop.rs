# Companion desktop implementation

This repository is the **live Rust desktop implementation** for 3FA.

## Allocated pair

- Rust: [`3FA-app/3FA-desktop.rs`](https://github.com/3FA-app/3FA-desktop.rs) — **live**; this repository.
- Flutter: [`3FA-app/3fa-desktop-flutter`](https://github.com/3FA-app/3fa-desktop-flutter) — **planned** and not yet verified as a published repository.

The planned URL above is an allocation target, not a claim that the remote currently exists. Do not mark the Flutter implementation live until its repository, native desktop runners, tests, and release status are verified.

## Feature-delivery contract

For every desktop-facing feature:

1. inspect the Rust implementation and the Flutter companion when available;
2. define shared acceptance criteria and identify affected authentication flows, Signal Protocol behavior, device state, schemas, clients, assets, and fixtures;
3. create/update work for both implementations, or record an explicit no-change rationale;
4. test and report Rust and Flutter status separately; and
5. keep reciprocal repository references current.

Until the Flutter repository is published, feature plans must reserve the companion scope rather than silently treating Rust completion as full desktop parity.

## Project routing

- GitHub Project: [`3FA-app-project` — Project 1](https://github.com/orgs/3FA-app/projects/1)
- Canonical portfolio registry: [`ORESoftware/project-registry`](https://github.com/ORESoftware/project-registry/blob/main/registry/desktop-applications.json)
- Linear rollout: [`DEN-2469`](https://linear.app/denman/issue/DEN-2469/roll-out-paired-rust-flutter-desktop-repositories-across-the-portfolio)
