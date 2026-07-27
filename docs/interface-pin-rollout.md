# Canonical interface pin rollout

This branch replaces private cross-repository protocol drift checks with an immutable vendored `3fa-interfaces` Rust package, exact Git blob provenance, JSON parity tests for legacy desktop vault DTOs, and direct re-exports for new Signal, device, recovery, and local-unlock contracts.

The vendored source is generated from `3FA-app/3fa-interfaces@ef75da711138dfb96e4fe18a87f8d82efe997c0d`. Production Signal sync remains disabled until the backend flag, platform secure storage, reviewed Signal provider, device ceremonies, and adversarial E2E gates are complete.
