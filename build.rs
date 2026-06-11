//! Compiles the Slint `.slint` UI files into Rust at build time.
//!
//! Guarded by the `gui` feature so that `cargo build --no-default-features`
//! (core-library / CI / headless) doesn't require the Slint toolchain.

fn main() {
    // Cargo sets CARGO_FEATURE_<NAME> when a feature is active.
    if std::env::var("CARGO_FEATURE_GUI").is_ok() {
        slint_build::compile("ui/app.slint").expect("failed to compile Slint UI");
    }
}
