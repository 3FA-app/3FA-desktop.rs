//! 3FA desktop authenticator — GUI binary.
//!
//! All logic lives in the `threefa_core` library; this is the Slint shell. The
//! `gui` feature (default) pulls in Slint; `--no-default-features` builds a tiny
//! headless stub so CI can exercise the core library without a display server.

#[cfg(feature = "gui")]
mod ui;

#[cfg(feature = "gui")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    ui::run()
}

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!(
        "threefa: built without the `gui` feature — core library only. \
         Rebuild with default features to launch the desktop app."
    );
}
