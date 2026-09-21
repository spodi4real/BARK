//! Embeds the application manifest.
//!
//! The manifest is what gives BARK the classic Windows look: it asks for
//! Common Controls version 6 (proper list views, status bars and themed
//! buttons rather than Windows 95 ones) and declares per-monitor DPI awareness
//! so text stays sharp on high-resolution screens instead of being stretched.
//! It also states that BARK runs as the invoking user and never asks for
//! elevation on launch.
//!
//! Embedded through the MSVC linker directly, so no resource compiler is
//! needed.

fn main() {
    let manifest = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("bark.manifest");
    println!("cargo:rerun-if-changed={}", manifest.display());
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}", manifest.display());
    }
}
