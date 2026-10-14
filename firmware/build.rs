//! Puts the memory layout for the target's architecture where the linker finds it.

use std::{env, fs, path::PathBuf};

fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let source = match arch.as_str() {
        "arm" => "memory-arm.x",
        "riscv32" => "memory-riscv.x",
        _ => return,
    };
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    fs::copy(source, out.join("memory.x")).expect("memory layout is readable");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed={source}");
    println!("cargo:rerun-if-changed=build.rs");
}
