use std::{env, path};

fn main() -> anyhow::Result<()> {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR to always be set by `cargo build`");
    let manifest_dir = path::Path::new(&manifest_dir);

    cxx_build::bridge("src/lib.rs")
        .file("perfetto-sdk/perfetto.cc")
        .file("src/perfetto-bindings.cc")
        .std("c++17")
        .include(manifest_dir)
        .include(manifest_dir.join("src"))
        .flag_if_supported("-Wno-redundant-move")
        .flag_if_supported("-Wno-deprecated-declarations")
        .compile("tracing-perfetto-sdk");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/perfetto-bindings.h");
    println!("cargo:rerun-if-changed=src/perfetto-bindings.cc");
    println!("cargo:rerun-if-changed=perfetto-sdk/perfetto.h");
    println!("cargo:rerun-if-changed=perfetto-sdk/perfetto.cc");

    Ok(())
}
