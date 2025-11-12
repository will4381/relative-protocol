#[cfg(feature = "generate-header")]
use std::env;
#[cfg(feature = "generate-header")]
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=include/bridge.h");

    #[cfg(feature = "generate-header")]
    generate_header();

    #[cfg(not(feature = "generate-header"))]
    println!("cargo:warning=Skipping bridge.h regeneration (enable the `generate-header` feature to refresh it).");
}

#[cfg(feature = "generate-header")]
fn generate_header() {
    use std::fs;

    let crate_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing"));
    let include_dir = crate_dir.join("include");
    let output = include_dir.join("bridge.h");

    if !include_dir.exists() {
        if let Err(error) = fs::create_dir_all(&include_dir) {
            panic!("failed to create include/ directory: {error}");
        }
    }

    match cbindgen::generate(&crate_dir) {
        Ok(generator) => {
            if generator.write_to_file(&output) {
                println!("cargo:warning=Updated {:?}", output);
            } else {
                println!("cargo:warning=bridge.h unchanged");
            }
        }
        Err(error) => {
            panic!("cbindgen failed: {error}");
        }
    }
}
