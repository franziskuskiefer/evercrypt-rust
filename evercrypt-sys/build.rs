extern crate bindgen;

use std::{env, path::PathBuf};

fn main() {
    // Get ENV variables
    let home_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let llvm_dir =
        env::var("LLVM_DIR").unwrap_or("/usr/local/Cellar/llvm/10.0.0_3/bin/".to_string());

    // Set HACL/Evercrypt paths
    let hacl_dir = home_dir + "/hacl-star";
    let lib_dir = hacl_dir.clone() + "/dist/gcc-compatible";
    let _kremlin_dir = hacl_dir.clone() + "/dist/kremlin";

    // Set library name and type
    let mode = "dylib";
    let name = "evercrypt";

    // Set LLVM path
    let llvm_config = llvm_dir + "llvm-config";
    println!("cargo:rustc-env=LLVM_CONFIG_PATH={}", llvm_config);

    // Set re-run trigger
    println!("cargo:rerun-if-changed=wrapper.h");

    // Set up rustc link environment
    println!("cargo:rustc-link-search=native={}", lib_dir);
    println!("cargo:rustc-link-lib={}={}", mode, name);
    println!("cargo:rustc-env=DYLD_LIBRARY_PATH={}", lib_dir);
    println!("cargo:rustc-link-lib=dylib={}", name);

    // HACL/Evercrypt header paths
    let hacl_includes = vec![
        "-Ihacl-star/dist/gcc-compatible",
        "-Ihacl-star/dist/kremlin/include",
        "-Ihacl-star/dist/kremlin/kremlib/dist/minimal",
    ];

    let bindings = bindgen::Builder::default()
        // Header to wrap HACL/Evercrypt headers
        .header("wrapper.h")
        // Set inlcude paths for HACL/Evercrypt headers
        .clang_args(hacl_includes.iter())
        // Allow function we want to have in
        .whitelist_function("EverCrypt_AutoConfig2_init")
        .whitelist_function("EverCrypt_AEAD_.*")
        .whitelist_var("Sepc_.*")
        .whitelist_var("EverCrypt_.*")
        // Block everything we don't need or define ourselfs.
        .blacklist_type("EverCrypt_AEAD_state_s.*")
        // Generate bindings
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
