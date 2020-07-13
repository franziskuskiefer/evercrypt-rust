extern crate bindgen;

use std::{env, fs, path::Path, path::PathBuf, process::Command};

#[cfg(windows)]
fn build_hacl() {
    unimplemented!();
}

#[cfg(not(windows))]
fn build_hacl(lib_dir: &Path) {
    // Run configure
    // XXX: Do we need to configure anything here?
    let mut configure_cmd = Command::new(
        fs::canonicalize(lib_dir.join("configure")).expect("Failed to find configure script!"),
    );
    let configure_status = configure_cmd
        .current_dir(lib_dir)
        .status()
        .expect("Failed to run configure");
    if !configure_status.success() {
        panic!("Failed to run configure.")
    }

    // Run make
    let mut make_cmd = Command::new("make");
    let make_status = make_cmd
        .current_dir(lib_dir)
        .arg("-j")
        .env("DISABLE_OCAML_BINDINGS", "1")
        .status()
        .expect("Failed to run make");
    if !make_status.success() {
        panic!("Failed to run make.")
    }
}

fn copy_evercrypt_lib(src: &str, dst: &Path) {
    println!("copy to {:?}", dst);
    Command::new("cp")
        .arg(src)
        .arg(dst)
        .status()
        .expect("Failed to copy evercrypt library");
}

fn main() {
    // Get ENV variables
    let home_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let llvm_dir =
        env::var("LLVM_DIR").unwrap_or("/usr/local/Cellar/llvm/10.0.0_3/bin/".to_string());
    let out_dir = env::var("OUT_DIR").unwrap();
    let profile = env::var("PROFILE").unwrap();
    let target = env::var("CARGO_TARGET_DIR").unwrap_or("target".to_string());
    let target_path = Path::new(&home_dir).join("..").join(&target).join(&profile);

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
    println!("cargo:rustc-env=LD_LIBRARY_PATH={}", lib_dir);
    println!("cargo:rustc-link-lib=dylib={}", name);

    // HACL/Evercrypt header paths
    let hacl_includes = vec![
        "-Ihacl-star/dist/gcc-compatible",
        "-Ihacl-star/dist/kremlin/include",
        "-Ihacl-star/dist/kremlin/kremlib/dist/minimal",
    ];

    // Build hacl/evercrypt
    build_hacl(Path::new(&lib_dir));

    // Copy evercrypt library to the target directory.
    copy_evercrypt_lib(&(lib_dir + "/libevercrypt.so"), &target_path);

    let bindings = bindgen::Builder::default()
        // Header to wrap HACL/Evercrypt headers
        .header("wrapper.h")
        // Set inlcude paths for HACL/Evercrypt headers
        .clang_args(hacl_includes.iter())
        // Allow function we want to have in
        .whitelist_function("EverCrypt_AutoConfig2_.*")
        .whitelist_function("EverCrypt_AEAD_.*")
        .whitelist_function("EverCrypt_Curve25519_.*")
        .whitelist_function("EverCrypt_Ed25519_.*")
        .whitelist_function("EverCrypt_Hash_.*")
        .whitelist_function("EverCrypt_HKDF_.*")
        .whitelist_function("EverCrypt_HMAC_.*")
        .whitelist_function("Hacl_P256_.*")
        .whitelist_var("EverCrypt_Error_.*")
        .whitelist_var("Spec_.*")
        // Block everything we don't need or define ourselfs.
        .blacklist_type("Hacl_Streaming_.*")
        .blacklist_type("EverCrypt_AEAD_state_s.*")
        // Generate bindings
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(out_dir);
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
