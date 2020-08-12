extern crate bindgen;

use std::{env, fs, path::Path, path::PathBuf, process::Command};

// TODO: add ARM builds

#[cfg(windows)]
fn build_hacl() {
    // TODO: add Windows builds
    panic!("Windows builds are not supported yet. Sorry!");
}

#[cfg(not(windows))]
fn build_hacl(lib_dir: &Path) {
    // Run configure
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
        panic!("Failed to run make.");
    }
}

#[allow(dead_code)]
fn llvm_path() {
    let llvm_dir =
        env::var("LLVM_DIR").unwrap_or("/usr/local/Cellar/llvm/10.0.0_3/bin/".to_string());

    // Set LLVM path
    let llvm_config = llvm_dir + "llvm-config";
    println!("cargo:rustc-env=LLVM_CONFIG_PATH={}", llvm_config);
}

fn copy_hacl_to_out(out_dir: &Path) {
    let cp_status = Command::new("cp")
        .arg("-r")
        .arg("hacl-star")
        .arg(out_dir)
        .status()
        .expect("Failed to copy hacl-star to out_dir.");
    if !cp_status.success() {
        panic!("Failed to copy hacl-star to out_dir.")
    }
}

fn main() {
    // Set re-run trigger
    println!("cargo:rerun-if-changed=wrapper.h");

    // Get ENV variables
    let home_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir);
    let profile = env::var("PROFILE").unwrap();
    let target = env::var("CARGO_TARGET_DIR").unwrap_or("target".to_string());
    let _target_path = Path::new(&home_dir).join("..").join(&target).join(&profile);

    // Set HACL/Evercrypt paths
    let hacl_dir = Path::new(&out_dir).join("hacl-star");
    let hacl_src_dir = if cfg!(not(windows)) {
        "gcc-compatible"
    } else if cfg!(windows) {
        "msvc-compatible"
    } else {
        panic!("I can't build on this platform yet :(");
    };
    let gcc_lib_dir = hacl_dir.join("dist").join(hacl_src_dir);

    // Set library name and type
    let mode = "static";
    let name = "evercrypt";

    // Set up rustc link environment
    println!(
        "cargo:rustc-link-search=native={}",
        gcc_lib_dir.to_str().unwrap()
    );
    println!("cargo:rustc-link-lib={}={}", mode, name);
    println!(
        "cargo:rustc-env=DYLD_LIBRARY_PATH={}",
        gcc_lib_dir.to_str().unwrap()
    );
    println!(
        "cargo:rustc-env=LD_LIBRARY_PATH={}",
        gcc_lib_dir.to_str().unwrap()
    );

    // HACL/Evercrypt header paths
    let hacl_includes = vec![
        "-Ihacl-star/dist/gcc-compatible",
        "-Ihacl-star/dist/kremlin/include",
        "-Ihacl-star/dist/kremlin/kremlib/dist/minimal",
    ];

    // Build hacl/evercrypt
    copy_hacl_to_out(&out_path);
    build_hacl(&gcc_lib_dir);

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
