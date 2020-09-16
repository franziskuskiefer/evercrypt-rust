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
    // TODO: add config for iOS and Android
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

struct BuildConfig {
    hacl_src_dir: &'static str,
}

fn main() {
    // Set re-run trigger
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=hacl-star");

    // Get ENV variables
    let home_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir);
    let profile = env::var("PROFILE").unwrap();
    let target = env::var("TARGET").unwrap();
    let target_dir = env::var("CARGO_TARGET_DIR").unwrap_or("target".to_string());
    let _target_path = Path::new(&home_dir)
        .join("..")
        .join(&target_dir)
        .join(&profile);

    // Make sure we can build for the given OS and architecture.
    let build_config = match target.as_str() {
        // No 32-bit support on any platform for now.
        "x86_64-apple-darwin" => BuildConfig {
            hacl_src_dir: "gcc-compatible",
        },
        "x86_64-unknown-linux-gnu" => BuildConfig {
            hacl_src_dir: "gcc-compatible",
        },
        // Only MSVC builds are supported on Windows.
        "x86_64-pc-windows-msvc" => panic!("Target '{:?}' is not supported yet.", target),
        // TODO: Which Android versions do we want to support?
        "aarch64-linux-android" => panic!("Target '{:?}' is not supported yet.", target),
        _ => panic!("Target '{:?}' is not supported yet.", target),
    };

    // println!("Target: {:?}", target);

    // Set HACL/Evercrypt paths
    let hacl_dir = Path::new(&out_dir).join("hacl-star");
    let hacl_src_path = hacl_dir.join("dist").join(build_config.hacl_src_dir);

    // Set library name and type
    let mode = "static";
    let name = "evercrypt";

    // Set up rustc link environment
    println!(
        "cargo:rustc-link-search=native={}",
        hacl_src_path.to_str().unwrap()
    );
    println!("cargo:rustc-link-lib={}={}", mode, name);
    println!(
        "cargo:rustc-env=DYLD_LIBRARY_PATH={}",
        hacl_src_path.to_str().unwrap()
    );
    println!(
        "cargo:rustc-env=LD_LIBRARY_PATH={}",
        hacl_src_path.to_str().unwrap()
    );

    // HACL/Evercrypt header paths
    let hacl_includes = vec![
        "-Ihacl-star/dist/".to_owned() + build_config.hacl_src_dir,
        "-Ihacl-star/dist/kremlin/include".to_string(),
        "-Ihacl-star/dist/kremlin/kremlib/dist/minimal".to_string(),
    ];

    // Build hacl/evercrypt
    copy_hacl_to_out(&out_path);
    build_hacl(&hacl_src_path);

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
        .whitelist_function("Hacl_SHA3_.*")
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
