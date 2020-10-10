extern crate bindgen;

use std::{collections::HashMap, env, fs, path::Path, path::PathBuf, process::Command};

// TODO: add ARM builds

#[cfg(windows)]
fn build_hacl(lib_dir: &Path, build_config: &BuildConfig) {
    // TODO: add Windows builds
    panic!("Windows builds are not supported yet. Sorry!");
}

#[cfg(not(windows))]
fn build_hacl(lib_dir: &Path, build_config: &BuildConfig) {
    // Run configure
    let mut configure_cmd = Command::new(
        fs::canonicalize(lib_dir.join("configure")).expect("Failed to find configure script!"),
    );
    let configure_status = configure_cmd
        .current_dir(lib_dir)
        .args(&build_config.config_flags)
        .arg("--disable-ocaml")
        .envs(build_config.env.clone())
        .status()
        .expect("Failed to run configure");
    if !configure_status.success() {
        panic!("Failed to run configure.")
    }

    // Make a clean build.
    // This might fail but we don't care.
    let mut make_cmd = Command::new("make");
    let _make_status = make_cmd.current_dir(lib_dir).arg("clean").status();

    // Run make
    let mut make_cmd = Command::new("make");
    if !build_config.make_flags.is_empty() {
        make_cmd.args(&build_config.make_flags);
    }
    let make_status = make_cmd
        .current_dir(lib_dir)
        .arg("-j")
        .arg("libevercrypt.a")
        .env("DISABLE_OCAML_BINDINGS", "1")
        .status()
        .expect("Failed to run make");
    if !make_status.success() {
        panic!("Failed to run make.");
    }
}

#[allow(dead_code)]
fn llvm_path() {
    let llvm_dir = env::var("LLVM_DIR").unwrap();

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
    cross: bool,
    config_flags: Vec<&'static str>,
    make_flags: Vec<&'static str>,
    env: HashMap<String, String>,
}

#[allow(dead_code)]
impl BuildConfig {
    fn new(hacl_src_dir: &'static str, cross: bool) -> Self {
        Self {
            hacl_src_dir,
            cross,
            config_flags: vec![],
            make_flags: vec![],
            env: HashMap::new(),
        }
    }
    fn set_config_flags(&mut self, config_flags: Vec<&'static str>) -> &mut Self {
        self.config_flags = config_flags;
        self
    }
    fn set_cross_config_flags(&mut self, config_flags: Vec<&'static str>) -> &mut Self {
        if self.cross {
            self.config_flags = config_flags;
        }
        self
    }
    fn set_make_flags(&mut self, make_flags: Vec<&'static str>) -> &mut Self {
        self.make_flags = make_flags;
        self
    }
    fn set_cross_make_flags(&mut self, make_flags: Vec<&'static str>) -> &mut Self {
        if self.cross {
            self.make_flags = make_flags;
        }
        self
    }
    fn set_env(&mut self, env: HashMap<String, String>) -> &mut Self {
        self.env = env;
        self
    }
    fn set_cross_env(&mut self, env: HashMap<String, String>) -> &mut Self {
        if self.cross {
            self.env = env;
        }
        self
    }
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
    let host = env::var("HOST").unwrap();
    let target_dir = env::var("CARGO_TARGET_DIR").unwrap_or("target".to_string());
    let _target_path = Path::new(&home_dir)
        .join("..")
        .join(&target_dir)
        .join(&profile);

    let cross = target != host;
    // Pre-populate config with some commonly used values.
    let mut cfg = BuildConfig::new("gcc-compatible", cross);

    // Make sure we can build for the given OS and architecture.
    let build_config = match target.as_str() {
        // No 32-bit support on any platform for now.
        "x86_64-apple-darwin" => cfg.set_cross_config_flags(vec!["-target", "x86_64-apple-darwin"]),
        "x86_64-unknown-linux-gnu" => {
            cfg.set_cross_config_flags(vec!["-target", "x86_64-unknown-linux-gnu"])
        }
        // ARM32 v7 (e.g. raspberry pi 3)
        // TODO: set TOOLCHAIN
        "armv7-unknown-linux-gnueabihf" => {
            cfg.set_cross_config_flags(vec!["-target", "arm32-none-linux-gnu"])
        }
        // ARM64 Linux
        // TODO: set TOOLCHAIN
        "aarch64-unknown-linux-gnu" => {
            cfg.set_cross_config_flags(vec!["-target", "aarch64-none-linux-gnu"])
        }
        // Only MSVC builds are supported on Windows.
        "x86_64-pc-windows-msvc" => panic!("Target '{:?}' is not supported yet.", target),
        // TODO: Which Android versions do we want to support?
        "aarch64-linux-android" => panic!("Target '{:?}' is not supported yet.", target),
        _ => panic!("Target '{:?}' is not supported yet.", target),
    };

    // Set HACL/Evercrypt paths
    let hacl_dir = Path::new(&out_dir).join("hacl-star");
    let hacl_src_path = hacl_dir.join("dist").join(build_config.hacl_src_dir);

    // Set library name and type
    let mode = "static";
    let name = "evercrypt";

    let hacl_src_path_str = hacl_src_path.to_str().unwrap();

    // Set up rustc link environment
    println!("cargo:rustc-link-search=native={}", hacl_src_path_str);
    println!("cargo:rustc-link-lib={}={}", mode, name);
    println!("cargo:rustc-env=DYLD_LIBRARY_PATH={}", hacl_src_path_str);
    println!("cargo:rustc-env=LD_LIBRARY_PATH={}", hacl_src_path_str);

    // HACL/Evercrypt header paths
    let kremlin_include = hacl_dir.join("dist").join("kremlin").join("include");
    let kremlib_minimal = hacl_dir
        .join("dist")
        .join("kremlin")
        .join("kremlib")
        .join("dist")
        .join("minimal");
    let hacl_includes = vec![
        "-I".to_owned() + hacl_src_path_str,
        "-I".to_owned() + kremlin_include.to_str().unwrap(),
        "-I".to_owned() + kremlib_minimal.to_str().unwrap(),
    ];

    // Build hacl/evercrypt
    copy_hacl_to_out(&out_path);
    build_hacl(&hacl_src_path, &build_config);

    let bindings = bindgen::Builder::default()
        // Header to wrap HACL/Evercrypt headers
        .header("wrapper.h")
        // Set include paths for HACL/Evercrypt headers
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
        // Block everything we don't need or define ourselves.
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
