#[cfg(not(windows))]
extern crate bindgen;

use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{Read, Write},
    path::Path,
    process::Command,
};

#[cfg(windows)]
fn build_hacl(lib_dir: &Path, build_config: &BuildConfig) {
    println!(
        "Compiling hacl-star in {:?} with {:?}",
        lib_dir, build_config
    );
    let mut build_status = Command::new("cmd");
    build_status
        .args(&["/C", lib_dir.join("hacl-build.bat").to_str().unwrap()])
        .envs(build_config.env.clone());

    let build_status = build_status.status().expect("Failed to run hacl build");
    if !build_status.success() {
        panic!("Failed to run hacl build.")
    }
}

#[cfg(not(windows))]
fn build_hacl(lib_dir: &Path, build_config: &BuildConfig) {
    // Run configure
    let mut configure_cmd = Command::new(
        std::fs::canonicalize(lib_dir.join("configure")).expect("Failed to find configure script!"),
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

#[cfg(not(windows))]
fn copy_hacl_to_out(out_dir: &Path, _hacl_src_dir: &Path) {
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

#[cfg(windows)]
fn copy_hacl_to_out(out_dir: &Path, hacl_src_dir: &Path) {
    let cp_status = Command::new("cmd")
        .args(&[
            "/C",
            "robocopy",
            "hacl-star",
            &format!("{}\\hacl-star", out_dir.to_str().unwrap()),
            "/e",
            "/s",
        ])
        .status()
        .expect(&format!("Failed to copy hacl-star to {:?}", out_dir));

    println!("Return code {}", cp_status.code().unwrap());

    println!("Copied hacl-star to {:?}", out_dir);
    let cp_status = Command::new("cmd")
        .args(&[
            "/C",
            "copy",
            "hacl-build.bat",
            hacl_src_dir.to_str().unwrap(),
        ])
        .status()
        .expect(&format!(
            "Failed to copy hacl-build.bat to {:?}",
            hacl_src_dir
        ));
    println!("Return code {}", cp_status.code().unwrap());
    println!("Copied hacl-build.bat to {:?}", hacl_src_dir);
}

#[derive(Debug)]
struct BuildConfig {
    hacl_src_dir: &'static str,
    cross: bool,
    config_flags: Vec<&'static str>,
    make_flags: Vec<&'static str>,
    env: HashMap<String, String>,
    lib_name: &'static str,
    windows: bool,
}

#[allow(dead_code)]
impl BuildConfig {
    fn new(hacl_src_dir: &'static str, lib_name: &'static str, cross: bool) -> Self {
        Self {
            hacl_src_dir,
            cross,
            config_flags: vec![],
            make_flags: vec![],
            env: HashMap::new(),
            lib_name,
            windows: false,
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
    fn set_lib_name(&mut self, lib_name: &'static str) -> &mut Self {
        self.lib_name = lib_name;
        self
    }
    fn windows(&mut self) -> &mut Self {
        self.windows = true;
        self
    }
    fn set_hacl_src_dir(&mut self, hacl_src_dir: &'static str) -> &mut Self {
        self.hacl_src_dir = hacl_src_dir;
        self
    }
}

/// Check if the hacl-star revision changed.
///
/// Returns true if there's a new hacl-star revision and false otherwise.
fn rebuild(home_dir: &Path, out_dir: &Path) -> bool {
    let config_file = out_dir.join("config");
    let hacl_revision = Command::new("git")
        .current_dir(home_dir)
        .args(&["submodule", "status", "hacl-star"])
        .output()
        .expect("Failed to get hacl-star revision")
        .stdout;
    let hacl_revision = if hacl_revision.is_empty() || hacl_revision.len() < 42 {
        String::new()
    } else {
        String::from_utf8(hacl_revision.clone()[1..41].to_vec()).unwrap()
    };
    match File::open(config_file.clone()) {
        Ok(mut file) => {
            // We have the file already. Check the revision.
            let mut prev_rev = String::new();
            file.read_to_string(&mut prev_rev)
                .expect("Error reading hacl revision config");
            if prev_rev != hacl_revision {
                println!(" previous hacl_revision: {:?}", prev_rev);
                // We need to rebuild and write the new revision to the config.
                drop(file);
                let mut new_file = File::create(config_file).unwrap();
                new_file.write(&hacl_revision.into_bytes()).unwrap();
                return true;
            }
            return false;
        }
        Err(_) => {
            // The file doesn't exist. Write it and build.
            let mut new_file = File::create(config_file).unwrap();
            new_file.write(&hacl_revision.into_bytes()).unwrap();
            return true;
        }
    }
}

#[cfg(not(windows))]
fn create_bindings(hacl_dir: &Path, hacl_src_path_str: &str, home_dir: &Path) {
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

    let bindings = bindgen::Builder::default()
        // Header to wrap HACL/Evercrypt headers
        .header("wrapper.h")
        // Set include paths for HACL/Evercrypt headers
        .clang_args(hacl_includes.iter())
        // Allow function we want to have in
        .allowlist_function("EverCrypt_AutoConfig2_.*")
        .allowlist_function("EverCrypt_AEAD_.*")
        .allowlist_function("EverCrypt_Curve25519_.*")
        .allowlist_function("EverCrypt_Ed25519_.*")
        .allowlist_function("EverCrypt_Hash_.*")
        .allowlist_function("EverCrypt_HKDF_.*")
        .allowlist_function("EverCrypt_HMAC_.*")
        .allowlist_function("Hacl_P256_.*")
        .allowlist_function("Hacl_SHA3_.*")
        .allowlist_var("EverCrypt_Error_.*")
        .allowlist_var("Spec_.*")
        // Block everything we don't need or define ourselves.
        .blocklist_type("Hacl_Streaming_.*")
        .blocklist_type("EverCrypt_AEAD_state_s.*")
        // Generate bindings
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    // let bindings_path = out_path.join("bindings.rs");
    let home_bindings = home_dir.join("src/bindings/bindings.rs");
    bindings
        .write_to_file(home_bindings.clone())
        .expect("Couldn't write bindings!");
}

#[cfg(windows)]
fn create_bindings(_hacl_dir: &Path, _hacl_src_path_str: &str, _home_dir: &Path) {}

fn main() {
    // Set re-run trigger
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=hacl-star");

    // Get ENV variables
    let home_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let home_dir = Path::new(&home_dir);
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir);
    let _profile = env::var("PROFILE").unwrap();
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();

    // Set library type
    let mode = "static";

    let cross = target != host;
    // Pre-populate config with some commonly used values.
    let mut cfg = BuildConfig::new("gcc-compatible", "evercrypt", cross);

    // Make sure we can build for the given OS and architecture.
    let build_config = match target.as_str() {
        // No 32-bit support on any platform for now.
        "x86_64-apple-darwin" => cfg.set_cross_config_flags(vec!["-target", "x86_64-apple-darwin"]),
        "i686-unknown-linux-gnu" => cfg.set_cross_config_flags(vec!["-target", "ia32"]),
        "x86_64-unknown-linux-gnu" => {
            cfg.set_cross_config_flags(vec!["-target", "x86_64-unknown-linux-gnu"])
        }
        // ARM32 v7 (e.g. raspberry pi 3)
        // TODO: set TOOLCHAIN when cross compiling
        "armv7-unknown-linux-gnueabihf" => {
            cfg.set_cross_config_flags(vec!["-target", "arm32-none-linux-gnu"])
        }
        // ARM64 Linux
        // TODO: set TOOLCHAIN when cross compiling
        "aarch64-unknown-linux-gnu" => {
            cfg.set_cross_config_flags(vec!["-target", "aarch64-none-linux-gnu"])
        }
        // Only MSVC builds are supported on Windows.
        "x86_64-pc-windows-msvc" => cfg
            .set_lib_name("libevercrypt")
            .windows()
            .set_hacl_src_dir("msvc-compatible"),
        // TODO: Which Android versions do we want to support?
        "aarch64-linux-android" => panic!("Target '{:?}' is not supported yet.", target),
        _ => panic!("Target '{:?}' is not supported yet.", target),
    };

    // Set HACL/Evercrypt paths
    let hacl_dir = out_path.join("hacl-star");
    let hacl_src_path = hacl_dir.join("dist").join(build_config.hacl_src_dir);
    let hacl_src_path_str = hacl_src_path.to_str().unwrap();

    println!("build_config: {:?}", build_config);
    println!("out_path: {:?}", out_path);
    println!("hacl_src_path: {:?}", hacl_src_path);

    // Build hacl/evercrypt
    // Always rebuild on windows for now. TODO: fix rebuild check on Windows.
    if build_config.windows || rebuild(home_dir, &out_path) {
        // Only rebuild if the hacl revision changed.
        copy_hacl_to_out(&out_path, &hacl_src_path);
        build_hacl(&hacl_src_path, &build_config);
    }

    // Generate new bindings. This is a no-op on Windows.
    create_bindings(&hacl_dir, hacl_src_path_str, home_dir);

    // Link evercrypt library.
    println!("cargo:rustc-link-search=native={}", hacl_src_path_str);
    println!("cargo:lib={}", hacl_src_path_str);
    println!("cargo:rustc-link-lib={}={}", mode, cfg.lib_name);
}
