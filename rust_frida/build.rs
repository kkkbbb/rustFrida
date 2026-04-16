fn main() {
    // 当 agent.so 变化时重新编译 host（include_bytes! 缓存问题）
    println!("cargo::rerun-if-changed=../target/aarch64-linux-android/debug/libagent.so");
    println!("cargo::rerun-if-changed=../target/aarch64-linux-android/release/libagent.so");
    println!("cargo::rerun-if-changed=../loader/build/bootstrapper.bin");
    println!("cargo::rerun-if-changed=../loader/build/rustfrida-loader.bin");

    if std::env::var_os("CARGO_FEATURE_QBDI").is_some() {
        let target = std::env::var("TARGET").expect("TARGET not set");
        let profile = std::env::var("PROFILE").expect("PROFILE not set");
        let manifest_dir =
            std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
        let workspace_root = manifest_dir.parent().expect("rust_frida must be inside workspace root");
        let helper_path = format!(
            "{}/target/{}/{}/libqbdi_helper.so",
            workspace_root.display(),
            target,
            if profile == "release" { "release" } else { "debug" }
        );
        println!("cargo:rustc-env=QBDI_HELPER_SO_PATH={}", helper_path);
        println!("cargo:rerun-if-changed={}", helper_path);
    }
}
