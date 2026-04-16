/*
 * Copyright © 2021 Keegan Saunders
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use std::{
    env,
    fs::{remove_file, File},
    io::{self, Error},
    path::Path,
};
use tar::Archive;
use xz::read::XzDecoder;

/// private function to retry download in case of error.
fn download_and_use_devkit_internal(kind: &str, version: &str, force_download: bool) -> Result<String, Error> {
    let mut target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir_path = Path::new(&out_dir);

    if target_arch == "aarch64" {
        target_arch = "arm64".to_string();
    } else if target_arch == "arm" {
        target_arch = "armhf".to_string();
    } else if target_arch == "i686" {
        target_arch = "x86".to_string();
    }

    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    let devkit_name = format!("frida-{kind}-devkit-{version}-{os}-{target_arch}",);

    let devkit_path = out_dir_path.join(&devkit_name);
    let devkit_tar = out_dir_path.join(format!("{}.tar.xz", &devkit_name));

    if force_download {
        drop(remove_file(&devkit_tar));
    }

    if !devkit_path.is_dir() {
        if !devkit_tar.is_file() {
            let frida_url = format!("https://github.com/frida/frida/releases/download/{version}/{devkit_name}.tar.xz",);

            println!(
                "cargo:warning=Frida {} devkit not found, downloading from {}...",
                kind, &frida_url,
            );
            // Download devkit
            let mut resp = reqwest::blocking::get(&frida_url).expect("devkit download request failed");
            let mut out = File::create(&devkit_tar).expect("failed to create devkit tar file");
            io::copy(&mut resp, &mut out).expect("failed to copy devkit tar content");
        }
        let tar_xz = File::open(&devkit_tar).expect("failed to open devkit tar.xz for extraction");
        let tar = XzDecoder::new(tar_xz);
        let mut archive = Archive::new(tar);
        archive.unpack(out_dir_path)?;
    }

    println!("cargo:rustc-link-search={}", out_dir.to_string_lossy());
    println!("cargo:rustc-link-lib=static=frida-{kind}");

    Ok(out_dir.to_string_lossy().to_string())
}

#[must_use]
pub fn download_and_use_devkit(kind: &str, version: &str) -> String {
    download_and_use_devkit_internal(kind, version, false)
        .or_else(|e| {
            println!("cargo:warning=Failed to unpack devkit: {e}, retrying download...");
            download_and_use_devkit_internal(kind, version, true)
        })
        .expect("cannot extract the devkit tar.gz")
}
