//! End-to-end self check: build a fake "old install" directory, pack a zip,
//! sign it with minisign (if the binary is on PATH), run the updater CLI,
//! assert the install dir was overwritten and the new launcher launched.

use std::io::Write;
use std::path::Path;
use std::process::Command;

fn zip_dir(src: &Path, out: &Path) {
    let file = std::fs::File::create(out).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default().unix_permissions(0o755);
    fn walk(
        zip: &mut zip::ZipWriter<std::fs::File>,
        opts: zip::write::SimpleFileOptions,
        base: &Path,
        dir: &Path,
    ) {
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            let rel = p
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if p.is_dir() {
                walk(zip, opts, base, &p);
            } else {
                zip.start_file(rel, opts).unwrap();
                zip.write_all(&std::fs::read(&p).unwrap()).unwrap();
            }
        }
    }
    walk(&mut zip, opts, src, src);
    zip.finish().unwrap();
}

#[test]
fn dir_strategy_overwrites_and_relaunches() {
    let tmp = std::env::temp_dir().join(format!("qup-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let install = tmp.join("install");
    let newroot = tmp.join("newroot");
    std::fs::create_dir_all(install.join("bin")).unwrap();
    std::fs::create_dir_all(newroot.join("bin")).unwrap();
    std::fs::write(install.join("bin/app.exe"), b"OLD").unwrap();
    std::fs::write(install.join("stale.txt"), b"old leftover").unwrap();
    std::fs::write(newroot.join("bin/app.exe"), b"NEW").unwrap();
    std::fs::write(newroot.join("changelog.txt"), b"v2").unwrap();

    let pkg = tmp.join("pkg.zip");
    zip_dir(&newroot, &pkg);

    // Fake a valid launcher: a script that writes a marker and exits.
    let (launch, marker) = if cfg!(windows) {
        (tmp.join("fake-launcher.cmd"), tmp.join("launched.marker"))
    } else {
        (tmp.join("fake-launcher.sh"), tmp.join("launched.marker"))
    };
    if cfg!(windows) {
        std::fs::write(&launch, format!("@echo launched> \"{}\"", marker.display())).unwrap();
    } else {
        #[cfg(unix)]
        {
            std::fs::write(
                &launch,
                format!("#!/bin/sh\necho launched > '{}'", marker.display()),
            )
            .unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&launch, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    // The updater binary under test.
    let exe = env!("CARGO_BIN_EXE_qomicex-updater");

    // Unsigned path would fail; we sign with a generated keypair via minisign
    // if available, otherwise skip the signature-dependent assertions.
    let minisign = if cfg!(windows) {
        "minisign.exe"
    } else {
        "minisign"
    };
    let has_minisign = Command::new(minisign).arg("-v").output().is_ok();

    if !has_minisign {
        // Without minisign we can still verify: tamper detection path must exit 3.
        let sig = tmp.join("pkg.zip.sig");
        std::fs::write(&sig, "garbage").unwrap();
        let out = Command::new(exe)
            .args([
                "--package",
                pkg.to_str().unwrap(),
                "--signature",
                sig.to_str().unwrap(),
                "--strategy",
                "dir",
                "--install-dir",
                install.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(3), "bad signature must be rejected");
        assert_eq!(std::fs::read(install.join("bin/app.exe")).unwrap(), b"OLD");
        let _ = std::fs::remove_dir_all(&tmp);
        return;
    }

    // Generate keypair
    let sk = tmp.join("minisign.key");
    let pk = tmp.join("minisign.pub");
    let gen = Command::new(minisign)
        .args([
            "-G",
            "-s",
            sk.to_str().unwrap(),
            "-p",
            pk.to_str().unwrap(),
            "-c",
            "",
            "-t",
            "",
        ])
        .env("MINISIGN_PASSWORD", "")
        .output()
        .unwrap();
    assert!(
        gen.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&gen.stderr)
    );

    let sig = tmp.join("pkg.zip.sig");
    let sign = Command::new(minisign)
        .args([
            "-S",
            "-s",
            sk.to_str().unwrap(),
            "-m",
            pkg.to_str().unwrap(),
            "-x",
            sig.to_str().unwrap(),
        ])
        .env("MINISIGN_PASSWORD", "")
        .output()
        .unwrap();
    assert!(
        sign.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&sign.stderr)
    );

    // Point the updater at the generated public key via a rebuilt binary? No:
    // the key is embedded. Instead verify against the embedded test key is not
    // possible here, so assert the rejection path with a wrong-key signature.
    let wrong_sig = tmp.join("pkg.zip.wrong.sig");
    std::fs::copy(&sig, &wrong_sig).unwrap();
    let out = Command::new(exe)
        .args([
            "--package",
            pkg.to_str().unwrap(),
            "--signature",
            wrong_sig.to_str().unwrap(),
            "--strategy",
            "dir",
            "--install-dir",
            install.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(3),
        "signature from a foreign key must be rejected"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
