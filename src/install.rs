//! Install strategies: unzip the package into a staging directory next to the
//! target, then move files into place. Elevation (pkexec / osascript) is only
//! used when the target is not writable by the current user.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- waiting

pub fn wait_process_exit(pid: u32, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    while process_alive(pid) {
        if start.elapsed() > timeout {
            return Err(format!("timed out waiting for pid {pid} to exit"));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Ok(())
}

#[cfg(windows)]
fn process_alive(pid: u32) -> bool {
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output()
        .map(|o| !String::from_utf8_lossy(&o.stdout).contains("INFO:"))
        .unwrap_or(true)
}

#[cfg(not(windows))]
fn process_alive(pid: u32) -> bool {
    Command::new("ps")
        .args(["-p", &pid.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(true)
}

// ---------------------------------------------------------------- zip

/// Extract the zip into `staging`, preserving unix modes and rejecting
/// path traversal entries.
fn extract_zip(zip_path: &Path, staging: &Path) -> io::Result<()> {
    let file = std::fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let rel = entry.mangled_name();
        if rel.as_os_str().is_empty() {
            continue;
        }
        let out = staging.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out)?;
            continue;
        }
        if let Some(p) = out.parent() {
            std::fs::create_dir_all(p)?;
        }
        let mut out_f = std::fs::File::create(&out)?;
        std::io::copy(&mut entry, &mut out_f)?;
        #[cfg(unix)]
        if let Some(mode) = entry.unix_mode() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- dir strategy

pub fn install_dir(package: &Path, install_dir: Option<&Path>) -> Result<(), String> {
    let dir = install_dir
        .ok_or("--install-dir is required for the dir strategy")?
        .to_path_buf();
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let staging = staging_path(&dir, "dir");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
    if let Err(e) = extract_zip(package, &staging).and_then(|_| {
        move_tree(&staging, &dir)?;
        Ok(())
    }) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e.to_string());
    }
    let _ = std::fs::remove_dir_all(&staging);
    Ok(())
}

/// Move every file/dir under `src` into `dst` (same volume: staging lives
/// next to dst so renames stay atomic).
fn move_tree(src: &Path, dst: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let target = dst.join(entry.file_name());
        if ty.is_dir() {
            std::fs::create_dir_all(&target)?;
            move_tree(&entry.path(), &target)?;
        } else {
            if target.exists() {
                std::fs::remove_file(&target)?;
            }
            std::fs::rename(entry.path(), &target)?;
        }
    }
    Ok(())
}

fn staging_path(target: &Path, tag: &str) -> PathBuf {
    let name = target
        .file_name()
        .map(|n| format!(".{tag}-update-tmp-{}", n.to_string_lossy()))
        .unwrap_or_else(|| format!(".{tag}-update-tmp"));
    target.parent().unwrap_or(target).join(name)
}

// ---------------------------------------------------------------- appimage strategy

pub fn install_appimage(package: &Path, appimage: Option<&Path>) -> Result<(), String> {
    let target = appimage
        .ok_or("--appimage is required for the appimage strategy")?
        .to_path_buf();
    let staging = staging_path(&target, "appimage");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
    let result = (|| -> io::Result<()> {
        extract_zip(package, &staging)?;
        let new_image = first_file(&staging).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "package contains no AppImage")
        })?;
        if target.exists() {
            std::fs::remove_file(&target)?;
        }
        std::fs::rename(&new_image, &target)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&staging);
    result.map_err(|e| e.to_string())
}

fn first_file(dir: &Path) -> Option<PathBuf> {
    for entry in std::fs::read_dir(dir).ok()? {
        let entry = entry.ok()?;
        if entry.file_type().ok()?.is_file() {
            return Some(entry.path());
        }
    }
    None
}

// ---------------------------------------------------------------- app strategy (macOS)

pub fn install_app(package: &Path, app_bundle: Option<&Path>) -> Result<(), String> {
    let bundle = app_bundle
        .ok_or("--app-bundle is required for the app strategy")?
        .to_path_buf();
    if !bundle.is_dir() {
        return Err(format!("app bundle {} not found", bundle.display()));
    }
    if dir_writable(&bundle) {
        return install_dir(package, Some(&bundle));
    }
    // /Applications is admin-owned: stage locally, then elevate the copy.
    let staging = std::env::temp_dir().join(format!("qomicex-update-app-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
    extract_zip(package, &staging).map_err(|e| e.to_string())?;
    elevate_copy(&staging, &bundle, true).map_err(|e| {
        let _ = std::fs::remove_dir_all(&staging);
        e
    })?;
    Ok(())
}

// ---------------------------------------------------------------- system strategy (deb/rpm)

pub fn install_system(package: &Path) -> Result<(), String> {
    let staging =
        std::env::temp_dir().join(format!("qomicex-update-system-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
    extract_zip(package, &staging).map_err(|e| e.to_string())?;
    // Package layout is relative to "/" (usr/bin/...). Overlay onto /.
    elevate_copy(&staging, Path::new("/"), false).map_err(|e| {
        let _ = std::fs::remove_dir_all(&staging);
        e
    })?;
    Ok(())
}

/// Copy `src/.` into `dst` with polkit/admin elevation, removing src afterwards.
#[cfg(target_os = "linux")]
fn elevate_copy(src: &Path, dst: &Path, cleanup_dst: bool) -> Result<(), String> {
    let script =
        std::env::temp_dir().join(format!("qomicex-update-elevate-{}.sh", std::process::id()));
    let mut body = format!(
        "cp -a '{s}'/. '{d}'/ && rm -rf '{s}'",
        s = src.display(),
        d = dst.display()
    );
    if cleanup_dst {
        body = format!(
            "cp -a '{s}'/. '{d}'/ && rm -rf '{s}' '{d}'/*.qdtmp",
            s = src.display(),
            d = dst.display()
        );
    }
    std::fs::write(&script, format!("#!/bin/sh\nset -e\n{body}\n")).map_err(|e| e.to_string())?;
    let status = Command::new("pkexec")
        .arg("sh")
        .arg(&script)
        .status()
        .map_err(|e| format!("cannot run pkexec (polkit agent missing?): {e}"))?;
    let _ = std::fs::remove_file(&script);
    if !status.success() {
        return Err(format!(
            "elevated copy failed (pkexec exit {})",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn elevate_copy(_src: &Path, _dst: &Path, _cleanup_dst: bool) -> Result<(), String> {
    Err("elevation not supported on this platform".into())
}

fn dir_writable(dir: &Path) -> bool {
    let probe = dir.join(".qomicex-update-probe");
    match std::fs::write(&probe, b"") {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

// ---------------------------------------------------------------- relaunch

pub fn launch(exe: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        Command::new(exe)
            .creation_flags(0x00000008 | 0x00000200) // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
            .spawn()?;
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::process::CommandExt;
        Command::new(exe).process_group(0).spawn()?;
    }
    Ok(())
}
