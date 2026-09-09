//! Qomicex Launcher self-updater.
//!
//! One-shot CLI invoked by the launcher after the update package (file-layout
//! zip + minisign signature) has been downloaded via the download center.
//!
//! Contract:
//! ```text
//! qomicex-updater \
//!   --package <zip> \         # downloaded update package (file layout)
//!   --signature <file> \      # minisign signature over the package
//!   --strategy <dir|appimage|app|system> \
//!   --install-dir <path> \    # dir strategy target (launcher install root)
//!   --appimage <path> \       # appimage strategy target ($APPIMAGE)
//!   --app-bundle <path> \     # app strategy target (.app directory)
//!   --wait-pid <pid> \        # wait for this process to exit before touching files
//!   --launch <exe>            # executable to start after a successful install
//! ```
//! Exit codes: 0 ok, 1 usage, 2 io, 3 signature invalid, 4 strategy failed,
//! 5 timed out waiting for the launcher to exit.

use std::path::PathBuf;
use std::sync::OnceLock;

mod install;
mod verify;

static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Append-only file log next to the signature file: the updater runs
/// detached with no console, so this is the only observable trace.
pub fn ulog(msg: &str) {
    use std::io::Write as _;
    if let Some(p) = LOG_PATH.get() {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let _ = writeln!(f, "[{secs}] {msg}");
        }
    }
    println!("{msg}");
}

const PUBLIC_KEY: &str = "untrusted comment: minisign public key: 35DD6AE53301ABE3
RWTjqwEz5WrdNfika/0W5/uR54TDhJNBSy2gRyvxxDefeXveXCb1a/ch";

pub struct Args {
    pub package: PathBuf,
    pub signature: PathBuf,
    pub strategy: String,
    pub install_dir: Option<PathBuf>,
    pub appimage: Option<PathBuf>,
    pub app_bundle: Option<PathBuf>,
    pub wait_pid: Option<u32>,
    pub launch: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut package = None;
    let mut signature = None;
    let mut strategy = None;
    let mut install_dir = None;
    let mut appimage = None;
    let mut app_bundle = None;
    let mut wait_pid = None;
    let mut launch = None;

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = |name: &str| -> Result<String, String> {
            it.next()
                .ok_or_else(|| format!("missing value for --{name}"))
        };
        match flag.as_str() {
            "--package" => package = Some(PathBuf::from(val("package")?)),
            "--signature" => signature = Some(PathBuf::from(val("signature")?)),
            "--strategy" => strategy = Some(val("strategy")?),
            "--install-dir" => install_dir = Some(PathBuf::from(val("install-dir")?)),
            "--appimage" => appimage = Some(PathBuf::from(val("appimage")?)),
            "--app-bundle" => app_bundle = Some(PathBuf::from(val("app-bundle")?)),
            "--wait-pid" => {
                wait_pid = Some(
                    val("wait-pid")?
                        .parse()
                        .map_err(|_| "--wait-pid expects a pid")?,
                )
            }
            "--launch" => launch = Some(PathBuf::from(val("launch")?)),
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(Args {
        package: package.ok_or("missing --package")?,
        signature: signature.ok_or("missing --signature")?,
        strategy: strategy.ok_or("missing --strategy")?,
        install_dir,
        appimage,
        app_bundle,
        wait_pid,
        launch,
    })
}

fn main() {
    let code = run();
    if code != 0 {
        eprintln!("qomicex-updater failed with exit code {code}");
    }
    std::process::exit(code);
}

fn run() -> i32 {
    let args = match parse_args() {
        Ok(a) => {
            // Log file sits next to the signature (same temp dir the Tauri
            // side writes the sig into); pid disambiguates concurrent runs.
            let sig_parent = a
                .signature
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(std::env::temp_dir);
            let _ = LOG_PATH.set(
                sig_parent.join(format!("qomicex-updater-{}.log", std::process::id())),
            );
            ulog(&format!(
                "start pid={} package={} strategy={}",
                std::process::id(),
                a.package.display(),
                a.strategy
            ));
            a
        }
        Err(e) => {
            eprintln!("{e}\n\nusage: qomicex-updater --package <zip> --signature <file> --strategy <dir|appimage|app|system> [--install-dir <path>] [--appimage <path>] [--app-bundle <path>] [--wait-pid <pid>] [--launch <exe>]");
            return 1;
        }
    };

    if let Err(e) = verify::verify_package(&args.package, &args.signature, PUBLIC_KEY) {
        ulog(&format!("verify failed: {e}"));
        return 3;
    }
    ulog("verify ok");

    if let Some(pid) = args.wait_pid {
        // The launcher's teardown (backend kill, window close, async guards)
        // has been observed taking >30s; the wait must cover it. Failure to
        // observe an exit means the target is wedged — overwrite anyway
        // (files may be locked; rename errors will surface in install) is
        // worse than waiting, so keep retrying for 3 minutes.
        ulog(&format!("waiting for pid {pid} (max 180s)"));
        if let Err(e) = install::wait_process_exit(pid, std::time::Duration::from_secs(180)) {
            ulog(&format!("wait failed: {e}"));
            return 5;
        }
        ulog("target exited");
    }

    let result = match args.strategy.as_str() {
        "dir" => install::install_dir(&args.package, args.install_dir.as_deref()),
        "appimage" => install::install_appimage(&args.package, args.appimage.as_deref()),
        "app" => install::install_app(&args.package, args.app_bundle.as_deref()),
        "system" => install::install_system(&args.package),
        other => Err(format!("unknown strategy: {other}")),
    };
    if let Err(e) = result {
        ulog(&format!("install failed: {e}"));
        return if args.strategy == "system" || args.strategy == "app" {
            4
        } else {
            2
        };
    }
    ulog("install ok");

    if let Some(exe) = &args.launch {
        // Strip dev-harness env before relaunching: QOMICEX_LAUNCHER_MANAGED=1
        // inherited from a debug launcher would stop the new (release) shell
        // from spawning its embedded backend, and QOMICEX_UPDATER_PATH would
        // override its embedded updater.
        std::env::remove_var("QOMICEX_LAUNCHER_MANAGED");
        std::env::remove_var("QOMICEX_UPDATER_PATH");
        ulog(&format!("launching {}", exe.display()));
        if let Err(e) = install::launch(exe) {
            ulog(&format!("relaunch failed: {e}"));
            return 2;
        }
    }
    ulog("done");
    0
}
