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
//! 5 timed out waiting for the launcher to exit, 6 elevation denied
//! (用户取消授权弹窗 / 既没有可用的 pkexec 也没有免密 sudo)。
//!
//! 失败一律在 `{更新包目录}/last-update-error.json` 落一份交接
//! （见 [`write_update_error`]）：updater 是 detached 进程，不落盘的话用户只会
//! 看到「启动器自己消失了」——issue #201 就是这么被拖成一轮取证的。

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

mod install;
mod verify;

static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Append-only file log next to the signature file: the updater runs
/// detached with no console, so this is the only observable trace.
pub fn ulog(msg: &str) {
    use std::io::Write as _;
    if let Some(p) = LOG_PATH.get() {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
        {
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
    pub log: Option<PathBuf>,
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
    let mut log = None;

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
            "--log" => log = Some(PathBuf::from(val("log")?)),
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
        log,
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
            // Log path: explicit --log (launcher-side derived, preferred) or
            // fallback next to the signature. pid disambiguates concurrent runs.
            let log_path = a.log.clone().unwrap_or_else(|| {
                let sig_parent = a
                    .signature
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(std::env::temp_dir);
                sig_parent.join(format!("qomicex-updater-{}.log", std::process::id()))
            });
            let _ = LOG_PATH.set(log_path);
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

    // 覆盖前的等待：Windows 等镜像锁释放（锁定即强杀，保留「更新必然推进」语义），
    // unix 等 launcher 进程退出——写探测在 unix 上判不了占用，root 所有的系统包
    // 目标会让探测永远失败（issue #201：deb/rpm 用户点更新后既不装也不重启）。
    if let Err(e) = install::wait_for_target(args.launch.as_deref(), args.wait_pid) {
        ulog(&format!("wait failed: {e}"));
        // 这条**不** relaunch：launcher 很可能仍卡在前台，再起一个只会多一个窗口。
        write_update_error(&args, "UPDATE_WAIT_TIMEOUT", &e);
        return 5;
    }
    ulog("target released");

    let result: Result<(), install::InstallFailure> = match args.strategy.as_str() {
        "dir" => {
            install::install_dir(&args.package, args.install_dir.as_deref()).map_err(Into::into)
        }
        "appimage" => {
            install::install_appimage(&args.package, args.appimage.as_deref()).map_err(Into::into)
        }
        "app" => {
            install::install_app(&args.package, args.app_bundle.as_deref()).map_err(Into::into)
        }
        "system" => install::install_system(&args.package, args.launch.as_deref()),
        other => Err(install::InstallFailure::from(format!(
            "unknown strategy: {other}"
        ))),
    };
    if let Err(f) = result {
        ulog(&format!("install failed: {f}"));
        write_update_error(
            &args,
            if f.denied {
                "ELEVATION_DENIED"
            } else {
                "UPDATE_INSTALL_FAILED"
            },
            &f.message,
        );
        // 失败也要把用户带回启动器。旧行为是「启动器退了、updater 静死、屏幕上
        // 什么都没发生」，用户只能自己重新打开应用——这正是 #201 的用户视角。
        relaunch(&args);
        return if f.denied {
            6
        } else if args.strategy == "system" || args.strategy == "app" {
            4
        } else {
            2
        };
    }
    ulog("install ok");

    relaunch(&args);
    ulog("done");
    0
}

/// 拉起启动器：成功与失败收尾共用（失败时让用户回到应用里，而不是留在桌面上）。
fn relaunch(args: &Args) {
    let Some(exe) = &args.launch else { return };
    // Strip dev-harness env before relaunching: QOMICEX_LAUNCHER_MANAGED=1
    // inherited from a debug launcher would stop the new (release) shell
    // from spawning its embedded backend, and QOMICEX_UPDATER_PATH would
    // override its embedded updater.
    std::env::remove_var("QOMICEX_LAUNCHER_MANAGED");
    std::env::remove_var("QOMICEX_UPDATER_PATH");
    ulog(&format!("launching {}", exe.display()));
    if let Err(e) = install::launch(exe) {
        // 装成功了却没起来：仍是「更新完成」，版本已前进，重开应用即可。
        // 不再因此把退出码改成 2（历史上没人观测这个码，只有日志有用）。
        ulog(&format!("relaunch failed: {e}"));
    }
}

/// 失败交接文件名（与更新包同目录，即 `{dataDir}/updates/`）。
/// 壳侧读取端在 `src-tauri/src/updater.rs`（`take_update_error`），文件名必须一致。
const ERROR_FILE: &str = "last-update-error.json";

/// 落一份失败交接。
///
/// 为什么值得单独落：updater 是 detached 进程，它退出时旧启动器早已 exit，
/// 屏幕上不会留下任何痕迹（#201 用户只能看到「应用自己消失了」）。新进程启动后
/// 由壳侧一次性消费并提示原因与手动升级命令。
///
/// 手写 JSON 而不是引 serde：这个 crate 的依赖面就是它的提权攻击面。字段值全部
/// 经 [`json_escape`]；「先写 .tmp 再 rename」原子覆盖，读到半个文件只会当成无交接。
/// 写失败只进日志——提示丢了不能改变本次更新的退出码。
fn write_update_error(args: &Args, code: &str, message: &str) {
    let Some(dir) = args.package.parent() else {
        ulog("error handoff skipped: package has no parent dir");
        return;
    };
    if let Err(e) = std::fs::create_dir_all(dir) {
        ulog(&format!("error handoff dir failed: {e}"));
        return;
    }
    let body = format!(
        r#"{{"code":"{}","message":"{}","strategy":"{}","version":"{}","occurredAt":{}}}"#,
        json_escape(code),
        json_escape(message),
        json_escape(&args.strategy),
        json_escape(&version_from_package(&args.package)),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );
    let tmp = dir.join(format!("{ERROR_FILE}.tmp"));
    let path = dir.join(ERROR_FILE);
    if let Err(e) = std::fs::write(&tmp, &body) {
        ulog(&format!("error handoff write failed: {e}"));
        return;
    }
    if std::fs::rename(&tmp, &path).is_err() {
        // rename 覆盖在 Windows/Unix 上都可行；失败时先删旧的一份再试一次。
        let _ = std::fs::remove_file(&path);
        if let Err(e) = std::fs::rename(&tmp, &path) {
            ulog(&format!("error handoff replace failed: {e}"));
        }
    } else {
        // rename 成功即落位，补一行日志便于取证。
        ulog(&format!("error handoff written: {}", path.display()));
    }
}

/// 从包文件名反推目标版本（`qomicex-update-<version>.zip`）。
/// 不符合约定就返回空串——前端只当附加展示信息，不作为任何判据。
fn version_from_package(package: &Path) -> String {
    package
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .and_then(|name| {
            name.strip_prefix("qomicex-update-")
                .and_then(|v| v.strip_suffix(".zip"))
                .map(str::to_string)
        })
        .unwrap_or_default()
}

/// JSON 字符串转义（`"`、`\`、控制符）。
///
/// message 里带的是 OS 报错原文，出现引号/反斜杠/换行都属正常——不转义会产出
/// 坏 JSON，前端读不到就等于静默丢掉提示。
fn json_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 8);
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("qomicex-updater-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn json_escape_escapes_exactly_the_json_dangerous_chars() {
        // message 里带的是 OS 报错原文：引号 / 反斜杠 / 换行都会让未转义的 JSON
        // 解析失败，前端读不到 = 静默丢掉「更新失败」提示（#201 要的正是可见性）。
        assert_eq!(json_escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(json_escape(r"a\b"), r"a\\b");
        assert_eq!(json_escape("l1\nl2\ttab\r"), r"l1\nl2\ttab\r");
        assert_eq!(json_escape("\u{1}"), r"\u0001");
        // 非 ASCII 原样保留（JSON 允许 UTF-8 字面量），中文报错才不会变成乱码
        assert_eq!(json_escape("权限不足 /usr/bin"), "权限不足 /usr/bin");
    }

    #[test]
    fn version_from_package_reads_the_downloaded_file_name() {
        assert_eq!(
            version_from_package(Path::new("/data/updates/qomicex-update-0.1.2-beta1.0.zip")),
            "0.1.2-beta1.0"
        );
        // 不符合约定 → 空串：前端只把它当附加展示信息，不作为任何判据
        assert_eq!(version_from_package(Path::new("/tmp/random.zip")), "");
    }

    #[test]
    fn error_handoff_file_is_well_formed_single_line_json() {
        let dir = scratch("err-handoff");
        let args = Args {
            package: dir.join("qomicex-update-0.1.2-beta1.0.zip"),
            signature: dir.join("qomicex-update-0.1.2-beta1.0.sig"),
            strategy: "system".into(),
            install_dir: None,
            appimage: None,
            app_bundle: None,
            wait_pid: None,
            launch: Some(PathBuf::from("/usr/bin/Qomicex Launcher")),
            log: None,
        };
        write_update_error(
            &args,
            "ELEVATION_DENIED",
            "pkexec 退出 127：\"x\" \\ y\nsecond line",
        );

        let raw = std::fs::read_to_string(dir.join(ERROR_FILE)).expect("交接文件应已落位");
        assert_eq!(
            raw.lines().count(),
            1,
            "换行必须转义，否则 JSON 断裂：{raw}"
        );
        assert!(raw.contains(r#"{"code":"ELEVATION_DENIED""#), "{raw}");
        assert!(raw.contains(r#""version":"0.1.2-beta1.0""#), "{raw}");
        assert!(raw.contains(r#""strategy":"system""#), "{raw}");
        assert!(raw.contains("\\\"x\\\""), "message 里的引号要转义：{raw}");
        assert!(raw.contains("\\\\ y"), "message 里的反斜杠要转义：{raw}");
        assert!(
            raw.contains(r"\nsecond line"),
            "message 里的换行要转义：{raw}"
        );
        // .tmp 必须被 rename 消耗掉，不在 updates 目录留残渣
        assert!(!dir.join(format!("{ERROR_FILE}.tmp")).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn error_handoff_survives_a_pre_existing_file() {
        // 连续两次失败：新交接必须原子覆盖旧的（与 pending-update-notice 同语义），
        // 否则用户看到的永远是第一次的错。
        let dir = scratch("err-handoff-replace");
        let mut args = Args {
            package: dir.join("qomicex-update-0.2.0.zip"),
            signature: dir.join("sig"),
            strategy: "system".into(),
            install_dir: None,
            appimage: None,
            app_bundle: None,
            wait_pid: None,
            launch: None,
            log: None,
        };
        write_update_error(&args, "UPDATE_INSTALL_FAILED", "first");
        args.package = dir.join("qomicex-update-0.3.0.zip");
        write_update_error(&args, "ELEVATION_DENIED", "second");

        let raw = std::fs::read_to_string(dir.join(ERROR_FILE)).unwrap();
        assert!(raw.contains("ELEVATION_DENIED"), "应被新交接覆盖：{raw}");
        assert!(raw.contains("\"second\""), "应被新交接覆盖：{raw}");
        assert!(!raw.contains("first"), "旧内容不该残留：{raw}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
