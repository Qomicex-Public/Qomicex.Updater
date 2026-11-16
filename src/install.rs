// Copyright (C) 2026 Qomicex Launcher Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Install strategies: unzip the package into a staging directory next to the
//! target, then move files into place. Elevation (osascript / pkexec / sudo) is
//! only used when the target is not writable by the current user.

use crate::ulog;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- waiting
//
// 「现在能不能覆盖启动器 exe」在两个平台上的答案不同，用错判据会直接毁掉
// 一种安装形态：
//
// - Windows：运行中的 image 持有独占锁，写探测就是精确的「在用」信号（进程
//   退出即释放），也没有 `tasklist` 本地化陷阱（中文系统输出「信息:」不含
//   INFO:，曾让旧的 pid 探测永久挂起，见 be5e1ef）。
// - Unix：运行中的 image **不**锁文件。写探测失败通常只代表「当前用户无权写」
//   ——deb/rpm 形态正是这样（`/usr/bin/Qomicex Launcher`，root 所有 0755）。
//   把 EACCES 当「锁定」后，每次系统包更新都空转满超时再放弃（exit 5），
//   deb/rpm 用户因此永久无法自更新（issue #201）。所以 unix 等的是 **pid 退出**，
//   真正的写入由提权路径以 root 完成。

/// 写探测的分类结果，见本节开头。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetState {
    /// 可以覆盖。
    Free,
    /// 被正在运行的进程占用（Windows 镜像锁 / unix ETXTBSY）。
    Busy,
    /// 只是**没权限**写，说明不了是否在用——unix 的系统安装形态走这里，
    /// 调用方必须回退到 pid 等待。
    Unknown,
}

/// 单次探测：能不能以写方式打开。（Windows：进程运行期间 image 被独占锁住，
/// 退出即释放。Unix：EACCES ≠ 锁定，见上方说明，用 [`probe_target`]。）
pub fn probe_unlockable(path: &Path) -> bool {
    std::fs::OpenOptions::new().write(true).open(path).is_ok()
}

/// Windows：可写 = Free，不可写 = Busy（镜像锁语义与 be5e1ef 起完全一致）。
#[cfg(windows)]
pub fn probe_target(path: &Path) -> TargetState {
    if probe_unlockable(path) {
        TargetState::Free
    } else {
        TargetState::Busy
    }
}

/// Unix：只有 ETXTBSY 才是「在用」；EACCES/EPERM 是「需要提权」；其它错误
/// （含 ENOENT——包管理器已把本体移除、或首次安装）都不该拦住更新，
/// `install_*` 真正写入时自会报错。
#[cfg(unix)]
pub fn probe_target(path: &Path) -> TargetState {
    // Linux 与 macOS/BSD 的 ETXTBSY 都是 26。
    const ETXTBSY: i32 = 26;
    match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(_) => TargetState::Free,
        Err(e) if e.raw_os_error() == Some(ETXTBSY) => TargetState::Busy,
        // std 把 EACCES 与 EPERM 都归入 PermissionDenied。
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => TargetState::Unknown,
        Err(_) => TargetState::Free,
    }
}

/// Wait until the launcher exe is no longer locked (process exit releases
/// the image lock). This is the real precondition for overwriting it, and
/// unlike `tasklist`-style pid probing it has no localization issues
/// (Chinese tasklist prints 「信息:」 not "INFO:", which broke the old check
/// and made wait_* hang forever).
pub fn wait_file_unlockable(path: &Path, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    loop {
        if probe_unlockable(path) {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(format!(
                "file {} still locked after {timeout:?}",
                path.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Force-kill the launcher process (image lock holder). Windows: `taskkill
/// /F` on the single pid — deliberately **without /T**: the tree walk
/// recurses into the shared WebView2 process pool and kills the updater
/// itself (observed). Webview children don't lock the launcher exe.
/// Unix: SIGKILL the process group (launcher was started with
/// process_group(0)).
pub fn kill_pid_tree(pid: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let status = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW（不闪控制台）
            .status()
            .map_err(|e| format!("cannot run taskkill: {e}"))?;
        if !status.success() {
            return Err(format!("taskkill exit {}", status.code().unwrap_or(-1)));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let status = Command::new("kill")
            .args(["-9", &format!("-{pid}")])
            .status()
            .map_err(|e| format!("cannot kill pgid: {e}"))?;
        if !status.success() {
            return Err(format!("kill exit {}", status.code().unwrap_or(-1)));
        }
        Ok(())
    }
}

/// Legacy pid-based wait. Broken on non-English Windows (tasklist's
/// "no tasks" line is localized) — kept only for callers without a file
/// to probe; prefer [wait_file_unlockable].
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
    // pid_t 是有符号 32 位。超范围的数字会被 kill 解析成**负数**，而负 pid 在
    // POSIX 里表示「整个进程组」——实测 `/usr/bin/kill -0 4294967295` 返回 0，
    // 于是 process_alive 恒真、等待烧满整个超时。0 同样不是合法 pid。
    // 这类输入直接判「不存活」放行（新增的回归用例就是冲它来的）。
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    // kill -0 = 纯存在性探测（不发信号）。工具本身失败时保守判「已死」(false)，
    // 让调用方的兜底等待能继续，而不是永久空转。
    //
    // 僵尸进程例外：它还在进程表里（kill -0 恒成功）但已不再持有任何资源。
    // launcher 退出后若父进程没来得及 reap，等待会白烧到超时——对更新而言
    // 等同已退出，必须放行。
    if is_zombie(pid) {
        return false;
    }
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Linux：`/proc/<pid>/stat` 的第 3 个字段是进程状态。读不到一律按非僵尸处理
/// （进程不存在时 `kill -0` 会给出正确答案）。
#[cfg(target_os = "linux")]
fn is_zombie(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map(|raw| zombie_from_stat(&raw))
        .unwrap_or(false)
}

/// 从 `/proc/<pid>/stat` 原文判僵尸。
///
/// `comm` 字段可以含空格甚至括号（例：`123 (weird (name)) Z 1 ...`），所以按
/// **最后一个** `)` 切分、再取其后首个非空白字符，而不是按空格切第 3 列。
/// 结构异常一律返回 false——宁可多等一会，也不要把还活着的 launcher 当已退出。
#[cfg(target_os = "linux")]
fn zombie_from_stat(raw: &str) -> bool {
    match raw.rfind(')') {
        Some(i) => raw[i + 1..].trim_start().starts_with('Z'),
        None => false,
    }
}

/// macOS 没有 procfs；且 DMG 形态的可执行文件属用户，走不到这条等待路径，
/// 保持 `kill -0` 原语义即可。
#[cfg(all(unix, not(target_os = "linux")))]
fn is_zombie(_pid: u32) -> bool {
    false
}

/// 等 launcher 退出的上限：实测拆卸（内嵌 backend 收尾、窗口关闭、异步守卫）
/// 可超 30s（见 updater e0b8901），这条必须给到 180s。
const EXIT_WAIT: Duration = Duration::from_secs(180);

/// Windows 镜像锁等待上限：进程退出即解锁，30s 足够；超时说明 launcher 真卡死。
const WINDOWS_LOCK_WAIT: Duration = Duration::from_secs(30);

/// 覆盖前的等待：各平台等**各自**真正表示「可以动手了」的信号。
///
/// 为什么不能让 unix 也等「写探测通过」：系统包形态（deb/rpm）的目标文件是
/// root 所有的 0755，非 root 用户永远写不动它，探测永远不通过——于是每次
/// 系统包更新都空转满超时再中止（issue #201）。
pub fn wait_for_target(launch: Option<&Path>, wait_pid: Option<u32>) -> Result<(), String> {
    // ── Windows：镜像锁是精确的「在用」信号。探测它，锁着就强杀 launcher
    //    本体（保留 be5e1ef 的「更新必然推进」语义），再等锁释放。
    if cfg!(windows) {
        return match launch {
            Some(exe) if !probe_unlockable(exe) => {
                ulog(&format!("target locked: {}", exe.display()));
                if let Some(pid) = wait_pid {
                    ulog(&format!("killing launcher pid {pid} tree"));
                    if let Err(e) = kill_pid_tree(pid) {
                        ulog(&format!("kill failed (continuing with wait): {e}"));
                    }
                }
                wait_file_unlockable(exe, WINDOWS_LOCK_WAIT)
            }
            Some(_) => {
                ulog("target already unlocked");
                Ok(())
            }
            None => wait_pid_exit(wait_pid),
        };
    }

    // ── Unix：写探测判不了占用，主判据回到「进程退出」。探测结果只进日志，
    //    用于区分 ETXTBSY（真占用）与 Unknown（没权限，正常现象）。
    if let Some(exe) = launch {
        ulog(&format!(
            "target {} probe: {:?}",
            exe.display(),
            probe_target(exe)
        ));
    }
    wait_pid_exit(wait_pid)
}

/// 只等 pid 的分支：unix 的主路径，也是 Windows 上拿不到 `--launch` 时的兜底。
fn wait_pid_exit(wait_pid: Option<u32>) -> Result<(), String> {
    match wait_pid {
        Some(pid) => {
            ulog(&format!("waiting for pid {pid} (max {EXIT_WAIT:?})"));
            wait_process_exit(pid, EXIT_WAIT)
        }
        // 没有 --wait-pid：运行中的 image 不锁文件，直接放行——安装（提权 rename）
        // 本就合法。再等「能不能写」就是 #201 那个死循环。
        None => {
            ulog("no --wait-pid: proceeding (a running image does not lock its file on unix)");
            Ok(())
        }
    }
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
            if let Err(e) = std::fs::rename(entry.path(), &target) {
                crate::ulog(&format!(
                    "rename {} -> {} failed: {e}",
                    entry.path().display(),
                    target.display()
                ));
                return Err(e);
            }
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

pub fn install_app(package: &Path, app_bundle: Option<&Path>) -> Result<(), InstallFailure> {
    let bundle = app_bundle
        .ok_or_else(|| {
            InstallFailure::from("--app-bundle is required for the app strategy".to_string())
        })?
        .to_path_buf();
    if !bundle.is_dir() {
        return Err(InstallFailure::from(format!(
            "app bundle {} not found",
            bundle.display()
        )));
    }
    if dir_writable(&bundle) {
        return install_dir(package, Some(&bundle)).map_err(Into::into);
    }
    // /Applications is admin-owned: stage privately, then elevate the copy.
    let work = PrivateDir::create("app")?;
    extract_zip(package, work.path()).map_err(|e| InstallFailure::from(e.to_string()))?;
    // 取消语义必须原样传到 main.rs（exit 6 / ELEVATION_DENIED）：这里曾经
    // 把 InstallFailure 压成 String，`denied` 一过手就丢了，用户取消被报成
    // 「安装失败」(#204)。staging 由 PrivateDir 的 Drop 收拾，失败与取消都不例外。
    elevate_copy(work.path(), &bundle, true)
}

/// 唯一、私有（0700）的一次性工作目录，Drop 时整棵删除。
///
/// 为什么不再用 `temp_dir().join("qomicex-update-app-<pid>")`：那个名字可预测。
/// macOS 的提权脚本要落到这里再交给 `osascript`，root 会用「脚本自身」的身份去
/// 执行它；预测得到路径就等于给了本地其它用户一个**预先放好同名文件/软链**
/// 的机会（脚本被替换 → 以 root 执行）。所以名字里带纳秒时钟做熵，
/// 且建目录失败（已存在）时只换名、绝不删别人的东西。
struct PrivateDir {
    path: PathBuf,
}

impl PrivateDir {
    fn create(tag: &str) -> Result<Self, InstallFailure> {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let base = std::env::temp_dir();
        for _ in 0..64 {
            // 时钟纳秒 + 序号：单机并发与跨进程都不至于撞名；真正的保证仍是
            // 「建不成就不复用」，熵只是让预置变得不现实。
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let name = format!(
                "qomicex-update-{tag}-{}-{nanos:x}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            );
            let path = base.join(name);
            match create_private_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                // 已存在（别的进程、或有人预先占位）→ 换名重试。
                // 这里**不能**删除：那个路径不属于我们，删掉是别人目录的破坏面。
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(InstallFailure::from(format!(
                        "cannot create {}: {e}",
                        path.display()
                    )))
                }
            }
        }
        Err(InstallFailure::from(
            "cannot create a private working directory in the temp dir".to_string(),
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// `mkdir` 语义上的排他建目录 + 0700。
///
/// 拆出来只为看清两件事：目录一定是**本次新建**的（AlreadyExists 交给调用方换名），
/// 权限一定是 0700（`temp_dir` 默认是 1777，不提权时别人也能读）。
fn create_private_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir(path)?;
    set_dir_mode_private(path)
}

#[cfg(unix)]
fn set_dir_mode_private(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn set_dir_mode_private(_path: &Path) -> io::Result<()> {
    // Windows 没有 DAC 权限位概念，也不走提权覆盖路径。
    Ok(())
}

// ---------------------------------------------------------------- system strategy (deb/rpm)

/// deb/rpm 形态：包内是相对 `/` 的文件布局（`usr/bin/…`），整棵树覆盖到 `/`。
///
/// **分级**：目标目录当前用户可写就本地覆盖（用户自行 chown、容器内、非常规
/// 安装形态），不可写才提权——避免在无 polkit agent 的机器上白弹一次窗。
/// 本地路径中途失败（混合属主）自动回退提权，重放同一份计划（`Place` 用 copy
/// 而非 move，`from` 仍在 staging，因此幂等）。
pub fn install_system(package: &Path, launch: Option<&Path>) -> Result<(), InstallFailure> {
    // 系统包的安装根永远是 `/`：包内布局就是 dpkg-deb -x 出来的相对路径。
    install_system_to(package, Path::new("/"), launch)
}

/// [`install_system`] 的实现体，`dst` 可注入。
///
/// 抽出来的唯一理由：让「解压 → 生成计划 → 本地覆盖」这条主链路能在临时目录里
/// 被完整跑一遍（不需要 root，也不碰真实系统目录）。生产调用固定 `dst = "/"`。
pub fn install_system_to(
    package: &Path,
    dst: &Path,
    launch: Option<&Path>,
) -> Result<(), InstallFailure> {
    let staging =
        std::env::temp_dir().join(format!("qomicex-update-system-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)
        .map_err(|e| InstallFailure::from(format!("cannot create {}: {e}", staging.display())))?;
    extract_zip(package, &staging).map_err(|e| InstallFailure::from(e.to_string()))?;

    // 判据是「装得到装不到」，不是「能不能写 launcher 本体」——后者正是 #201 里
    // 被误当成文件锁定的那个探测。取 launch 的父目录（deb/rpm = /usr/bin），
    // 没有 launch 参数时退回 /usr/bin。
    let probe_dir = launch
        .map(|l| l.parent().unwrap_or(l))
        .unwrap_or_else(|| Path::new("/usr/bin"));
    let ops = plan_overlay(&staging, dst).map_err(|e| InstallFailure::from(e.to_string()))?;
    ulog(&format!(
        "system overlay: {} ops onto {} (probe dir {})",
        ops.len(),
        dst.display(),
        probe_dir.display()
    ));

    if dir_writable(probe_dir) {
        match run_overlay(&ops) {
            Ok(()) => {
                let _ = std::fs::remove_dir_all(&staging);
                return Ok(());
            }
            Err(e) => ulog(&format!(
                "本地覆盖未完成: {e} —— 回退提权（计划幂等，重放安全）"
            )),
        }
    }

    let failure = elevate_overlay(&ops, &staging, dst, false);
    if failure.is_err() {
        // 提权脚本 set -e 中途失败时 staging 可能还在，且属主是自己 → 删得掉。
        let _ = std::fs::remove_dir_all(&staging);
    }
    failure
}

// ---------------------------------------------------------------- overlay ops
//
// 「把 staging 覆盖到 dst」只有一份计划：本地执行与提权脚本都从 plan_overlay
// 渲染出来。分叉成两套（旧的 cp -a 脚本 vs move_tree）正是提权路径写不出
// 正确结果、也看不出错在哪的原因之一（issue #201 取证困难）。

/// 一次覆盖动作的最小描述。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    MakeDir(PathBuf),
    /// `from`（staging 内文件）落到 `to`；`mode` 是 unix 权限位（Windows 恒 0）。
    Place {
        from: PathBuf,
        to: PathBuf,
        mode: u32,
    },
}

/// 落位时写在**目标同目录**的临时名后缀（点前缀：崩溃残留也不污染目录列表）。
const PLACE_TMP_SUFFIX: &str = "qomicex-update-tmp";

/// 覆盖/提权失败。
///
/// `denied = true` 表示用户或系统拒绝提权授权——它必须与 IO 失败可区分：
/// 前者要引导用户改用包管理器手动升级（`sudo dpkg -i`），后者是链路自身的缺陷。
/// `main.rs` 据此映射退出码 6 / 4。
#[derive(Debug)]
pub struct InstallFailure {
    pub denied: bool,
    pub message: String,
}

impl From<String> for InstallFailure {
    fn from(message: String) -> Self {
        Self {
            denied: false,
            message,
        }
    }
}

impl std::fmt::Display for InstallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// 遍历 `staging` 生成「覆盖到 `dst`」的动作序列（先目录、再其内文件）。
pub fn plan_overlay(staging: &Path, dst: &Path) -> io::Result<Vec<Op>> {
    let mut ops = Vec::new();
    collect_ops(staging, dst, &mut ops)?;
    Ok(ops)
}

fn collect_ops(dir: &Path, dst: &Path, ops: &mut Vec<Op>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            ops.push(Op::MakeDir(target.clone()));
            collect_ops(&entry.path(), &target, ops)?;
        } else {
            ops.push(Op::Place {
                from: entry.path(),
                mode: file_mode(&entry.path())?,
                to: target,
            });
        }
    }
    Ok(())
}

/// 以当前用户身份执行覆盖计划。
pub fn run_overlay(ops: &[Op]) -> io::Result<()> {
    for op in ops {
        match op {
            Op::MakeDir(dir) => std::fs::create_dir_all(dir)?,
            Op::Place { from, to, mode } => place_file(from, to, *mode)?,
        }
    }
    Ok(())
}

/// 单个文件落位：copy 到目标同目录的临时名 → 设权限 → rename 覆盖。
///
/// 为什么不直接写目标本体：
/// - `open(O_WRONLY|O_TRUNC)` 打在**正在执行**的 image 上会 ETXTBSY（launcher
///   卡死没退时的真实场景）；`rename` 覆盖是 inode swap——unix 合法，Windows
///   也支持替换已存在文件。
/// - staging 常在 `/tmp`（与 `/` 常常跨卷），先 copy 到目标同目录再 rename，
///   不会出现 EXDEV；同卷 rename 本身原子。
/// - 用 copy 而不是 move：`from` 留在 staging，本地装到一半失败回退提权时，
///   同一份计划可以幂等重放。
fn place_file(from: &Path, to: &Path, mode: u32) -> io::Result<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = place_tmp(to);
    let result = (|| -> io::Result<()> {
        std::fs::copy(from, &tmp)?;
        set_mode(&tmp, mode)?;
        std::fs::rename(&tmp, to)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn place_tmp(to: &Path) -> PathBuf {
    let name = to
        .file_name()
        .map(|n| format!(".{n}.{PLACE_TMP_SUFFIX}", n = n.to_string_lossy()))
        .unwrap_or_else(|| format!(".{PLACE_TMP_SUFFIX}"));
    to.parent().unwrap_or(to).join(name)
}

#[cfg(unix)]
fn file_mode(path: &Path) -> io::Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(std::fs::metadata(path)?.permissions().mode() & 0o7777)
}

#[cfg(windows)]
fn file_mode(_path: &Path) -> io::Result<u32> {
    // Windows 没有 DAC 权限位概念，也不走提权覆盖路径。
    Ok(0)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if mode == 0 {
        return Ok(());
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(windows)]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

/// POSIX 单引号转义：`'` → `'\''`。
///
/// **所有**进脚本的路径都必须过这里：`--launch`、dataDir、包文件名可以带空格，
/// 理论上也能带引号——不能破坏脚本，更不能留命令注入面（提权脚本以 root 跑）。
pub fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

/// 渲染提权脚本：一条动作一行显式命令，不用 `find`、循环、变量展开或通配
/// （除既有的 `*.qdtmp` 清理），整份脚本可以静态审阅。`staging` 由脚本最后删除。
///
/// 这个脚本是**以 root 身份**执行的，所以落位动作按「不跟随预置临时文件」写：
///
/// - `mkdir -p --`：前缀里的 `-` 不能变成选项；目标目录已存在时它必须是 no-op
///   （`/Applications` 被误报成不可写时也能自愈，而不是整个更新死在第一条命令）。
/// - `rm -f -- tmp` 后 `cp`：绝不写进一个已存在的同名对象。临时名可预测，预置
///   软链就能让 root 把包内容写到任意路径上；先删再建等于只肯用自己新建的文件。
/// - `trap` 只清本次渲染出来的那些临时名：中途失败不留半截 `.tmp`，也不用宽泛
///   通配去删目标目录里的东西。
pub fn render_overlay_script(ops: &[Op], staging: &Path, dst: &Path, cleanup_dst: bool) -> String {
    // 本次可能出现的落位临时名：trap 只允许碰它们。
    let mut tmps: Vec<PathBuf> = ops
        .iter()
        .filter_map(|op| match op {
            Op::Place { to, .. } => Some(place_tmp(to)),
            Op::MakeDir(_) => None,
        })
        .collect();
    tmps.dedup();

    let mut body = String::from("#!/bin/sh\nset -e\n");
    if !tmps.is_empty() {
        // 只有本次渲染出来的临时名允许被清掉。
        let mut rm = String::from("rm -f --");
        for tmp in &tmps {
            rm.push(' ');
            rm.push_str(&sh_quote(tmp));
        }
        // 失败/中断两条路径要分开写：
        // - EXIT trap 覆盖 `set -e` 下的提前退出，执行完脚本照常退出，不必自己 exit。
        // - 信号 trap 如果只清理不退出，sh 会在 handler 返回后**继续执行剩下的动作**
        //   ——半截覆盖会接着往下写，比不清理更糟。所以必须显式 exit。
        // `EXIT` 是 POSIX 方言里的 `0`，dash/bash/busybox sh 都认；用 `0` 反而与
        // 信号名混在一起不好读，这里保留 EXIT 并同时给 0，兼容只认数字的实现。
        body.push_str(&format!("{rm}\n"));
        body.push_str(&format!(
            "qmx_cleanup() {{ {rm}; }}\n\
             trap 'qmx_cleanup' EXIT\n\
             trap 'qmx_cleanup; exit 130' INT\n\
             trap 'qmx_cleanup; exit 143' TERM\n\
             trap 'qmx_cleanup; exit 129' HUP\n"
        ));
    }
    for op in ops {
        match op {
            Op::MakeDir(dir) => {
                body.push_str("mkdir -p -- ");
                body.push_str(&sh_quote(dir));
                body.push('\n');
            }
            Op::Place { from, to, mode } => {
                let tmp = place_tmp(to);
                body.push_str("rm -f -- ");
                body.push_str(&sh_quote(&tmp));
                body.push('\n');
                body.push_str("cp -f -- ");
                body.push_str(&sh_quote(from));
                body.push(' ');
                body.push_str(&sh_quote(&tmp));
                body.push('\n');
                if *mode != 0 {
                    body.push_str(&format!("chmod {:04o} ", mode));
                    body.push_str(&sh_quote(&tmp));
                    body.push('\n');
                }
                body.push_str("mv -f -- ");
                body.push_str(&sh_quote(&tmp));
                body.push(' ');
                body.push_str(&sh_quote(to));
                body.push('\n');
            }
        }
    }
    if cleanup_dst {
        // macOS .app：清掉下载器可能留下的半截 .qdtmp 临时包（既有行为）。
        body.push_str(&format!("rm -f -- {}/*.qdtmp\n", sh_quote(dst)));
    }
    body.push_str("rm -rf -- ");
    body.push_str(&sh_quote(staging));
    body.push('\n');
    body
}

/// 提权后端的一次尝试结果。
enum PrivAttempt {
    Done,
    /// 用户明确取消授权（关掉 polkit 弹窗 / macOS 点「取消」）——**不再**尝试
    /// 别的提权后端：这是选择而不是故障，绕开它等于无视用户的拒绝。
    Cancelled(String),
    /// 提权已经拿到，是覆盖脚本自己失败了。同样不能再试下一个后端：重放同一条
    /// 必然失败的计划，只会用 `sudo: a password is required` 之类的次生错误盖掉
    /// 真正的现场。映射为 `UPDATE_INSTALL_FAILED`（exit 4）。
    ExecFailed(String),
    /// 该后端不可用（缺二进制 / 无 polkit agent / 非交互 sudo 要密码）
    /// → 继续试下一个后端。
    Unavailable(String),
}

/// macOS 上图形授权弹窗的固定 AppleScript。
///
/// 为什么用 `on run argv` 而不是把路径拼进脚本源码：AppleScript 字符串转义与
/// Shell 引用是两个独立边界，拼源码就要同时转义两层（`\`、`"` 与 `'`），任何一层
/// 漏掉都会在提权上下文里变成命令注入。这里脚本源码是常量，路径只作为进程参数
/// 进来，再由 `quoted form of` 转成单层 shell 引用。
///
/// 为什么在脚本里区分错误号：`do shell script` 在 shell 非零退出时抛出**退出码
/// 同号**的 AppleScript 错误（TN2065），而用户点「取消」抛的是 -128。若直接把
/// 进程退出码当成判据，一个恰好退 42 的脚本会与「取消」混淆（-128 亦然）。
/// 因此这里把两种失败翻译成 stdout 上的机器标记。
///
/// 为什么把 `do shell script` 的结果赋给变量而不是直接返回：它会连安装脚本的
/// stdout 一起回吐，混进标记就会让「标记」失去唯一性（脚本打印一个同名串即可
/// 伪造成功）。赋给变量即丢弃，stdout 只剩标记本身。
const OSASCRIPT_ELEVATE: &str = "on run argv
	set scriptPath to item 1 of argv
	try
		set installOutput to do shell script \"/bin/sh \" & quoted form of scriptPath with administrator privileges
	on error errMsg number errNum
		if errNum is -128 then
			return \"QOMICEX_CANCELLED\"
		end if
		return \"QOMICEX_FAILED\"
	end try
	return \"QOMICEX_OK\"
end run";

/// 提权后端顺序。
///
/// 抽成「按 os 名取表」而不是直接用 `cfg!`：这条顺序是本 issue 的核心契约
/// （先弹授权、失败才退让），必须能在任意平台上被测死，而不是只有 mac 机器
/// 才跑得到一半。
fn backends_for(os: &str) -> &'static [&'static str] {
    // macOS 只能走图形授权：GUI 进程没有 tty，`sudo` 永远等不到密码；`pkexec`
    // 在 macOS 上根本不存在。`sudo -n` 仅作为 osascript **无法启动**时的兜底
    // （配了免密 sudoers 的机器），一旦 osascript 真的跑起来就不再退让——取消、
    // 授权失败、脚本失败都必须立刻停止，绕开用户的拒绝等于无视它。
    if os == "macos" {
        return &["osascript", "sudo"];
    }
    // Linux / 其它 unix：既有语义不变（#201 的修复就是在这条链上）。
    &["pkexec", "sudo"]
}

fn privilege_backends() -> &'static [&'static str] {
    backends_for(std::env::consts::OS)
}

/// `program` 以 root 身份跑 `sh <script>`。
///
/// 用 `output()` 而不是 `status()`：旧实现把 stderr 全丢了，只剩
/// 「elevated copy failed (pkexec exit 1)」这种既定位不了也没法转成
/// 可操作提示的日志（#201 取证的主要困难）。
fn run_privileged(program: &str, script: &Path) -> PrivAttempt {
    if program == "osascript" {
        return run_osascript(script);
    }
    let mut cmd = Command::new(program);
    // -n = 绝不弹密码提示：自更新是无人值守链路，卡在读 stdin 上会让
    // 启动器进程与 updater 一起挂死。
    if program == "sudo" {
        cmd.arg("-n");
    }
    let out = match cmd.arg("sh").arg(script).output() {
        Ok(o) => o,
        // 后端二进制不存在（没有 polkit 的系统、macOS）：算「不可用」，继续试
        // 下一个后端，而不是当成失败中止——#201 的定制发行版正可能落在这一支。
        Err(e) => return PrivAttempt::Unavailable(format!("{program} 无法执行（未安装？）: {e}")),
    };
    if out.status.success() {
        return PrivAttempt::Done;
    }
    let code = out.status.code();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let detail = format!(
        "{program} 退出 {note}{tail}",
        note = code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "信号终止".into()),
        tail = if stderr.is_empty() {
            String::new()
        } else {
            format!("：{stderr}")
        }
    );
    classify_priv_failure(program, code, &stderr, &detail)
}

/// macOS 图形授权：`osascript` 跑固定脚本，提权脚本路径经 argv 传入。
///
/// 退出码在这里**不**是判据（`do shell script` 抛出的 AppleScript 错误也不改
/// osascript 的退出码，成功/失败都可能是 0），唯一判据是 stdout 上的机器标记。
fn run_osascript(script: &Path) -> PrivAttempt {
    let out = match Command::new("osascript")
        .arg("-e")
        .arg(OSASCRIPT_ELEVATE)
        .arg(script)
        .output()
    {
        Ok(o) => o,
        // spawn 失败（osascript 不在预期位置 / 无图形会话）：判「不可用」，
        // 允许后续 sudo -n 兜底。这是唯一允许回退的情形——此时提权脚本
        // 一次都还没被执行过。
        Err(e) => return PrivAttempt::Unavailable(format!("osascript 无法执行: {e}")),
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let detail = format!(
        "osascript {}{}",
        match out.status.code() {
            Some(c) => format!("退出 {c}"),
            None => "被信号终止".into(),
        },
        if stderr.is_empty() {
            String::new()
        } else {
            format!("：{stderr}")
        }
    );
    classify_osascript(&stdout, &detail)
}

/// osascript 的标准输出 → 提权结论。
///
/// AppleScript 把 `do shell script` 的结果丢进局部变量后只返回标记，所以正常
/// 情况下 stdout 恰好是标记本身；仍按**整份输出**比对，任何多余内容（警告、
/// 其它程序写入）都按失败处理，绝不当成成功。
fn classify_osascript(stdout: &str, detail: &str) -> PrivAttempt {
    match stdout.trim() {
        "QOMICEX_OK" => PrivAttempt::Done,
        // -128 = 用户在授权弹窗上点了取消。这是**选择**而不是故障：不再试别的
        // 后端，直接映射为「提权未获授权」（exit 6 / ELEVATION_DENIED）。
        "QOMICEX_CANCELLED" => PrivAttempt::Cancelled(format!("{detail}（用户取消授权）")),
        // 授权已经通过，是安装脚本自己失败（shell 非零退出）——不能再退给
        // `sudo -n`：那条路必然报 "a password is required"，用一个无关的失败
        // 盖掉真正的现场（当时是哪个文件、哪个 mkdir 出的事），也白重放一次。
        "QOMICEX_FAILED" => {
            PrivAttempt::ExecFailed(format!("{detail}（已获授权，安装脚本执行失败）"))
        }
        // 标记以外的任何输出：协议没走通，同样不能当成功，也不该再提权重放。
        _ => PrivAttempt::ExecFailed(format!("{detail}（授权流程返回了无法识别的结果）")),
    }
}

/// 把退出码翻译成「用户拒绝授权」还是「该后端不可用」。
///
/// 单独抽出来是为了在没有 root、没有 polkit agent 的环境里把这条判定测死：
/// 它决定用户看到的是「你取消了授权，请手动升级」还是「这台机器提权不可用」，
/// 也是退出码 6 与 4 的唯一分岔点，并直接决定要不要继续往后端回退。
///
/// 只有「明确没得到授权」才允许算取消。pkexec 拿到授权后只剩一种结果：
/// 脚本以 uid 0 跑完（我们看到的成功）或脚本自己失败——而**后者**在这个函数
/// 眼里和后端不可用无从区分（都是非零退出），所以归 `Unavailable`：把它们分开
/// 需要 `pkexec` 的自定义错误码或 polkit 的 agent 事件，不在本 issue 范围。
fn classify_priv_failure(
    program: &str,
    code: Option<i32>,
    stderr: &str,
    detail: &str,
) -> PrivAttempt {
    // pkexec 约定：126 = 未获授权（无 agent / 策略拒绝）；127 通常是用户关掉弹窗。
    //
    // 但 127 **不只**表示取消：Debian 容器实测 polkitd 没在跑时 pkexec 同样退 127，
    // stderr 是「Error getting authority: Error initializing authority: Could not
    // connect」。那是后端不可用——若误判成"用户取消"就不再回退 sudo -n，于是配了
    // 免密 sudoers 的机器永久无法自更新，与 #201 同属「误读信号」这一类缺陷。
    if program == "pkexec" && code == Some(127) && !polkit_unreachable(stderr) {
        return PrivAttempt::Cancelled(detail.to_string());
    }
    PrivAttempt::Unavailable(detail.to_string())
}

/// polkit 自身起不来（守护进程缺失 / 连不上 / 非桌面会话）——绝不能算用户取消。
fn polkit_unreachable(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    [
        "error getting authority",
        "error initializing authority",
        "could not connect",
        "cannot connect",
        "no such file or directory",
        "not authorized to perform operation",
    ]
    .iter()
    .any(|needle| s.contains(needle))
}

/// 提权执行覆盖计划：按平台分级。
///
/// - macOS：`osascript`（管理员授权弹窗）→ `sudo -n`（仅 spawn 失败时兜底）
/// - Linux / 其它 unix：`pkexec`（polkit 弹窗）→ `sudo -n`（免密 sudoers）
///
/// 为什么要留 sudo -n：不是每台机器都跑 polkit agent（无桌面/minimal 安装/
/// 定制发行版），而配了免密 sudoers 的机器不该因此永久无法自更新。
/// 脚本全文进日志：它是这类故障唯一的现场证据。
fn elevate_overlay(
    ops: &[Op],
    staging: &Path,
    dst: &Path,
    cleanup_dst: bool,
) -> Result<(), InstallFailure> {
    // 脚本放在私有目录里并 0700：它会以 root 身份被 osascript/pkexec/sudo 执行，
    // 可预测的共享路径等于把「先放一个同名文件」的机会留给本地其它用户。
    let work = PrivateDir::create("elevate")?;
    let script_path = work.path().join("overlay.sh");
    let body = render_overlay_script(ops, staging, dst, cleanup_dst);
    write_private_script(&script_path, &body)?;

    let mut cancelled: Option<String> = None;
    let mut exec_failed: Option<String> = None;
    let mut unavailable: Vec<String> = Vec::new();
    for program in privilege_backends() {
        match run_privileged(program, &script_path) {
            PrivAttempt::Done => {
                return Ok(());
            }
            PrivAttempt::Cancelled(reason) => {
                ulog(&format!("{program} 授权被取消: {reason}"));
                cancelled = Some(reason);
                break;
            }
            PrivAttempt::ExecFailed(reason) => {
                ulog(&format!("{program} 已获授权但覆盖失败: {reason}"));
                exec_failed = Some(reason);
                break;
            }
            PrivAttempt::Unavailable(reason) => {
                ulog(&format!("提权后端 {program} 不可用: {reason}"));
                unavailable.push(reason);
            }
        }
    }
    let _ = std::fs::remove_file(&script_path);
    ulog(&format!(
        "elevate script ({} ops, target {})：\n{}",
        ops.len(),
        dst.display(),
        body
    ));
    Err(match (cancelled, exec_failed) {
        (Some(reason), _) => InstallFailure {
            denied: true,
            message: format!("提权未获授权（{reason}）。{}", manual_upgrade_hint()),
        },
        // 授权是给了的：换手动升级的建议没有意义，用户需要的是真正的现场。
        (None, Some(reason)) => InstallFailure {
            denied: false,
            message: format!("提权成功但覆盖未完成：{reason}"),
        },
        (None, None) => InstallFailure {
            denied: false,
            message: format!("提权失败：{}", unavailable.join("；")),
        },
    })
}

/// 把提权脚本写进私有目录：排他创建 + 0700。
///
/// 不用 `std::fs::write`：它会跟随已存在的同名对象（软链 → 写到别处，或写进别人
/// 预先建好的文件）。`create_new` 保证写的一定是自己新建的 inode；权限位在打开
/// 时给，不留「先可读、后 chmod」的窗口。
fn write_private_script(path: &Path, body: &str) -> Result<(), InstallFailure> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o700);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| InstallFailure::from(format!("cannot write elevate script: {e}")))?;
    file.write_all(body.as_bytes())
        .map_err(|e| InstallFailure::from(format!("cannot write elevate script: {e}")))?;
    Ok(())
}

/// 「用户自己重装一次」的手动出路。
///
/// 按平台分派：Debian/RPM 的建议在 macOS 上毫无意义，而这段文案会一路进
/// `last-update-error.json` 并弹在用户面前（#201 要的正是可操作的提示）。
fn manual_upgrade_hint() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "手动升级：重新下载 DMG 并把 Qomicex Launcher 拖入「应用程序」覆盖旧版本"
    }
    #[cfg(not(target_os = "macos"))]
    {
        "手动升级：sudo dpkg -i <deb> 或 sudo rpm -Uvh <rpm>"
    }
}

/// macOS .app 覆盖的提权入口（保留旧签名，install_app 不感知计划渲染）。
///
/// 返回 `InstallFailure` 而不是 `String`：`denied` 是 exit 6 与 exit 4 的唯一
/// 分岔点，压成字符串就等于把「用户取消」报成「安装失败」(#204)。
fn elevate_copy(src: &Path, dst: &Path, cleanup_dst: bool) -> Result<(), InstallFailure> {
    let ops = plan_overlay(src, dst).map_err(|e| InstallFailure::from(e.to_string()))?;
    elevate_overlay(&ops, src, dst, cleanup_dst)
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

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("qomicex-updater-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 造一棵 deb 式文件树：`usr/bin/Qomicex Launcher`(0755) + 一个名字里带
    /// 空格和单引号的 `.desktop`（deb 包的真实文件名形态 + 注入面）。
    #[cfg(unix)]
    fn fake_deb_tree(root: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let exe = root.join("usr/bin/Qomicex Launcher");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, b"new-binary").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let desktop = root.join("usr/share/applications/It's a test.desktop");
        std::fs::create_dir_all(desktop.parent().unwrap()).unwrap();
        std::fs::write(&desktop, b"Exec=x").unwrap();
        exe
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    #[test]
    fn plan_overlay_maps_staging_onto_target_and_keeps_mode() {
        let src = scratch("plan-src");
        let dst = scratch("plan-dst");
        let exe = fake_deb_tree(&src);

        let ops = plan_overlay(&src, &dst).unwrap();
        assert!(
            ops.contains(&Op::MakeDir(dst.join("usr"))),
            "目录必须显式建：{:?}",
            ops
        );
        let placed = ops
            .iter()
            .find(|o| matches!(o, Op::Place { to, .. } if *to == dst.join("usr/bin/Qomicex Launcher")))
            .expect("exe 的 Place 动作");
        match placed {
            // 权限位必须带进计划：提权脚本里的 cp 不带 chmod 时，0755 会被 umask
            // 削成 0644，覆盖完的启动器再也起不来。
            Op::Place { from, mode, .. } => {
                assert_eq!(from, &exe);
                assert_eq!(*mode & 0o111, 0o111, "丢了可执行位");
            }
            other => unreachable!("expected Place, got {other:?}"),
        }
        assert!(ops.iter().any(|o| matches!(o, Op::Place { to, .. }
                if *to == dst.join("usr/share/applications/It's a test.desktop"))));
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
    }

    #[cfg(unix)]
    #[test]
    fn run_overlay_overwrites_and_keeps_staging_for_replay() {
        let src = scratch("local-src");
        let dst = scratch("local-dst");
        let exe = fake_deb_tree(&src);
        std::fs::create_dir_all(dst.join("usr/bin")).unwrap();
        std::fs::write(dst.join("usr/bin/Qomicex Launcher"), b"old").unwrap();

        let ops = plan_overlay(&src, &dst).unwrap();
        run_overlay(&ops).expect("本地覆盖应成功");

        assert_eq!(
            std::fs::read(dst.join("usr/bin/Qomicex Launcher")).unwrap(),
            b"new-binary"
        );
        // 源必须还在：本地路径中途失败要回退提权，同一份计划得能幂等重放。
        assert!(exe.exists(), "run_overlay 不该消耗 staging 里的源文件");
        assert_eq!(
            mode_of(&dst.join("usr/bin/Qomicex Launcher")) & 0o111,
            0o111
        );
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
    }

    /// 渲染出的提权脚本必须**真的能跑**：覆盖已存在的目标、保住可执行位、
    /// 处理带空格与引号的文件名，最后删掉 staging。以当前用户对着临时目录执行，
    /// 不需要 root，也不需要碰真实系统目录。
    #[cfg(unix)]
    #[test]
    fn rendered_overlay_script_installs_over_existing_tree() {
        let src = scratch("script-src");
        let dst = scratch("script-dst");
        fake_deb_tree(&src);
        std::fs::create_dir_all(dst.join("usr/bin")).unwrap();
        std::fs::write(dst.join("usr/bin/Qomicex Launcher"), b"old-binary").unwrap();

        let ops = plan_overlay(&src, &dst).unwrap();
        let script = render_overlay_script(&ops, &src, &dst, false);
        let script_path = dst.join("run.sh");
        std::fs::write(&script_path, &script).unwrap();
        let status = Command::new("sh")
            .arg(&script_path)
            .status()
            .expect("找不到 sh：提权脚本同样依赖它");
        assert!(status.success(), "脚本执行失败：\n{script}");

        assert_eq!(
            std::fs::read(dst.join("usr/bin/Qomicex Launcher")).unwrap(),
            b"new-binary"
        );
        assert_eq!(
            mode_of(&dst.join("usr/bin/Qomicex Launcher")) & 0o111,
            0o111,
            "覆盖后丢了可执行位：\n{script}"
        );
        assert_eq!(
            std::fs::read(dst.join("usr/share/applications/It's a test.desktop")).unwrap(),
            b"Exec=x"
        );
        // `'` 必须被转义成 '\'' 而不是原样进脚本
        assert!(script.contains(r#"'\''"#), "单引号没转义：\n{script}");
        // 脚本自己负责删 staging（旧实现同样依赖这条，不能因为改用 mv 就丢掉）
        assert!(!src.exists(), "脚本末尾应清理 staging：\n{script}");
        let _ = std::fs::remove_dir_all(&dst);
    }

    /// 目标同目录里**预先放好**的落位临时名不能被复用（#204）。
    ///
    /// 临时名 (`.<name>.qomicex-update-tmp`) 是可预测的：预置一个软链，root 的
    /// `cp` 就会顺着它把包内容写到任意路径上。脚本必须先删再建，只肯写自己新建
    /// 的文件。这里用「指向目录的软链」证明那一刻它确实被删掉了——不删则 `cp`
    /// 失败、脚本非零退出。
    #[cfg(unix)]
    #[test]
    fn overlay_script_never_reuses_a_preset_placement_tmp() {
        let src = scratch("preset-src");
        let dst = scratch("preset-dst");
        std::fs::create_dir_all(dst.join("usr/bin")).unwrap();
        std::fs::write(src.join("payload"), b"payload").unwrap();

        let ops = plan_overlay(&src, &dst).unwrap();
        let to = dst.join("payload");
        let tmp = place_tmp(&to);
        // 软链指向目录：`cp` 若跟随它就会失败（也是「没被删掉」的证据）。
        let decoy = dst.join("decoy-dir");
        std::fs::create_dir_all(&decoy).unwrap();
        std::os::unix::fs::symlink(&decoy, &tmp).unwrap();

        let script = render_overlay_script(&ops, &src, &dst, false);
        let script_path = dst.join("run.sh");
        std::fs::write(&script_path, &script).unwrap();
        let status = Command::new("sh").arg(&script_path).status().unwrap();

        assert_eq!(
            status.code(),
            Some(0),
            "预置的落位临时名被复用了（软链应当先被删掉）：\n{script}"
        );
        assert_eq!(std::fs::read(&to).unwrap(), b"payload");
        assert!(
            std::fs::symlink_metadata(&tmp).is_err(),
            "落位临时名应在 mv 之后消失：\n{script}"
        );
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
    }

    /// 脚本中途失败时只能留下「自己刚建的那些临时名」，且必须被 trap 清掉（#204）。
    ///
    /// 构造法：第二个 Place 的源文件在渲染后删掉 → `cp` 失败 → `set -e` 退出。
    /// 此时第一个 Place 的临时文件已经建好，正是 trap 该收拾的东西；目标是
    /// 预置的旧内容，不能被半截覆盖。
    #[cfg(unix)]
    #[test]
    fn overlay_script_cleans_its_own_tmps_when_it_fails_midway() {
        let src = scratch("trap-src");
        let dst = scratch("trap-dst");
        std::fs::write(src.join("a-first"), b"new-a").unwrap();
        std::fs::write(src.join("b-second"), b"new-b").unwrap();
        std::fs::write(dst.join("a-first"), b"old-a").unwrap();
        std::fs::write(dst.join("b-second"), b"old-b").unwrap();

        let ops = plan_overlay(&src, &dst).unwrap();
        let script = render_overlay_script(&ops, &src, &dst, false);
        let script_path = dst.join("run.sh");
        std::fs::write(&script_path, &script).unwrap();
        // 渲染完成后再让第二个源消失，脚本跑到那一步就失败。
        std::fs::remove_file(src.join("b-second")).unwrap();

        let status = Command::new("sh").arg(&script_path).status().unwrap();
        assert!(!status.success(), "源缺失时脚本必须失败：\n{script}");

        for name in ["a-first", "b-second"] {
            let target = dst.join(name);
            assert!(
                std::fs::symlink_metadata(place_tmp(&target)).is_err(),
                "失败路径上 {name} 的临时文件没被清掉：\n{script}"
            );
            assert!(
                std::fs::read(&target).unwrap().starts_with(b"old-"),
                "{name} 被半截覆盖了：\n{script}"
            );
        }
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
    }

    /// 目标目录已存在时 `mkdir -p` 必须是 no-op（#204 的 macOS 场景）。
    ///
    /// `/Applications` 由系统预建：真去建它就得到 EEXIST，`set -e` 下整条提权
    /// 脚本会死在第一条命令上。这条同时钉住「-p 别丢」。
    #[cfg(unix)]
    #[test]
    fn overlay_script_tolerates_a_pre_existing_target_dir() {
        let src = scratch("mkdir-src");
        let dst = scratch("mkdir-dst");
        std::fs::create_dir_all(src.join("Frameworks")).unwrap();
        std::fs::write(src.join("Frameworks/lib.dylib"), b"lib").unwrap();
        // 目标目录先建好（模拟 /Applications 形态）
        std::fs::create_dir_all(dst.join("Frameworks")).unwrap();

        let ops = plan_overlay(&src, &dst).unwrap();
        assert!(
            ops.contains(&Op::MakeDir(dst.join("Frameworks"))),
            "计划里本来就该有这条：{:?}",
            ops
        );
        let script = render_overlay_script(&ops, &src, &dst, false);
        let script_path = dst.join("run.sh");
        std::fs::write(&script_path, &script).unwrap();
        let status = Command::new("sh").arg(&script_path).status().unwrap();

        assert_eq!(
            status.code(),
            Some(0),
            "已存在的目标目录把整个脚本弄挂了：\n{script}"
        );
        assert_eq!(
            std::fs::read(dst.join("Frameworks/lib.dylib")).unwrap(),
            b"lib"
        );
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
    }

    /// 提权链路的一次性工作目录：唯一、私有、用完即清（#204）。
    ///
    /// 这些正是 macOS 提权脚本的落脚点。三条都必须成立，缺一条就是本地提权面：
    /// 目录名可预测 → 别人能预置；权限不是 0700 → 别人能读改；不清理 → 残留可被
    /// 下次执行利用。
    #[cfg(unix)]
    #[test]
    fn private_work_dir_is_unique_private_and_self_cleaning() {
        let first = PrivateDir::create("unit").unwrap();
        let second = PrivateDir::create("unit").unwrap();
        assert_ne!(
            first.path(),
            second.path(),
            "两次创建必须拿到不同目录，不能复用固定名"
        );
        assert_eq!(
            mode_of(first.path()) & 0o777,
            0o700,
            "提权脚本的落脚目录必须只有自己可读写"
        );
        // 排他创建：预先占位同名目录时不能直接拿来用（换个名字重试）。
        assert!(first.path().is_dir());
        let path = first.path().to_path_buf();
        drop(first);
        drop(second);
        assert!(
            std::fs::symlink_metadata(&path).is_err(),
            "PrivateDir 的 Drop 必须整棵删掉：{}",
            path.display()
        );
    }

    /// 提权脚本文件本身：排他创建 + 0700，且不跟随预置同名对象（#204）。
    #[cfg(unix)]
    #[test]
    fn elevate_script_is_written_exclusively_and_not_world_readable() {
        let dir = scratch("priv-script");
        let path = dir.join("overlay.sh");
        write_private_script(&path, "#!/bin/sh\nexit 0\n").unwrap();
        assert_eq!(
            mode_of(&path) & 0o777,
            0o700,
            "以 root 执行的脚本不能给别人读改"
        );
        // 已存在就必须失败，而不是覆盖/跟随（软链是这里的攻击面）
        let err = write_private_script(&path, "#!/bin/sh\nexit 1\n");
        assert!(
            err.is_err(),
            "已存在的脚本必须拒绝覆盖（否则预置软链可让 root 写到任意路径）"
        );
        let target = dir.join("outside");
        let link = dir.join("link.sh");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_private_script(&link, "x").is_err(), "软链不能被跟随");
        assert!(!target.exists(), "内容不该被写到软链指向处");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 目标路径已被别人占用时：换名重试，**绝不**删掉那个已存在的目录（#204）。
    ///
    /// 这里直接把 `create_private_dir` 的 AlreadyExists 分支单拎出来测：它是
    /// 「多用户机器上不越界」这条的分水岭，删别人的目录比不复用更糟。
    #[cfg(unix)]
    #[test]
    fn private_dir_creation_never_disturbs_an_existing_path() {
        let base = scratch("collide");
        let taken = base.join("taken");
        std::fs::create_dir_all(&taken).unwrap();
        std::fs::write(taken.join("someone-elses-file"), b"keep me").unwrap();

        let err = create_private_dir(&taken).unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::AlreadyExists,
            "必须把「已存在」如实报给调用方，而不是吞掉或覆盖"
        );
        assert_eq!(
            std::fs::read(taken.join("someone-elses-file")).unwrap(),
            b"keep me",
            "已存在的目录（含内容）不能被这次创建动到"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// 信号 trap 必须显式 exit（#204）。
    ///
    /// 这条只能在文本上钉死、不需要真发信号：POSIX 里信号 handler 返回后 sh 会
    /// **继续执行剩下的动作**——提权脚本剩下的正是 `cp`/`mv`，等于中断之后接着
    /// 半截覆盖。EXIT trap 则不必自己 exit（脚本本来就要退）。
    #[test]
    fn signal_traps_end_the_script_explicitly() {
        let src = scratch("trap-shape-src");
        let dst = scratch("trap-shape-dst");
        std::fs::write(src.join("a"), b"a").unwrap();
        let ops = plan_overlay(&src, &dst).unwrap();
        let script = render_overlay_script(&ops, &src, &dst, false);

        assert!(
            script.contains("trap 'qmx_cleanup' EXIT"),
            "EXIT trap 负责 set -e 提前退出时的清理：\n{script}"
        );
        for (sig, code) in [("INT", 130), ("TERM", 143), ("HUP", 129)] {
            assert!(
                script.contains(&format!("trap 'qmx_cleanup; exit {code}' {sig}")),
                "信号 {sig} 的 handler 必须清理后显式 exit {code}，\
                 否则 sh 会继续执行剩余的 cp/mv：\n{script}"
            );
        }
        // 清理只允许碰本次渲染出来的临时名
        assert!(
            script.contains("qmx_cleanup() { rm -f --"),
            "清理函数必须以 rm -f -- 开头且只带渲染出的路径：\n{script}"
        );
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
    }

    /// 提权脚本以 root 执行，而包内文件名来自下载物——恶意/损坏的包不能把
    /// 文件名变成命令。`sh_quote` 是这条线上唯一的防线，必须有回归用例钉住。
    #[cfg(unix)]
    #[test]
    fn overlay_script_neutralises_quoted_file_names() {
        let src = scratch("inject-src");
        let dst = scratch("inject-dst");
        // 载荷含 `'` 与 `;`（都是 Linux 文件名的合法字符）。转义一旦失效，sh 会
        // 解析出 `exit 42`：脚本退出码与落位结果同时失真，两条断言都能抓到。
        let evil = "x'; exit 42; '";
        std::fs::write(src.join(evil), b"payload").unwrap();

        let ops = plan_overlay(&src, &dst).unwrap();
        let script = render_overlay_script(&ops, &src, &dst, false);
        let script_path = dst.join("run.sh");
        std::fs::write(&script_path, &script).unwrap();
        let status = Command::new("sh").arg(&script_path).status().unwrap();

        assert_eq!(
            status.code(),
            Some(0),
            "包内文件名被当成命令执行了（或转义把语法搞坏了）：\n{script}"
        );
        assert_eq!(
            std::fs::read(dst.join(evil)).unwrap(),
            b"payload",
            "转义后的路径应原样落位：\n{script}"
        );
        let _ = std::fs::remove_dir_all(&dst);
    }

    #[cfg(unix)]
    #[test]
    fn sh_quote_escapes_only_the_single_quote() {
        assert_eq!(
            sh_quote(Path::new("/usr/bin/Qomicex Launcher")),
            "'/usr/bin/Qomicex Launcher'"
        );
        assert_eq!(
            sh_quote(Path::new("/a'b")),
            r#"'/a'\''b'"#,
            "单引号必须闭合-转义-重开，不能只加反斜杠"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn zombie_from_stat_handles_bracketed_comm() {
        // 正常进程 / 僵尸 / comm 里带括号与空格 / 结构异常
        assert!(!zombie_from_stat("9 (dash) S 8 9 0 0 -1 4198400 1 0 0 0"));
        assert!(zombie_from_stat("9 (dash) Z 8 9 0 0 -1 4198400"));
        assert!(
            zombie_from_stat("123 (weird (name) here) Z 1 123 0 0"),
            "comm 含括号时必须按最后一个 ) 切分"
        );
        assert!(!zombie_from_stat("garbage without parens"));
        assert!(!zombie_from_stat("1 (a)"));
    }

    #[cfg(unix)]
    #[test]
    fn probe_target_separates_permission_denied_from_busy() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("probe");
        // 同 uid 但去掉写位 → EACCES：这是「要提权」，绝不是「被占用」
        let readonly = dir.join("launcher");
        std::fs::write(&readonly, b"x").unwrap();
        std::fs::set_permissions(&readonly, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert_eq!(
            probe_target(&readonly),
            TargetState::Unknown,
            "EACCES 被判成锁定就是 issue #201"
        );
        // 可写 → Free
        let writable = dir.join("appimage");
        std::fs::write(&writable, b"x").unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(probe_target(&writable), TargetState::Free);
        // 不存在 → 也不该拦住更新
        assert_eq!(probe_target(&dir.join("gone")), TargetState::Free);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// unix 的等待判据必须是「进程退出」，不是「能不能写」。
    ///
    /// issue #201 的直接回归：deb/rpm 的 `/usr/bin/Qomicex Launcher` 是 root
    /// 所有的 0755，写探测永远失败；旧实现把 EACCES 当锁定，烧满超时后 exit 5，
    /// 于是「点了更新 → 启动器退出 → 既没装也没重启」。
    #[cfg(unix)]
    #[test]
    fn wait_for_target_uses_the_pid_not_the_write_probe_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("wait");
        let exe = dir.join("Qomicex Launcher");
        std::fs::write(&exe, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o555)).unwrap();
        // 前提成立：这个目标对当前用户就是「写不动」的
        assert_eq!(probe_target(&exe), TargetState::Unknown);

        // 两种「一定已经退出」的 pid 都必须**立刻**放行：
        // ① 超出 pid_t 范围——旧实现里 kill 把它当进程组、返回成功，等待白烧满超时
        // ② 真的 spawn/wait 过并已回收的 pid（kill -0 → ESRCH）
        let mut child = Command::new("sh").arg("-c").arg("exit 0").spawn().unwrap();
        let reaped = child.id();
        child.wait().unwrap();
        for (label, dead_pid) in [("超范围 pid", u32::MAX), ("已回收 pid", reaped)] {
            let started = Instant::now();
            wait_for_target(Some(&exe), Some(dead_pid))
                .unwrap_or_else(|e| panic!("{label} 必须放行，实得 {e}"));
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "{label} 等了 {:?} —— 又在等「能不能写」而不是等进程退出",
                started.elapsed()
            );
        }

        // 没有 --wait-pid 时同样放行（unix 上运行中的 image 不锁文件）
        wait_for_target(Some(&exe), None).expect("无 pid 时不该等写权限");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wait_for_target_without_either_signal_is_a_no_op() {
        wait_for_target(None, None).expect("没有等待对象就直接放行");
    }

    // 僵尸判定没有「真造一个僵尸」的用例：本机实测 Rust `spawn` 出的子进程退出后
    // 会被立即回收（观察不到 `state = Z`），能否留下僵尸取决于内核/运行库时序，
    // 硬写就是个会随环境翻脸的用例。覆盖拆成两块：解析逻辑见
    // `zombie_from_stat_handles_bracketed_comm`；「已退出的 pid 必须立刻放行」见
    // `wait_for_target_uses_the_pid_not_the_write_probe_on_unix`。

    /// 提权分类：「用户取消」与「后端不可用」是两条不同的用户提示，也是退出码
    /// 6 与 4 的唯一分岔点，还决定要不要继续往后端回退。
    #[test]
    fn classify_separates_user_cancelled_from_backend_unavailable() {
        assert!(
            matches!(
                classify_priv_failure(
                    "pkexec",
                    Some(127),
                    "User cancelled authentication agent",
                    "d"
                ),
                PrivAttempt::Cancelled(_)
            ),
            "用户关掉授权弹窗必须算取消，且不再回退别的后端"
        );
        // Debian 容器实测：polkitd 没跑时 pkexec **也**退 127。那不是用户拒绝——
        // 误判会挡掉 sudo -n 兜底，配了免密 sudoers 的机器于是永久无法自更新。
        assert!(
            matches!(
                classify_priv_failure(
                    "pkexec",
                    Some(127),
                    "Error getting authority: Error initializing authority: Could not connect: No such file or directory",
                    "d"
                ),
                PrivAttempt::Unavailable(_)
            ),
            "polkit 连不上属于后端不可用，必须继续试 sudo -n"
        );
        assert!(
            matches!(
                classify_priv_failure(
                    "pkexec",
                    Some(126),
                    "Not authorized to perform operation",
                    "d"
                ),
                PrivAttempt::Unavailable(_)
            ),
            "未获授权（无 agent / 策略拒绝）不是用户取消"
        );
        assert!(
            matches!(
                classify_priv_failure("sudo", Some(1), "sudo: a password is required", "d"),
                PrivAttempt::Unavailable(_)
            ),
            "非交互 sudo 要密码属于不可用"
        );
        assert!(
            matches!(
                classify_priv_failure("sudo", Some(127), "unexpected", "d"),
                PrivAttempt::Unavailable(_)
            ),
            "只有 pkexec 的 127 才可能代表用户取消"
        );
    }

    /// issue #204：macOS 的管理员授权弹窗取消必须走 `Cancelled`（→ exit 6 /
    /// `ELEVATION_DENIED`），而**不能**靠退出码判断。
    ///
    /// `do shell script` 抛出的 AppleScript 错误号就是 shell 的退出码（TN2065），
    /// 用户取消是 -128；两者混在一个数字空间里。所以判定只看 stdout 标记。
    #[test]
    fn osascript_marker_separates_cancel_from_install_failure() {
        assert!(
            matches!(classify_osascript("QOMICEX_OK\n", "d"), PrivAttempt::Done),
            "标记为 OK 才允许算安装成功"
        );
        assert!(
            matches!(
                classify_osascript("QOMICEX_CANCELLED", "d"),
                PrivAttempt::Cancelled(_)
            ),
            "用户点取消必须映射为「授权被取消」，否则会被报成安装失败"
        );
        assert!(
            matches!(
                classify_osascript("QOMICEX_FAILED", "d"),
                PrivAttempt::ExecFailed(_)
            ),
            "已获授权但脚本失败，不能回退给 sudo -n 重放（会盖掉真正的失败原因）"
        );
        // 协议没走通（空输出 / 夹杂别的输出）：既不是成功也不是取消，
        // 同样不该再提权重放一次。
        for marker in ["", "some shell output", "exit 128"] {
            assert!(
                matches!(classify_osascript(marker, "d"), PrivAttempt::ExecFailed(_)),
                "非标记输出 {marker:?} 必须按失败处理，绝不能当成功"
            );
        }
        // 安装脚本的 stdout 会一起回吐：标记藏在别的输出里不算数（否则一个打印
        // 了字面量的脚本就能伪造成功）。
        assert!(
            matches!(
                classify_osascript("cp done\nQOMICEX_OK", "d"),
                PrivAttempt::ExecFailed(_)
            ),
            "标记只在整份输出恰好等于标记时采信"
        );
    }

    /// 后端顺序就是「先弹授权、失败才退让」的契约本身（#204）。
    ///
    /// 顺序错了会直接复现缺陷：macOS 上先试 `pkexec`/`sudo -n` 只会白失败一次，
    /// 配了免密 sudoers 的机器甚至绕过授权弹窗。所以两个平台的分支都要在同一台
    /// 机器上可测——只断言 `cfg!` 命中的那一支等于放跑另一支。
    #[test]
    fn privilege_backends_are_ordered_per_platform() {
        assert_eq!(
            backends_for("macos"),
            &["osascript", "sudo"],
            "macOS 必须先弹管理员授权；pkexec 在 macOS 上不存在，试它是白费"
        );
        assert_eq!(
            backends_for("linux"),
            &["pkexec", "sudo"],
            "Linux 的既有语义（#201）不能被本次改动打乱"
        );
        assert_eq!(
            backends_for("freebsd"),
            &["pkexec", "sudo"],
            "其它 unix 与 Linux 同构，不需要单独的图形授权分支"
        );
        // 生产入口必须选中本平台那一支
        assert_eq!(privilege_backends(), backends_for(std::env::consts::OS));
    }

    /// AppleScript 源码的几条不变量（脚本是常量，可在任意平台静态钉住）。
    ///
    /// 这些点错了不会在本仓库的 CI（无 macOS）里暴露，只会在用户机器上表现为
    /// 「每次都提示授权被取消」或「路径带引号就注入」——所以只能靠断言守。
    #[test]
    fn osascript_script_keeps_its_safety_invariants() {
        let src = OSASCRIPT_ELEVATE;
        assert!(
            src.contains("on run argv") && src.contains("item 1 of argv"),
            "脚本路径必须从 argv 进来，而不是被拼进 AppleScript 源码"
        );
        assert!(
            src.contains("quoted form of scriptPath"),
            "路径进 shell 前必须经 quoted form of 转义"
        );
        assert!(
            src.contains("with administrator privileges"),
            "缺了这段就不是管理员授权弹窗，GUI 进程根本提不了权"
        );
        assert!(
            src.contains("errNum is -128"),
            "-128 是用户在授权弹窗点取消的错误号，误判会把它报成安装失败"
        );
        // 标记必须是脚本自己产出的，且不能把安装输出漏进 stdout
        assert!(
            src.contains("set installOutput to do shell script"),
            "do shell script 的返回值必须被丢弃，否则安装脚本的 stdout 会混进标记"
        );
        // 双引号是 AppleScript 字符串的边界：源码里除配对的外不能出现裸引号
        assert_eq!(
            src.matches('"').count() % 2,
            0,
            "AppleScript 字符串引号必须成对：{src}"
        );
    }

    /// 取消语义必须能穿过 `install_app` 的提权分支（#204 的直接回归）。
    ///
    /// 真去 spawn osascript/pkexec 会弹授权窗，测试里不能那么干；但缺陷的实质是
    /// **类型**：`elevate_copy` 曾把 `InstallFailure` 压成 `String` 再往上返回，
    /// `denied` 一过手就没了。编译期钉住这个签名，比运行时断言更早拦住回归。
    #[cfg(unix)]
    #[test]
    fn elevate_copy_preserves_the_denied_flag() {
        let _typed: fn(&Path, &Path, bool) -> Result<(), InstallFailure> = elevate_copy;
        let _typed_app: fn(&Path, Option<&Path>) -> Result<(), InstallFailure> = install_app;
    }

    /// 后端二进制根本不存在（无 polkit 的定制发行版、macOS）必须判「不可用」，
    /// 绝不能卡在交互提示上——自更新是无人值守链路。
    #[test]
    fn missing_privilege_backend_is_unavailable_not_fatal() {
        let dir = scratch("priv");
        let script = dir.join("overlay.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        match run_privileged("qomicex-definitely-not-installed", &script) {
            PrivAttempt::Unavailable(reason) => {
                assert!(
                    reason.contains("无法执行"),
                    "提示要说清后端不可用：{reason}"
                )
            }
            PrivAttempt::Done => panic!("不存在的后端不该报成功"),
            PrivAttempt::Cancelled(_) => panic!("缺二进制不等于用户取消"),
            PrivAttempt::ExecFailed(_) => panic!("脚本根本没跑起来，谈不上执行失败"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// deb 形态主链路端到端（对着临时 root，不碰系统目录、不需要 root）：
    /// 真 zip → 解压 → 生成计划 → 本地覆盖，目标被换掉且可执行位保住。
    #[cfg(unix)]
    #[test]
    fn install_system_to_lands_a_deb_tree_without_elevation_when_writable() {
        use std::io::Write as _;
        let dir = scratch("sys-e2e");
        // 包内布局与 CI 产物一致：dpkg-deb -x 出来的相对路径
        let pkg = dir.join("qomicex-update-9.9.9.zip");
        let file = std::fs::File::create(&pkg).unwrap();
        let mut zw = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default().unix_permissions(0o755);
        zw.add_directory("usr", opts).unwrap();
        zw.add_directory("usr/bin", opts).unwrap();
        zw.start_file("usr/bin/Qomicex Launcher", opts).unwrap();
        zw.write_all(b"NEW-LAUNCHER").unwrap();
        zw.finish().unwrap();

        // 已安装的「旧」系统目录：目标文件存在且内容不同
        let fake_root = dir.join("root");
        std::fs::create_dir_all(fake_root.join("usr/bin")).unwrap();
        std::fs::write(fake_root.join("usr/bin/Qomicex Launcher"), b"OLD").unwrap();

        let launch = fake_root.join("usr/bin/Qomicex Launcher");
        install_system_to(&pkg, &fake_root, Some(&launch)).expect("可写目标不该走提权");

        assert_eq!(
            std::fs::read(&launch).unwrap(),
            b"NEW-LAUNCHER",
            "system 策略必须把 deb 树覆盖进目标根"
        );
        assert_eq!(
            mode_of(&launch) & 0o111,
            0o111,
            "覆盖后必须仍可执行，否则更新完就是起不来"
        );
        // staging 用完即删（旧实现同样依赖这条行为，改用 rename 后不能丢）
        let staging =
            std::env::temp_dir().join(format!("qomicex-update-system-{}", std::process::id()));
        assert!(!staging.exists(), "staging 未清理：{}", staging.display());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
