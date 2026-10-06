//! Install strategies: unzip the package into a staging directory next to the
//! target, then move files into place. Elevation (pkexec / osascript) is only
//! used when the target is not writable by the current user.

use crate::ulog;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
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
pub fn render_overlay_script(ops: &[Op], staging: &Path, dst: &Path, cleanup_dst: bool) -> String {
    let mut body = String::from("#!/bin/sh\nset -e\n");
    for op in ops {
        match op {
            Op::MakeDir(dir) => {
                body.push_str("mkdir -p ");
                body.push_str(&sh_quote(dir));
                body.push('\n');
            }
            Op::Place { from, to, mode } => {
                let tmp = place_tmp(to);
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
        body.push_str(&format!("rm -f {}/*.qdtmp\n", sh_quote(dst)));
    }
    body.push_str("rm -rf -- ");
    body.push_str(&sh_quote(staging));
    body.push('\n');
    body
}

/// 提权后端的一次尝试结果。
enum PrivAttempt {
    Done,
    /// 用户明确取消授权（关掉 polkit 弹窗）——**不再**尝试别的提权后端：
    /// 这是选择而不是故障，绕开它等于无视用户的拒绝。
    Cancelled(String),
    /// 该后端不可用（缺二进制 / 无 polkit agent / 非交互 sudo 要密码）
    /// → 继续试下一个后端。
    Unavailable(String),
}

/// `program` 以 root 身份跑 `sh <script>`。
///
/// 用 `output()` 而不是 `status()`：旧实现把 stderr 全丢了，只剩
/// 「elevated copy failed (pkexec exit 1)」这种既定位不了也没法转成
/// 可操作提示的日志（#201 取证的主要困难）。
fn run_privileged(program: &str, script: &Path) -> PrivAttempt {
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

/// 把退出码翻译成「用户拒绝授权」还是「该后端不可用」。
///
/// 单独抽出来是为了在没有 root、没有 polkit agent 的环境里把这条判定测死：
/// 它决定用户看到的是「你取消了授权，请手动升级」还是「这台机器提权不可用」，
/// 也是退出码 6 与 4 的唯一分岔点，并直接决定要不要继续往后端回退。
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

/// 提权执行覆盖计划：`pkexec` → `sudo -n` 分级。
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
    let script_path =
        std::env::temp_dir().join(format!("qomicex-update-elevate-{}.sh", std::process::id()));
    let body = render_overlay_script(ops, staging, dst, cleanup_dst);
    std::fs::write(&script_path, &body)
        .map_err(|e| InstallFailure::from(format!("cannot write elevate script: {e}")))?;

    let mut cancelled: Option<String> = None;
    let mut unavailable: Vec<String> = Vec::new();
    for program in ["pkexec", "sudo"] {
        match run_privileged(program, &script_path) {
            PrivAttempt::Done => {
                let _ = std::fs::remove_file(&script_path);
                return Ok(());
            }
            PrivAttempt::Cancelled(reason) => {
                ulog(&format!("{program} 授权被取消: {reason}"));
                cancelled = Some(reason);
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
    Err(match cancelled {
        Some(reason) => InstallFailure {
            denied: true,
            message: format!(
                "提权未获授权（{reason}）。手动升级：sudo dpkg -i <deb> 或 sudo rpm -Uvh <rpm>"
            ),
        },
        None => InstallFailure {
            denied: false,
            message: format!("提权失败：{}", unavailable.join("；")),
        },
    })
}

/// macOS .app 覆盖的提权入口（保留旧签名，install_app 不感知计划渲染）。
fn elevate_copy(src: &Path, dst: &Path, cleanup_dst: bool) -> Result<(), String> {
    let ops = plan_overlay(src, dst).map_err(|e| e.to_string())?;
    elevate_overlay(&ops, src, dst, cleanup_dst).map_err(|f| f.message)
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
