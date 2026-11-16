# Qomicex.Updater

Qomicex 启动器自更新器：独立无 GUI CLI，由启动器在更新包下载完成后调用。

## 契约

```text
qomicex-updater \
  --package <zip>         # 更新包（文件布局 zip，下载中心下载）
  --signature <file>      # minisign 签名（对 zip 全文）
  --strategy <s>          # dir | appimage | app | system
  --install-dir <path>    # dir 策略：启动器安装根目录
  --appimage <path>       # appimage 策略：$APPIMAGE 路径
  --app-bundle <path>     # app 策略：.app 目录
  --wait-pid <pid>        # 等待该进程退出后再动文件（默认等 30s）
  --launch <exe>          # 安装成功后启动的可执行文件
```

退出码：0 成功 | 1 用法错误 | 2 IO/启动失败 | 3 签名无效 | 4 策略执行失败 | 5 等待超时 |
6 提权未获授权（用户取消）。

## 策略

| 策略 | 平台 | 动作 | 提权 |
|---|---|---|---|
| dir | Windows (NSIS 安装) | 解压覆盖安装目录 | 无 |
| appimage | Linux AppImage | 替换单文件 + chmod +x | 无 |
| app | macOS .app | 私有 staging → osascript 弹窗提权覆盖 | 是 |
| system | Linux deb/rpm | staging → pkexec 弹窗覆盖 / | 是 |

提权后端按平台分派：macOS 是 `osascript`（管理员授权弹窗）→ `sudo -n`（仅
osascript 无法启动时兜底），Linux 是 `pkexec` → `sudo -n`。只有「后端没装 /
连不上 / 非交互 sudo 要密码」才继续试下一个；**用户取消**与**已获授权但脚本
失败**都立刻停止——前者落 `ELEVATION_DENIED`（exit 6），后者落
`UPDATE_INSTALL_FAILED`（exit 4），重放同一条计划只会盖掉真正的现场。

macOS 的提权脚本落在 `temp_dir` 下本次新建的私有目录（0700，Drop 即删）里，
路径不可预测；脚本内先删目标同目录的落位临时名再 `cp`，只肯写自己新建的文件，
不跟随预置软链。

安全：minisign 公钥编译期嵌入（`src/main.rs` `PUBLIC_KEY`），签名无效拒绝动手。
