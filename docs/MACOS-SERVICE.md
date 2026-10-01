# macOS 登录后服务（LaunchAgent）

本配置适用于**当前用户登录 macOS 图形桌面后启动**。退出登录后服务停止；
重启后要等该用户登录才能运行。锁屏不是退出登录，但睡眠会影响网络服务。
它不会创建登录前的系统服务，也不会开启自动登录。

模板：[com.example.ssh-stream-gateway.agent.plist](../examples/launchd/com.example.ssh-stream-gateway.agent.plist)。
仓库只提供占位模板和手动操作说明，没有安装器，也没有真实地址、身份或密钥。
下文安装、加载和停止命令仅供你在确认路径与运行身份后，在自己的 Mac 上执行。

## 先确认运行条件

1. 按 [README](../README.md) 完成 Mac 本地构建或验证下载的构建，准备仓库外的私人
   `server.toml`、TLS 证书/密钥、固定 SSH 身份和已核验的 `known_hosts`
2. 选择持久的二进制位置，不要指向临时下载目录、之后会清理的构建目录或网络挂载。
   可执行文件及其父目录不能允许其他用户修改；服务使用当前登录用户身份，不需要 root
3. 所有配置中的文件路径和 plist 的参数必须使用**字面绝对路径**。把模板中的两个
   `/ABSOLUTE/PATH/TO/...` 都替换掉。每个参数保留为一个 `<string>`，路径中的空格
   无需额外 shell 引号；XML 中的 `&`、`<` 等字符要正确转义
4. 私人目录通常为 `0700`，配置、密钥等私人文件为 `0600`，由运行用户持有。
   模板的 `Umask=63` 表示八进制 `077`，只影响新建文件，不修复已有权限。
   不要为了服务能读取而扩大权限、复制私钥或把口令放进 plist、环境变量、Git 或命令行
5. 绑定具体的 WireGuard/私网 IP 和非特权端口，并自行确认路由与防火墙范围。
   不要改成通配监听地址；模板不设置网络，也不会代替启动 WireGuard

`launchd` 直接运行二进制，没有 shell，不展开 `~`、`$HOME`、`$(...)` 或通配符，
也不会读取 `.zshrc` 等交互式 shell 初始化文件。服务一直在前台运行；不要加 `&`、
`nohup`、shell 包装或自行 daemonize。模板不需要 `WorkingDirectory`；若自行添加，
该目录必须事先存在并可访问。它不使用 `Sockets`，因为程序自行绑定监听地址，
不支持 launchd socket activation。[Apple 的 launchd 运行要求](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)

### 加密 SSH 身份与 agent

服务是非交互的，OpenSSH 使用 `BatchMode=yes`，不会弹出口令输入界面。
加密私钥需要你在本机预先解锁至 SSH agent，再在 `server.toml` 的目标中设置
`identity_agent` 为那个 agent socket 的字面绝对路径。也可以选择对应公钥文件，
由已经解锁的 agent 签名。默认 `identity_agent` 为空时明确禁用 agent。

GUI 登录并不保证服务启动时密钥已解锁；agent socket 也可能随会话变化。
本工具清理 SSH 子进程的环境并指定 SSH 参数，不依赖 shell 的 `SSH_AUTH_SOCK`
或 SSH 配置中的 Keychain 选项。重新登录后应再次核验指定 socket 和密钥是否可用。
缺失/未解锁身份会令相关 SSH 会话失败，不会自动改用其他身份。
不要为无人值守启动去解密私钥、保存解锁口令或改成 root。

如果以后需要开机且登录前运行，应另行设计 LaunchDaemon 和专用非特权身份；
用户的登录 Keychain、登录会话 ssh-agent 和其 socket 不能假定在登录前可用。

## WireGuard 较晚启动时会发生什么

`serve` 先验证配置并加载 TLS，再尝试监听**原配置中的 IP 和端口**。

- 仅地址尚未就绪的 `EADDRNOTAVAIL` / `AddrNotAvailable` 会重试：等待
  1、2、4、8、16 秒，随后每 30 秒重试，直到该地址可绑定或收到停止信号
- 等待期间进程仍存在，但没有接受连接；`launchctl` 显示运行不等于 HTTPS 已就绪
- 不会回退到 loopback、其他接口或 `0.0.0.0` / `::`，不会启动或修改 WireGuard
- 地址拼错但符合私网规则，也可能一直等待，应核对实际接口地址
- 首次等待会写诊断，之后等待诊断至多每分钟一次；绑定成功后写一次监听诊断。
  模板默认丢弃 stderr；调试时见下方“查看状态与诊断”
- 端口被占用 (`EADDRINUSE`)、权限错误、配置/TLS 错误立即退出，不进入地址重试
- SIGTERM / Ctrl-C 在等待期间同样生效；已运行时会停止接收连接并清理本地 SSH 子进程

这是**启动阶段绑定等待**。后续 WG 断线、地址变化或 Mac 睡眠可能中断现有流；
不会重放远端命令，也不保证自动重新绑定一个改变后的地址。
收到退出帧前断开的命令结果仍然未知，重试有副作用的命令前应先确认远端状态。

## 重启策略与停止语义

模板选择 `RunAtLoad=true`、`KeepAlive={SuccessfulExit=false}`、`ThrottleInterval=60`：
登录加载后运行一次，非零退出或异常终止会由 launchd 重新启动，包含普通 Rust panic。
正常处理 SIGTERM / Ctrl-C 后返回 0，不触发此重启条件。

**配置、TLS、端口冲突等普通错误也会被 launchd 重新启动**。程序自身对这些错误立即
退出 125；launchd 无法用这个条件区分“可恢复异常”和“需要人工修复的配置错误”。
60 秒节流可避免快速启动循环，但不是有限重试次数、健康检查或恢复时限。
持续错误会一直以受限频率重启，必须主动 `bootout`，修复后再加载，不能靠等待解决。
服务运行较久后才失败时也不保证额外等满 60 秒才重启；这是启动频率节流。
`KeepAlive` / `SuccessfulExit` 与 `ThrottleInterval` 的含义见
[Apple 的 launchd.plist 手册源码](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5)，
具体版本以 Mac 上 `man launchd.plist` 为准。

`ExitTimeOut=45` 为 SIGTERM 后的本地 SSH 清理留出时间，之后 launchd 可强制终止。
不设置 `AbandonProcessGroup`。清理本地 SSH 不保证远端脱离连接的后台命令也停止。
停止服务优先用下面的 `bootout`，不要用 `kill -9` 测试正常关闭。

## 在 Mac 上验证，再手动安装

下面命令中的占位路径必须先替换。先在将运行服务的用户自己的 Terminal 中，
以该用户身份验证，**不要加 sudo**。`check-config` 不读取 TLS 密钥、不验证 SSH 登录，
因此还需前台运行；此时还不要加载 LaunchAgent，避免同一端口运行两份服务。

```sh
/ABSOLUTE/PATH/TO/ssh-stream-gateway check-config --config /ABSOLUTE/PATH/TO/private/server.toml
/ABSOLUTE/PATH/TO/ssh-stream-gateway serve --config /ABSOLUTE/PATH/TO/private/server.toml
```

用受信任的客户端检查 HTTPS/HTTP2、口令和所需 SSH 目标，然后 Ctrl-C 停止前台实例。
这一步会建立实际监听/SSH 连接，只在你准备好对应网络和目标时执行。
若只做仓库检查，可以运行不启动服务的离线模板测试：

```sh
python3 -B -m unittest discover -s tests -p 'test_launchd_templates.py'
```

将模板复制到**仓库外**的编辑位置，替换两个路径并检查，保留 `Label` 与文件名一致。
模板没有 `UserName`；LaunchAgent 使用所属的 GUI 用户。不要将它放进
`/Library/LaunchDaemons` 或 `/System/Library`。

```sh
# 这里只是示例变量；EDITED_PLIST 必须是已修改并核验的私人副本
EDITED_PLIST='/ABSOLUTE/PATH/TO/edited/com.example.ssh-stream-gateway.agent.plist'
LABEL='com.example.ssh-stream-gateway.agent'
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
DOMAIN="gui/$(id -u)"

/usr/bin/plutil -lint "$EDITED_PLIST"
/usr/bin/grep -n 'ABSOLUTE/PATH/TO' "$EDITED_PLIST"
# 上一条必须没有匹配；确认路径正确后才继续。plutil 只验证 plist 语法。
```

以下命令会安装和启动当前用户服务。确认用户、二进制/配置路径和网络范围后再执行；
目标文件已经存在时先检查并备份，不要不经检查地覆盖。

```sh
/bin/mkdir -p "$HOME/Library/LaunchAgents"
/usr/bin/install -m 600 "$EDITED_PLIST" "$PLIST"
/usr/bin/plutil -lint "$PLIST"
/bin/launchctl bootstrap "$DOMAIN" "$PLIST"
/bin/launchctl print "$DOMAIN/$LABEL"
```

`bootstrap` 配合 `RunAtLoad` 启动该实例，不必紧接着强制重启。
这些 shell 变量仅在 Terminal 中展开，不能照搬进 plist。
LaunchAgent plist 必须属于当前用户且不允许组/其他用户写入；上述新文件使用 `0600`。
若此前已手动禁用该 label，需要先查清状态，再有意识地执行
`launchctl enable "$DOMAIN/$LABEL"`。不要为了排错批量启用其他服务或绕过系统安全提示。

## 查看状态与诊断

在同一个用户 Terminal 中重新设置上方 `LABEL`、`PLIST`、`DOMAIN` 后：

```sh
/bin/launchctl print "$DOMAIN/$LABEL"
/bin/launchctl print-disabled "$DOMAIN"
```

检查 PID、状态、最近退出码和实际参数。运行状态只说明进程存在；HTTPS 是否监听、
TLS 是否可信、认证/SSH 是否成功必须独立验收。`plutil` 成功也不代表路径或配置可用。
不要把包含私人路径的完整状态输出贴进公共 issue。

模板将 stdin/stdout/stderr 显式指向 `/dev/null`，**默认不保留应用诊断日志**，
也不保证 stderr 出现在 macOS 的统一日志中。这避免无人看管的日志文件无限增长。
遇到错误时先 `bootout`，再按上方命令前台运行，读取本机终端诊断；修复后重新
`bootstrap`。启动失败时也可查看 Console 中 launchd 自身的错误。

若需要持久诊断，可在你自己的 plist 副本中将 `StandardErrorPath` 改为已准备好的
私人日志绝对路径，并**事先安排大小/保留期限制和轮转**。父目录必须存在，日志文件
由运行用户持有、权限 `0600`，避免符号链接和共享目录。launchd 不替你轮转文件；
单纯重命名旧日志不保证当前进程改写新文件，轮转时要安排安全停止/重新启动。
不要启用会记录请求头、口令、命令或流内容的外部日志。

## 修复、停止和移除

持续失败时先 `bootout`，修复后重新 `bootstrap`，避免一直重试错误配置。
如果 job 仍已加载、正常退出后处于停止状态，可以手动启动：

```sh
/bin/launchctl kickstart "$DOMAIN/$LABEL"
/bin/launchctl print "$DOMAIN/$LABEL"
```

不使用 `kickstart -k`，以免强制打断活跃会话。更改 plist、替换二进制或需要重新读取
配置时，先等现有工作完成，再正常卸载/加载：

```sh
/bin/launchctl bootout "$DOMAIN/$LABEL"
# 确认旧进程及本地 SSH 子进程已退出后，再编辑/替换和重新验证
/usr/bin/plutil -lint "$PLIST"
/bin/launchctl bootstrap "$DOMAIN" "$PLIST"
```

只想停止本次登录的服务，就执行 `bootout` 后不要重新加载。plist 仍在 LaunchAgents
目录时，下次登录会再次加载。若不希望下次登录启动，可在卸载后把这一份 plist
移到你自己的备份目录，或有意识地禁用这个 label；不要删除私人配置和密钥。

## 部署验收清单

- 模板离线解析通过，Mac 上 `plutil -lint` 通过，所有占位路径已替换
- 实际 plist 由当前用户持有，非组/全局可写，未加入 `UserName` 或 shell
- GUI 登录后自动运行，退出登录后停止；服务只监听配置中的具体 IP/端口
- WG 地址尚未出现时进程等待；地址出现后才监听，期间 SIGTERM 可立即结束等待
- 错误 TLS/配置或端口冲突时程序立即退出，launchd 节流后重试；`bootout` 可停止循环，修复后重新加载成功
- 异常退出后 launchd 重新启动；正常 SIGTERM 返回 0 后不会自行重启
- SIGTERM / `bootout` 正常清理本地 SSH，没有把远端任务是否结束当作已保证
- 加密身份在每次会话中可用，socket 已核验，HTTPS 与实际 SSH 目标独立测试通过

仓库的离线测试不能替代以上实际 Mac、登录会话、WireGuard 和密钥环境验收。

参考：[Apple 的服务/用户会话说明](https://developer.apple.com/library/archive/technotes/tn2083/_index.html)、
[Apple 的 launchd.plist 手册源码](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5)。
安装机器上的 `man launchctl` 和 `man launchd.plist` 是该 macOS 版本的命令/键说明。
