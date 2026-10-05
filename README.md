# ssh-stream-gateway

在 Mac 上验证口令，再通过系统 OpenSSH 连接白名单内的远端服务器。云端 Rust 客户端通过 **HTTPS + HTTP/2 双向流** 收发 stdin、stdout、stderr 和退出码。SSH 私钥留在 Mac，程序不会把私钥内容传给客户端。

```text
云端 CLI ── HTTPS / HTTP2（可经 HTTP(S) CONNECT 代理）── Mac gateway
                                                        │
                                                 /usr/bin/ssh
                                                        │
                                                  白名单 SSH 目标
```

这是一个小型单用户工具。支持 macOS/Linux，无 PTY；适合执行命令、传入脚本和长流输出。默认只监听 loopback；可改为具体的 WireGuard/私网地址。TLS 始终必需，不提供明文或跳过证书校验选项。

## 构建

需要 Rust 1.88+、系统 OpenSSH。建议当前 stable Rust。此仓库不包含密钥、真实服务器配置或部署后门。

```sh
cargo build --locked --release
cargo test --locked
python3 -m unittest discover -s tests -p test_launchd_templates.py
cargo clippy --locked --all-targets -- -D warnings
```

二进制为 `target/release/ssh-stream-gateway`。在 Mac 上从源码构建会得到当前 Mac 架构的原生版本。不提供自动安装脚本。CI 在测试通过后为每个平台生成含二进制、构建提交和 SHA256 的短期 artifact；只下载你核对过提交且全部检查成功的构建。artifact 不是已签名/公证的 macOS 安装包，下载后仍需按 Mac 的正常安全提示由你确认运行。也可以按上面的命令直接在 Mac 构建。

## Mac 服务端准备

1. 将 `examples/server.toml` 复制到仓库外的私人目录，例如 `~/.config/ssh-stream-gateway/server.toml`
2. 配置服务端 TLS 证书及对应密钥，证书 SAN 必须匹配云端使用的 DNS 名或 IP。私有 CA 可以使用，客户端单独信任其 CA/证书。TLS 私钥和 SSH 私钥都留在 Mac
3. 运行下面的交互命令，输入自己选取的口令。建议六个独立随机词，用空格或连字符连接。不要使用简单短密码；程序要求 20–256 个可打印 ASCII 字符，并不验证这些词是否随机

```sh
./target/release/ssh-stream-gateway hash-password
```

4. 将输出的 Argon2id PHC 哈希填写到服务端 `password_hash`。服务端不保存明文口令。不要把口令直接放进命令行、环境变量、Git 或聊天记录
5. 每个 `[targets.ALIAS]` 固定目标 host、port、user、identity_file、known_hosts_file。只使用已通过可信渠道核对的主机密钥；不要把未经核验的 `ssh-keyscan` 输出当作已验证的密钥。非默认端口需要对应的 `[host]:port` known_hosts 项
6. `identity_file` 必须是特定身份的绝对路径。若为加密私钥，预先由你在 Mac 本地解锁至 SSH agent，再在服务端指定 `identity_agent` 的绝对 socket 路径。也可以指定对应公钥文件由 agent 完成签名。默认不使用 agent；永不转发 agent。不要为了自动化复制或解密私钥
7. 将配置、TLS 密钥与其他私人文件放在权限 0700 的目录中，文件限制为 0600。确保此目录与代码仓库分离。绑定 WireGuard 地址时，另外由你配置 WG 路由和防火墙，只允许预期客户端；程序本身不修改网络设置

```sh
./target/release/ssh-stream-gateway check-config --config /ABSOLUTE/PATH/server.toml
./target/release/ssh-stream-gateway serve --config /ABSOLUTE/PATH/server.toml
```

`check-config` 检查配置语法、安全参数和白名单格式，不测试证书/密钥是否可用，也不登录 SSH。`serve` 始终保持前台运行，适合由 macOS launchd 管理；登录后自动启动的 LaunchAgent 模板与安装/停止步骤见 [macOS 服务说明](docs/MACOS-SERVICE.md)。模板不自动安装，也不会修改 WG 或防火墙。Ctrl-C/SIGTERM 在等待地址和正常服务时都可退出；正常服务退出还会清理本地 SSH 子进程。

### 等待 WireGuard 地址

配置与 TLS 先通过检查，再绑定精确的 `bind` IP/端口。如果 OS 返回地址尚不可用（EADDRNOTAVAIL），进程按 1、2、4、8、16、30 秒退避，之后每 30 秒重试，直到地址出现或收到停止信号。不会改绑 `0.0.0.0`、其他接口或其他端口。首次等待打印一条提示，之后每分钟最多一条，避免 WG 延迟启动造成日志洪泛。IP 填错也会保持等待，需由你核对配置。

端口占用、权限错误、无效配置和 TLS 错误不会进入上述重试，会直接以非零状态退出。LaunchAgent 使用 `KeepAlive.SuccessfulExit=false` 与 `ThrottleInterval=60`，覆盖异常退出和 Rust panic；因此持续配置错误也会由 launchd 按受节流的频率重新尝试，直到修复或卸载该服务。请先检查配置和前台启动，发现反复错误时先停止服务再排查。干净退出返回 0，不触发此异常重启条件。

监听建立后的连接中断不会重放 SSH 命令，也不自动修改或重建 WG；网络恢复依赖你已有的 WG 配置。

## 云端客户端

将 `examples/client.toml` 复制到仓库外，填入 endpoint、可选 CA 公钥证书路径以及可选口令文件路径。配置和 CA 可以由你放到指定目录；**不要把 Mac 的 SSH 私钥或 TLS 私钥传到云端**。

- 不配置 `password_file`：每次从 `/dev/tty` 隐藏输入口令，stdin 仍留给远端命令
- 配置 `password_file`：使用自己创建的单独普通文件，可有结尾换行。必须由当前用户持有且权限为 0600/0400，不允许符号链接。文件内容是口令，不是服务端 Argon2 哈希

```sh
ssh-stream-gateway exec --config /ABSOLUTE/PATH/client.toml build 'uname -a'
printf 'hello\n' | ssh-stream-gateway exec --config /ABSOLUTE/PATH/client.toml build 'cat'
ssh-stream-gateway exec --config /ABSOLUTE/PATH/client.toml build 'sh -s' < script.sh
```

也可不用配置文件：

```sh
ssh-stream-gateway exec --endpoint https://gateway.example.invalid:8443 \
  --ca /ABSOLUTE/PATH/ca.pem build 'uname -a'
```

命令必须作为一个字符串传入。这个字符串有意交给**远端账户的 shell** 解释，支持管道、重定向等；不会在 Mac 本地 shell 执行。它不是命令沙箱：获得口令意味着可以用白名单远端账户执行任意命令。白名单只限制初始 SSH 登录目标；该远端账户仍可上传/执行程序，并按自身权限继续连接其他网络目标。不要给不可信用户共享此口令。

stdout/stderr 保持分离，二进制数据不做文本转换；每条流内部保持顺序，两条流之间没有全局先后顺序保证。正常返回远端 SSH 退出码；SSH 连接错误通常是 255，本地工具/协议错误是 125，网关超时是 124，客户端 Ctrl-C 是 130。远端命令也可能主动使用这些退出码，不能仅靠数字区分来源。若连接在 EXIT 帧前断开，执行结果未知；不会自动重试，避免重复执行有副作用的命令。

### 云端 HTTP 代理

HTTPS endpoint 使用 `HTTPS_PROXY`/`https_proxy`，缺省时使用 `ALL_PROXY`/`all_proxy`；`NO_PROXY`/`no_proxy` 可旁路匹配的目标。大写变量优先。HTTP_PROXY 仅适用于 HTTP origin，本工具不接受此类 origin，因此它单独存在时不会选择代理。

支持 `http://` 和 `https://` CONNECT 代理（包括代理 URL 内的 Basic 凭据）；不支持 SOCKS。代理凭据不会传给 origin 或打印进诊断。错误/不支持的显式代理配置会报错，不会悄悄直连。HTTPS 代理证书也必须可信。`--ca` 将证书加入系统信任根，作用于 origin 与 HTTPS 代理。无跳过 TLS 校验、重定向或应用层自动重试。

普通 HTTP/1 网关或会缓冲整个请求的反向代理不适用；必须保留真正的 HTTP/2 双向流。WG 打通 Mac 到目标服务器的路由，不等于云端到 gateway 的 HTTPS 路径已经可达；这两段网络需分别验证。

## 安全边界与限制

- 认证使用 HTTPS bearer 口令，服务端存 Argon2id 哈希。每次会话先认证，再检查目标，再启动 SSH
- 全局认证失败预算最多突发 5 次，之后每 12 秒恢复一次；成功认证返还一个额度。至多 2 个并行密码校验，默认 4 个会话，硬上限 32。认证洪泛可能暂时拒绝合法请求，这是保护单用户私网服务的取舍
- 只允许显式 loopback/RFC1918/IPv6 ULA 监听地址，拒绝公共/通配地址。不是互联网暴露的多租户服务；网络级访问控制仍必要。32 个连接的上限不是完整 DoS 防御
- OpenSSH 忽略用户/系统 ssh 配置；固定 identity、known_hosts、目标和选项；缺失身份时不回退到默认密钥。StrictHostKeyChecking 开启，禁止自动添加或更新 host key
- 禁止 SSH agent/X11/端口转发、ProxyCommand/ProxyJump、LocalCommand、ControlMaster 复用和客户端自定义 SSH 参数。密钥仅由本机 OpenSSH 使用
- 帧最大 16 KiB，双向队列有界并施加背压。握手、opening frame、SSH connect、空闲和总时长有限制。流停止消费会占用有限的会话额度，直到断连或超时
- Ctrl-C/断连/超时终止并回收 **Mac 上的 SSH 进程**。无法保证远端已脱离终端或忽略断连的后台任务停止，不能将取消当作事务回滚
- 不支持 PTY、终端 resize、交互式密码登录、原生 scp/sftp、任意 TCP 隧道、Mac 本地执行、多人权限或自动重连
- 远端 stdout/stderr 是不可信原始字节；向真实终端显示时，远端能发送终端控制序列，如使用普通 ssh 一样。敏感输出应重定向到受保护文件
- TLS、口令、哈希、private config、真实地址、private key 均不进入仓库。程序不记录口令、命令或流内容；不要启用会捕获 Authorization/body 的外部代理日志

## 验证

测试只使用 loopback、临时 TLS 测试证书/固定测试口令、假 SSH 子进程和系统 `ssh -G` 参数解析，不访问真实 SSH 服务器。另有模拟地址延迟出现的退避/日志限频/取消测试和真实进程的 SIGTERM/SIGINT、端口占用、缺失 TLS 材料启动测试。覆盖认证与白名单先于 spawn、默认身份回退防护、二进制 EOF、stdout/stderr、早退出、断连/取消清理、背压、并发/超时、TLS/证书/h2、HTTP(S) CONNECT 与代理配置。CI 在 Linux/macOS 上运行测试和 release 构建；实际 Mac SSH 身份、证书及 WG 连通性仍需部署时验收。

协议细节见 [PROTOCOL.md](PROTOCOL.md)。

## 可复用的 Linux 客户端恢复工具

可选的 [客户端安装与恢复 helpers](tools/client-recovery/README.md) 提供固定目标、校验和验证、交互式口令恢复和安全错误分类。示例只含占位配置，凭据目录和已构建二进制不进入仓库。
