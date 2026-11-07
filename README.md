# HopWay · 顺路

从 SOCKS5 TCP 代理扩展出的原生 macOS 客户端。Go 内核负责转发和分流，SwiftUI 控制台负责配置、启停、切换出站和查看连接。

## 运行

打开 **~/Applications/HopWay.app**，点击 **启动代理**。默认 SOCKS5 监听 `127.0.0.1:1080`，HTTP 监听 `127.0.0.1:8080`。两种入站都只接受本机连接。默认规则使用直连出站。

```bash
curl --noproxy "" --socks5-hostname 127.0.0.1:1080 https://example.com/
curl --noproxy "" --proxy http://127.0.0.1:8080 https://example.com/
```

在「概览」或菜单栏中打开「设为系统代理」后，HopWay 会把所有已启用网络服务的 HTTP、HTTPS 和 SOCKS 代理指向自己，局域网和本机地址不走代理。也可以在配置里写 `"systemProxy": true`，让内核启动时自动开启。

- 改动之前，HopWay 先把每个网络服务原来的代理设置保存到 `cache/system-proxy-backup.json`。停止代理、退出 App 或内核收到 SIGTERM 时，都会按这份备份还原。如果 HopWay 被强制结束或崩溃，没来得及还原，下次启动时会先自动还原，并在界面上提示。
- 如果上次异常退出时留下了备份，HopWay 会一直沿用那份记录着你真实设置的备份，不会把 HopWay 自己的设置当成原始值覆盖进去。
- 开启期间新出现的网络服务（比如插上 USB 网卡）也会被设上代理。你在系统设置里手动改过的服务，HopWay 不会改回去。

### 增强模式（TUN）

打开「增强模式（TUN）」后，HopWay 会创建一块虚拟网卡（macOS 上是 utun），接管整台电脑的流量。不认系统代理的应用、命令行工具、游戏和 DNS 查询都会经过 HopWay，现有规则（包括进程规则）照常生效。也可以在配置里写 `"tun": { "enabled": true }`，让内核启动时自动开启。

- **权限**：只有创建网卡和设置路由需要 root。开启时，macOS 会弹出标准的管理员密码框，由一个只活几秒的特权助手（`mac-proxy-core -tun-helper`）创建 utun 并加好路由，再通过 Unix socket 把网卡交给以普通权限运行的内核，然后退出。内核关闭网卡时，路由会随网卡一起消失，不会留下残余。
- **免密服务**：在 TUN 开关下点「安装免密服务」，输入一次密码即可。之后再开启 TUN，就不会再弹出密码框。这个服务是一个 launchd 守护进程（`/Library/LaunchDaemons/com.hopway.tun-service.plist`），程序文件复制到 root 所有的 `/Library/PrivilegedHelperTools/` 下，普通用户无法替换。它只做一件事：创建网卡并交出去。它只接受安装者的请求，请求者的 uid 由内核根据对端凭证核验，无法伪造。每交出一次网卡，服务就退出一次，再由 launchd 重新拉起，所以不会在 root 进程里积累状态。版本不一致时，服务会拒绝请求并提示重新安装。点「卸载免密服务」可以删除它。
- **DNS**：所有 DNS 查询（UDP 53）都由内核应答。A 记录返回 198.18.0.0/15 段里的 fake-ip，之后的连接再映射回原来的域名，所以规则看到的是域名，域名交给代理节点去解析，不会泄漏 DNS。AAAA 记录返回空，`.local` 等本地名字和其他类型的查询转发给开启前的系统 DNS。开启时，系统 DNS 会被临时指向网卡，因为局域网内的 DNS 服务器走直连路由，会绕过隧道；关闭或崩溃后的下次启动时会还原。
- **IPv6**：写 `"tun": { "enabled": true, "ipv6": true }` 可以同时接管 IPv6：网卡会配上 IPv6 地址和 `::/0` 路由，AAAA 查询也返回 fake-ip（fc00::/18）。默认关闭，此时 AAAA 查询返回空，应用走 IPv4 进入隧道。直接使用 IPv6 字面地址的连接，在默认情况下不经过隧道。
- **嗅探**：应用直接连 IP 时，内核会从 TLS ClientHello（SNI）或 HTTP Host 头里取出域名，用于匹配规则。
- **防止回环**：内核自己发出的连接（连接节点、直连、DNS 查询）都绑定在物理网卡上，不会再进入隧道。内核自己做 DNS 查询时，直接发给开启前的上游服务器。
- **UDP**：和 TCP 一样按规则分流，可以直连，也可以经由代理节点转发。QUIC、游戏和语音通话都能走代理。规则选中的出站如果不支持 UDP，这个流就会被丢弃，QUIC 会自动改用 TCP。

内核会自己检测网络切换和睡眠唤醒，不依赖系统通知：它比较网卡地址，并对比墙上时钟和单调时钟（Mac 睡眠时单调时钟会停）。检测到变化后，内核会清空 DNS 缓存，关闭已经失效的空闲会话和多路复用会话（gRPC、QUIC 等），重新给自动策略组测速。最近的网络事件可以在 `/status` 的 `network` 字段里看到。

## 节点和规则

复制订阅 URL、Clash YAML 或节点分享链接，然后点击「一键导入」。粘贴的是订阅 URL 时，HopWay 会把它记为一个**订阅**，节点不写进配置文件，而是保存为缓存快照：默认每 12 小时经由 HopWay 自己的路由自动更新一次，更新后立即热加载，已经打开的连接不会中断。更新失败时继续使用上一份快照。订阅带来的策略组和规则排在你自己的规则之后，你自己的 `match` 规则始终排在最后。支持 HTTP(S) 订阅、文本或 Base64 节点列表，以及 `ss://`（含 SIP002 和旧式 Base64）、`trojan://`、`socks5://`、`vless://`、`vmess://`、`hysteria2://`（`hy2://`）、`tuic://`、`anytls://`。Clash 配置里的 `proxy-groups` 和 `rules` 会一并导入，替换现有的分组和规则；其中 `load-balance` 组按 `url-test` 处理，`GEOIP`、`RULE-SET` 等规则和远程节点集暂不导入，导入结果会说明跳过了哪些。完整的 HopWay JSON 会替换当前配置。不导入跳过证书验证（`skip-cert-verify`、`allowInsecure`）的节点。

### 协议

内核默认使用 [sing-box](https://github.com/SagerNet/sing-box) 协议栈，节点类型如下：

| `type` | 必填字段 | 说明 |
| --- | --- | --- |
| `socks5` | `server` | 可选 `username`、`password` |
| `http` / `https` | `server` | 可选 Basic 认证；`https` 外加 TLS |
| `shadowsocks` | `server`、`cipher`、`password` | AEAD 与 2022（`2022-blake3-aes-128-gcm` 等），插件 `obfs-local`、`v2ray-plugin` |
| `trojan` | `server`、`password` | 始终 TLS |
| `vless` | `server`、`uuid` | 可选 `tls`；Vision、REALITY 见 `options` |
| `vmess` | `server`、`uuid` | AEAD，可选 `cipher` |
| `hysteria2` | `server`、`password` | QUIC；可在 `options` 设置 `obfs`、`server_ports` 端口跳跃、带宽 |
| `tuic` | `server`、`uuid`、`password` | QUIC，默认 ALPN `h3` |
| `anytls` | `server`、`password` | 始终 TLS |

公共字段：`name`、`serverName`（SNI）、`caPEM`（自建 CA）。`options` 是一个 JSON 对象，会合并到生成的 [sing-box 出站](https://sing-box.sagernet.org/configuration/outbound/)上，可以设置传输（`ws`、`grpc`、`http`、`httpupgrade`）、`flow`、`tls.reality`、`tls.utls`、`multiplex` 等字段。`options.detour` 填另一个节点名可以组成链式代理。

```json
{
  "name": "sg-reality", "type": "vless", "server": "sg.example.com:443",
  "uuid": "…", "tls": true, "serverName": "www.apple.com",
  "options": {
    "flow": "xtls-rprx-vision",
    "tls": { "utls": { "enabled": true, "fingerprint": "chrome" },
             "reality": { "enabled": true, "public_key": "…", "short_id": "0123abcd" } }
  }
}
```

### 策略组、规则和测速

```json
{
  "mode": "rule",
  "selected": "Proxy",
  "nodes": [ … ],
  "groups": [
    { "name": "Proxy", "type": "select", "members": ["Auto", "sg-reality", "DIRECT"] },
    { "name": "Auto", "type": "url-test", "members": ["sg-reality", "jp-hy2"], "toleranceMs": 50 },
    { "name": "Backup", "type": "fallback", "members": ["jp-hy2", "sg-reality"] }
  ],
  "health": { "url": "https://www.gstatic.com/generate_204", "intervalSec": 300 },
  "rules": [
    { "type": "domain-keyword", "value": "ads", "via": "REJECT" },
    { "type": "domain-suffix", "value": "openai.com", "via": "Auto" },
    { "type": "process-bundle-id", "value": "com.google.Chrome", "via": "Proxy" },
    { "type": "process-name", "value": "Telegram", "via": "Proxy" },
    { "type": "process-path", "value": "/Applications/Steam.app/", "via": "DIRECT" },
    { "type": "ip-cidr", "value": "192.168.0.0/16", "via": "DIRECT", "noResolve": true },
    { "type": "ip-cidr", "value": "203.0.113.0/24", "via": "Backup" },
    { "type": "match", "via": "SELECT" }
  ]
}
```

- `select` 由用户选择成员；`url-test` 选测得延迟最低的成员，新成员要比当前成员快出 `toleranceMs` 以上才切换；`fallback` 选第一个可用成员。组可以嵌套。
- 自动组的成员按 `health` 定期测速。测速之外，节点在连接时出现 DNS、连接或握手失败也会立即标记为不可用。经过自动组的连接如果因节点本身失败，会在同一次请求内换下一个成员重试（最多 3 次），对应用透明。目标站点本身不可达时不会重试。
- 默认测速目标无法访问时，HopWay 会通过同一个节点试用备用目标。自定义 `health.url` 时可另填 `health.fallbackUrl`。整批测速都失败时，节点标为待复测，保留上一次确认的健康状态。
- `rule` 模式按顺序取第一条匹配的规则，未匹配时走 `DIRECT`。规则在加载时建立索引，十万条规则的匹配耗时仍在一微秒以内。`SELECT` 表示当前选定出站。
- 目标是域名时，只有当排在最前的候选规则是 IP 规则时，内核才解析这个域名（每次连接最多解析一次）；带 `noResolve` 的 IP 规则只匹配客户端直接提交的 IP。
- `process-name` 匹配发起连接的应用：可以填可执行文件名，也可以填 `.app` 包名（不区分大小写）。例如填 `Google Chrome`，就能匹配它的所有 Helper 进程。`process-path` 匹配可执行文件的完整路径；以 `/` 结尾时匹配该目录下的所有程序。识别进程不需要 TUN：内核根据本机应用连接到 HopWay 时使用的端口，在系统连接表（macOS 上是 `net.inet.tcp.pcblist_n`）里找到对应的进程。只有当排在最前的候选规则是进程规则时，内核才会去查进程；其他连接在建立之后才补查，只用于诊断显示，不增加连接延迟。
- `process-bundle-id` 匹配 macOS 应用最外层 `.app` 的标识符，例如 `com.google.Chrome`。嵌套 Helper 使用同一个应用标识，应用移动目录后也能继续匹配。无法确认应用身份时，按规则顺序继续匹配。连接详情会显示已识别的应用标识。
- `global` 把所有连接交给选定出站，`direct` 强制直连。端口可填 `0`，由系统分配。

### 规则集与 GeoIP / GeoSite

```json
"ruleSets": [
  { "name": "geoip-cn", "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs" },
  { "name": "reject", "url": "https://example.com/reject.txt", "behavior": "domain", "intervalSec": 86400 },
  { "name": "mine", "path": "/Users/me/rules.yaml", "behavior": "classical" }
],
"rules": [
  { "type": "rule-set", "value": "reject", "via": "REJECT" },
  { "type": "rule-set", "value": "geoip-cn", "via": "DIRECT" }
]
```

- 支持 sing-box 二进制 `.srs`（GeoIP、GeoSite 都用这种格式），以及 Clash 规则集的 `yaml` 和 `text` 格式。Clash 格式的 `behavior` 可以是 `domain`、`ipcidr` 或 `classical`。格式默认按文件扩展名判断。
- 远程规则集缓存在配置目录的 `cache/` 下，离线也能启动。下载在后台进行，同样走 HopWay 的路由，默认每天检查一次；更新失败时保留旧版本，并在状态里显示错误。
- 导入 Clash 配置时，`RULE-SET` 及对应的 `rule-providers`、`GEOIP`、`GEOSITE` 都会转成规则集，`GEOIP,LAN` 会展开成内网网段。暂不支持 `mrs` 格式和本地文件类型的 provider。
- 规则集里的 IP 条目与 `ip-cidr` 规则一样：目标是域名时按需解析，`noResolve` 时不解析。

### 配置的可靠性

- 保存配置后会立即热加载，不用重启内核：新连接走新配置，已经打开的连接留在旧实例上，直到结束。运行中切换的模式、选定出站和 select 组的选择在热加载后保留。只有改了监听端口才需要重启。
- 每次加载成功后，配置都会备份到 `cache/last-good.json`。之后配置文件损坏或校验失败时，内核会改用这份备份启动，并在界面上提示，而不是直接无法启动。`-check` 校验不会使用备份。

### 连接诊断

每条连接都记录发起它的应用、经过的策略组路径、实际使用的节点和服务器，以及 DNS、连接、握手、首字节各阶段的耗时。失败的连接会标出失败阶段：`dns`（解析不到服务器）、`connect`（服务器拒绝连接或超时）、`handshake`（TLS、证书或代理协议握手失败）、`upstream`（代理已连上，但没有任何响应就关闭了连接。VLESS、Trojan 等协议的认证错误通常表现为这种情况）、`route`（被规则拦截）。gRPC、QUIC 等多路复用的连接会标为 `shared`，因为它们复用已有会话，没有单独的建连耗时。把鼠标停在控制台连接表的目标或状态上，可以查看这些信息。

### UDP

UDP 流量同样按规则、策略组和故障转移处理，并显示在连接表里（入站一栏标有「UDP」）。经由节点转发时，SS（含 2022）、Trojan、VLESS（含 REALITY 和 Vision）、VMess、Hysteria2、TUIC、AnyTLS 都和独立的服务端做过 UDP 互通测试。UDP 有两个入口：TUN 模式，以及 SOCKS5 的 UDP ASSOCIATE。后者让支持 SOCKS5 UDP 的应用不开 TUN 也能用 UDP。UDP ASSOCIATE 只接收来自控制连接所在 IP 的数据报，不支持分片，控制连接关闭时这个关联随之结束。

## 从源码构建

内核需要 Go 1.25.5 或更高版本（sing-box 1.14 的要求），协议栈来自 [sing-box](https://github.com/SagerNet/sing-box)（GPL-3.0-or-later），配置解析使用 [Go YAML v3](https://pkg.go.dev/go.yaml.in/yaml/v3)。用 `HOPWAY_TAGS=hopway_native ./build-app.sh` 可以构建不含 sing-box 的版本，它只支持基础 TCP 协议，仍然依赖 GPL 的 sing-vmess。App 构建需要带 macOS SDK 的 Xcode 工具链，目标 macOS 14 或更高版本。构建脚本打包本机架构的 App 并做本地临时签名。

```bash
TAGS=with_quic,with_utls,badlinkname,tfogo_checklinkname0
go run -tags $TAGS -ldflags=-checklinkname=0 .          # 单独运行 Go 内核
go run -tags $TAGS -ldflags=-checklinkname=0 . -check -config /path/config.json
go test -tags $TAGS -ldflags=-checklinkname=0 ./...      # 含 8 种协议的端到端互通测试
./build-app.sh                                         # 安装到 ~/Applications/HopWay.app
```

阅读顺序可从 `main.go` 开始，再看 `internal/socks5` 和 `internal/httpproxy` 如何接收流量，`internal/engine` 如何分流（`rules.go`）、选组和测速（`groups.go`）、记录诊断，`internal/backend` 如何把节点交给 sing-box 并测量各阶段耗时，最后看 `internal/importer` 和 `ui/CoreModel.swift`。控制接口只监听本机随机端口，每次运行产生新的令牌，提供 `GET /status`、`PUT /policy`、`PUT /groups/{name}`（切换 select 组）、`POST /probe`（立即测速全部节点）、`POST /reload`（热加载配置）、`POST /subscriptions/refresh` 和 `POST /rulesets/refresh`（立即更新）。界面关闭内核子进程的标准输入后，内核退出。

协议依据见 [SOCKS5](https://www.rfc-editor.org/rfc/rfc1928)、[SOCKS5 用户名密码认证](https://www.rfc-editor.org/rfc/rfc1929.html)、[HTTP CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#name-connect)、[Trojan](https://trojan-gfw.github.io/trojan/protocol) 和 [Shadowsocks AEAD](https://shadowsocks.org/doc/aead.html)。

面向日常使用的产品差距和验收标准见 [竞品对比与路线](ROADMAP.md)。
