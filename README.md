# HopWay · 顺路

从 SOCKS5 TCP 代理扩展出的原生 macOS 客户端。Go 内核负责转发和分流，SwiftUI 控制台负责配置、启停、切换出站和查看连接。

## 运行

打开旁边的 **HopWay.app**，点击 **启动代理**。默认 SOCKS5 监听 `127.0.0.1:1080`，HTTP 监听 `127.0.0.1:8080`。两种入站都只接受本机连接。默认规则使用直连出站。

```bash
curl --noproxy "" --socks5-hostname 127.0.0.1:1080 https://example.com/
curl --noproxy "" --proxy http://127.0.0.1:8080 https://example.com/
```

系统代理由 macOS 的网络设置管理。进入「系统设置 → 网络 → 当前网络 → 详细信息 → 代理」。对于 Web 代理和安全 Web 代理，填写 HTTP 监听地址。对于 SOCKS 代理，填写 SOCKS5 监听地址。停用内核前可以恢复原设置。浏览器或单个应用也可以独立设置代理。

## 节点和规则

复制订阅 URL、Clash YAML 或节点分享链接，然后点击「一键导入」。支持 HTTP(S) 订阅、文本或 Base64 节点列表，以及 `ss://`（含 SIP002 和旧式 Base64）、`trojan://`、`socks5://`、`vless://`、`vmess://`、`hysteria2://`（`hy2://`）、`tuic://`、`anytls://`。Clash 配置里的 `proxy-groups` 和 `rules` 会一并导入，替换现有的分组和规则；其中 `load-balance` 组按 `url-test` 处理，`GEOIP`、`RULE-SET` 等规则和远程节点集暂不导入，导入结果会说明跳过了哪些。完整的 HopWay JSON 会替换当前配置。不导入跳过证书验证（`skip-cert-verify`、`allowInsecure`）的节点。

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
    { "type": "ip-cidr", "value": "192.168.0.0/16", "via": "DIRECT", "noResolve": true },
    { "type": "ip-cidr", "value": "203.0.113.0/24", "via": "Backup" },
    { "type": "match", "via": "SELECT" }
  ]
}
```

- `select` 由用户选择成员；`url-test` 选测得延迟最低的成员，新成员要比当前成员快出 `toleranceMs` 以上才切换；`fallback` 选第一个可用成员。组可以嵌套。
- 自动组的成员按 `health` 定期测速。测速之外，节点在连接时出现 DNS、连接或握手失败也会立即标记为不可用。经过自动组的连接如果因节点本身失败，会在同一次请求内换下一个成员重试（最多 3 次），对应用透明。目标站点本身不可达时不会重试。
- `rule` 模式按顺序取第一条匹配的规则，未匹配时走 `DIRECT`。规则在加载时建立索引，十万条规则的匹配耗时仍在一微秒以内。`SELECT` 表示当前选定出站。
- 目标是域名时，只有当排在最前的候选规则是 IP 规则时，内核才解析这个域名（每次连接最多解析一次）；带 `noResolve` 的 IP 规则只匹配客户端直接提交的 IP。
- `global` 把所有连接交给选定出站，`direct` 强制直连。端口可填 `0`，由系统分配。

### 连接诊断

每条连接都记录经过的策略组路径、实际使用的节点和服务器，以及 DNS、连接、握手、首字节各阶段的耗时。失败的连接会标出失败阶段：`dns`（解析不到服务器）、`connect`（服务器拒绝连接或超时）、`handshake`（TLS、证书或代理协议握手失败）、`upstream`（代理已连上，但没有任何响应就关闭了连接。VLESS、Trojan 等协议的认证错误通常表现为这种情况）、`route`（被规则拦截）。gRPC、QUIC 等多路复用的连接会标为 `shared`，因为它们复用已有会话，没有单独的建连耗时。把鼠标停在控制台连接表的目标或状态上，可以查看这些信息。

本版本处理 TCP 代理流量。UDP、TUN 和订阅自动刷新还没有做。

## 从源码构建

内核需要 Go 1.25.5 或更高版本（sing-box 1.14 的要求），协议栈来自 [sing-box](https://github.com/SagerNet/sing-box)（GPL-3.0-or-later），配置解析使用 [Go YAML v3](https://pkg.go.dev/go.yaml.in/yaml/v3)。用 `HOPWAY_TAGS=hopway_native ./build-app.sh` 可以构建不含 sing-box 的版本，它只支持基础 TCP 协议，仍然依赖 GPL 的 sing-vmess。App 构建需要带 macOS SDK 的 Xcode 工具链，目标 macOS 14 或更高版本。构建脚本打包本机架构的 App 并做本地临时签名。

```bash
TAGS=with_quic,with_utls,badlinkname,tfogo_checklinkname0
go run -tags $TAGS -ldflags=-checklinkname=0 .          # 单独运行 Go 内核
go run -tags $TAGS -ldflags=-checklinkname=0 . -check -config /path/config.json
go test -tags $TAGS -ldflags=-checklinkname=0 ./...      # 含 8 种协议的端到端互通测试
./build-app.sh                                         # 生成 ../HopWay.app
```

阅读顺序可从 `main.go` 开始，再看 `internal/socks5` 和 `internal/httpproxy` 如何接收流量，`internal/engine` 如何分流（`rules.go`）、选组和测速（`groups.go`）、记录诊断，`internal/backend` 如何把节点交给 sing-box 并测量各阶段耗时，最后看 `internal/importer` 和 `ui/CoreModel.swift`。控制接口只监听本机随机端口，每次运行产生新的令牌，提供 `GET /status`、`PUT /policy`、`PUT /groups/{name}`（切换 select 组）和 `POST /probe`（立即测速全部节点）。界面关闭内核子进程的标准输入后，内核退出。

协议依据见 [SOCKS5](https://www.rfc-editor.org/rfc/rfc1928)、[SOCKS5 用户名密码认证](https://www.rfc-editor.org/rfc/rfc1929.html)、[HTTP CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#name-connect)、[Trojan](https://trojan-gfw.github.io/trojan/protocol) 和 [Shadowsocks AEAD](https://shadowsocks.org/doc/aead.html)。

面向日常使用的产品差距和验收标准见 [竞品对比与路线](ROADMAP.md)。
