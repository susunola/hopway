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

复制订阅 URL、Clash YAML 或节点分享链接，然后点击「一键导入」。支持 HTTP(S) 订阅中的内联节点和文本或 Base64 节点列表，以及 `ss://`、`trojan://`、`socks5://`、`vless://`、`vmess://`。导入会合并节点并保留已有规则，列出部分跳过原因。完整的 HopWay JSON 会替换当前配置。运行中的内核可调用 `POST /reload` 热重载，或重启以应用；想让所有代理请求使用导入节点，可在「概览」切换到全局模式并选择节点。

也可以在「配置」插入模板，填写服务器和认证信息后校验并保存。支持这些 TCP 出站：

| `type` | 字段 |
| --- | --- |
| `socks5` | `name`、`server`，可选 `username` 和 `password` |
| `http` | `name`、`server`，可选 Basic 认证 `username`、`password` |
| `https` | 同 HTTP，外加 TLS。可选 `serverName`、`caPEM` |
| `trojan` | `name`、`server`、`password`。可选 `serverName`、`caPEM` |
| `vless` / `vmess` | `name`、`server`、`uuid`，可选 `tls`、`serverName`、`caPEM`。VMess 使用 AEAD，可选 `cipher` |
| `shadowsocks` | `name`、`server`、`password`、`cipher`，支持 `aes-128-gcm`、`aes-256-gcm` |

`server` 填 `host:port`。IPv6 地址需要方括号。TLS 默认验证系统信任和服务器名称。自建 CA 可把 PEM 文本作为节点的 `caPEM`。HTTP 和 SOCKS5 上游的用户名和密码会以未加密的协议传给上游。应用把配置和节点密码保存在用户目录的 JSON 文件里，配置文件权限为 `0600`。

```json
{
  "socksPort": 1080,
  "httpPort": 8080,
  "mode": "rule",
  "selected": "my-node",
  "nodes": [
    { "name": "my-node", "type": "socks5", "server": "proxy.example.com:1080" }
  ],
  "rules": [
    { "type": "domain", "value": "blocked.example", "via": "REJECT" },
    { "type": "domain-suffix", "value": "example.org", "via": "SELECT" },
    { "type": "ip-cidr", "value": "192.168.0.0/16", "via": "DIRECT" },
    { "type": "match", "via": "DIRECT" }
  ]
}
```

- `rule` 采用第一个匹配的规则，未匹配时走 `DIRECT`。`SELECT` 使用当前选定出站。
- `global` 把所有连接交给选定出站，`direct` 强制直连。
- 域名规则使用客户端提交的目标名，IP 网段规则匹配客户端直接提交的 IP。`socks5h` 会把域名提交给内核。
- 端口可填 `0`，由系统分配端口。在「概览」可以查看实际值。

本版本处理 TCP 代理流量。Clash 策略组、规则和远程节点集不会随节点导入。本版本暂不支持 UDP、TUN、REALITY、Vision、WebSocket、gRPC、Shadowsocks 2022 和插件协议。

## 订阅、用量和故障切换

用订阅 URL 导入时，内核会把订阅记进配置的 `subscriptions`，并给它带来的节点标上 `subscription`。订阅服务器若返回 `Subscription-Userinfo` 响应头，其中的已用上传、已用下载、总量和到期时间也会一并保存。再次导入同一个 URL 即刷新：先移除该订阅原有的节点，再导入新节点。选定出站或规则若指向已消失的节点，会分别改为 `AUTO` 和 `SELECT`，并在 `notes` 里说明。托管运行时，内核每 6 小时自动刷新一次订阅，写回配置后热重载。也可以用 `-refresh -config <路径>` 手动刷新全部订阅。

`AUTO` 是内置的虚拟出站，可以用作 `selected` 或规则的 `via`。它按 `nodes` 的顺序（即优先级）使用第一个可用节点：

- 新连接失败时，在同一次请求里依次换下一个节点重试，最多 3 个。只有后面的节点连通了，前面失败的节点才会被标为不可用，所以目标网站本身连不上时，不会误判节点故障。
- 托管运行时，内核每分钟通过每个节点请求一次 `http://www.gstatic.com/generate_204`，记录延迟。连续失败两次才标为不可用；不可用的节点恢复后，`AUTO` 自动切回优先级更高的节点。
- 流量用完或已过期的订阅，其节点会被 `AUTO` 跳过，除非已没有其他节点可用。
- 所有节点都不可用时，优先尝试最近一次连接成功过的节点。

首次导入节点时，若选定出站仍是 `DIRECT`，会改为 `AUTO`。

用量按出站累计。内核每 10 秒记一次，按本地日期保存最近 120 天，每分钟及退出时写入配置旁边的 `usage.json`（可用 `-usage` 改路径）。

### 控制接口

`-managed` 启动时，内核在标准输出打印一行 JSON：`control`、`token`、`socks`、`http`。所有请求都需要带上 `Authorization: Bearer <token>`。标准输入关闭后内核退出。

| 接口 | 说明 |
| --- | --- |
| `GET /status` | 当前状态。见下文字段说明 |
| `PUT /policy` | `{"mode":"rule","selected":"AUTO"}`，只对本次运行生效 |
| `POST /check` | 立即测速全部节点，返回 202，结果在下一次 `/status` 中体现 |
| `POST /reload` | 重读配置文件并热重载，不断开现有连接。保留当前模式和选定出站（若仍有效），以及各节点的健康状态和流量计数 |
| `POST /refresh` | 刷新全部订阅，或用 `?name=<订阅名>` 只刷新一个。返回 `{"updated":[],"failed":{},"notes":[]}`，有订阅刷新成功时会写回配置并热重载 |
| `GET /usage?days=14` | `{"days":[{"date":"2026-11-07","outbounds":{"<出站名>":{"sent":0,"received":0}}}]}`，按日期从旧到新排列，不传 `days` 返回全部 |

`/status` 返回的字段：

- `policy`：当前模式和选定出站。
- `auto`：`AUTO` 当前解析到的节点。
- `active`：活动连接数。
- `revision`：配置每热重载一次加 1。UI 看到它变化时，应重新读取配置文件。
- `subscriptions`：同配置中的订阅列表，单位为字节，`expire` 和 `updated` 为 Unix 秒，`0` 表示订阅未提供。
- `nodes`：出站列表，依次为 `AUTO`、`DIRECT`、`REJECT` 和各节点。每项含 `name`、`type`、`subscription`、`health`（`ok`、`down` 或空，空表示未测）、`latency`（毫秒）、`spent`（套餐已用完或过期）、`sent`、`received`（本次运行累计字节）。
- `connections`：最近的连接记录。经 `AUTO` 的连接，`via` 是实际使用的节点，`rule` 末尾带 ` · auto`。

实时网速可以用相邻两次 `/status` 中各节点 `sent` 和 `received` 的差值计算。

## 从源码构建

内核使用 Go 1.24 或更高版本，使用 [sing-vmess](https://github.com/SagerNet/sing-vmess) 的 VLESS／VMess 编解码（GPL-3.0-or-later）和 [Go YAML v3](https://pkg.go.dev/go.yaml.in/yaml/v3) 解析配置。App 构建需要带 macOS SDK 的 Xcode 工具链，目标 macOS 14 或更高版本。构建脚本打包本机架构的 App 并做本地临时签名。

```bash
go run .                              # 单独运行 Go 内核
go run . -check -config /path/config.json
./build-app.sh                        # 生成 ../HopWay.app
```

阅读顺序可从 `main.go` 开始，再看 `internal/socks5` 和 `internal/httpproxy` 如何接收流量，`internal/engine` 如何分流和统计，最后看 `internal/outbound` 以及 `ui/CoreModel.swift`。控制接口只监听本机随机端口，每次运行产生新的令牌。界面关闭内核子进程的标准输入后，内核退出。

协议依据见 [SOCKS5](https://www.rfc-editor.org/rfc/rfc1928)、[SOCKS5 用户名密码认证](https://www.rfc-editor.org/rfc/rfc1929.html)、[HTTP CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#name-connect)、[Trojan](https://trojan-gfw.github.io/trojan/protocol) 和 [Shadowsocks AEAD](https://shadowsocks.org/doc/aead.html)。

面向日常使用的产品差距和验收标准见 [竞品对比与路线](ROADMAP.md)。
