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

复制订阅 URL、Clash YAML 或节点分享链接，然后点击「一键导入」。支持 HTTP(S) 订阅中的内联节点和文本或 Base64 节点列表，以及 `ss://`、`trojan://`、`socks5://`、`vless://`、`vmess://`。导入会合并节点并保留已有规则，列出部分跳过原因。完整的 HopWay JSON 会替换当前配置。运行中的内核需重启以应用；想让所有代理请求使用导入节点，可在「概览」切换到全局模式并选择节点。

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

本版本处理 TCP 代理流量。Clash 策略组、规则和远程节点集不会随节点导入。本版本暂不支持订阅自动刷新、UDP、TUN、REALITY、Vision、WebSocket、gRPC、Shadowsocks 2022 和插件协议。

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
