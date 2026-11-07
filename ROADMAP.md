# HopWay 竞品对比与路线

先把「导入订阅 → 选到可用节点 → 接管浏览器 → 出问题能恢复」做成一条可靠路径。当前版本适合验证内核和 UI，距离日常替代成熟客户端，差距主要在订阅语义、网络接管和故障恢复。

| 对标产品 | 值得借鉴 | HopWay 的差距 |
| --- | --- | --- |
| Clash Verge Rev + Mihomo | 配置管理、订阅更新、可视化节点和规则、系统代理和 TUN | 目前只从 Clash 配置导入内联节点，缺少策略组、远程节点集、更新及系统代理开关。[Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) · [订阅更新](https://github.com/clash-verge-rev/clash-verge-rev/blob/dev/PRIVACY.md) |
| sing-box | 广泛的出站协议和传输变体，选择及测速出站 | VLESS/VMess 目前只覆盖基础 TCP 和标准 TLS。优先补常用 WebSocket，以及 VLESS 的 REALITY + Vision，再根据测试订阅里的覆盖率排 Hysteria2、TUIC 和其他变体。[sing-box 出站文档](https://sing-box.sagernet.org/configuration/outbound/) · [Mihomo 传输文档](https://wiki.metacubex.one/en/config/proxies/transport/) |
| Surge Mac | Network Extension 增强模式、按应用分流、请求诊断和策略解释 | 目前仅记录目标、命中规则和流量。下一步可将失败拆成 DNS、TCP、TLS、认证和转发阶段，让用户看懂哪一步出了问题。[增强模式](https://manual.nssurge.com/features/enhanced-mode.html) · [策略解释](https://manual.nssurge.com/tools/cli.html) |

1. **日常可用。** 增加可恢复的系统代理开关、订阅刷新、上一次可用配置、节点可用性检测。用真实订阅的脱敏样本做回归。验收时分别模拟配置损坏、内核退出、换 Wi-Fi 和睡眠唤醒，确认浏览器可恢复联网，原代理设置能还原。
2. **兼容主流订阅。** 支持策略组、规则集、远程节点集和按需更新。协议按「协议 × 传输 × TLS」列出可用组合。测试应使用独立服务端互通，覆盖鉴权失败、配置不受支持和节点失效后的切换。
3. **全局接管与 macOS 体验。** 用 Network Extension 做 TUN，处理 UDP、DNS、IPv6、局域网旁路和网络切换，再考虑签名、公证和升级。诊断面板应说明谁发起连接、命中什么规则、经过哪些节点、在哪一步失败。[Apple 部署说明](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)

每个阶段持续记录导入成功率、首个代理请求成功耗时、网络切换后的恢复时间和连接失败原因。先测基线，再设目标。若考虑发布给其他用户，先确定 Go 内核所用协议库的授权和分发方案。

## 进度（2026-11）

已完成：

- 协议层改为可插拔后端，默认 sing-box 1.14。新增 VLESS REALITY + Vision、WebSocket、gRPC、HTTP/2、HTTPUpgrade、Hysteria2（含端口跳跃和 salamander 混淆）、TUIC、AnyTLS、Shadowsocks 2022、SS 插件和链式代理。`hopway_native` 构建标签保留原来的小型实现。
- 8 种协议与独立运行的 sing-box 服务端做端到端互通测试，使用自签证书和本地 REALITY 握手目标，覆盖单次写入超过 64 KB 的情况。测试中发现并在 HopWay 侧绕过了两个上游缺陷：sing-anytls 单次写入超过 65535 字节时会把流写坏；sing-shadowsocks2 在边读边写时，SS2022 握手存在数据竞争，会偶发 `bad request salt`。同时修复了服务端先发言（SSH、SMTP）的目标在惰性握手协议下会卡住的问题。
- 支持 `select`、`url-test`、`fallback` 策略组（可嵌套），按配置定期测速。节点在连接时失败会被立即标记为不可用；节点本身故障时，同一次请求内自动换成员重试。
- 导入 Clash 的 `proxy-groups` 和 `rules`。
- 规则匹配改为建立索引：十万条规则时每次匹配约 130 ns，不分配内存。新增 `domain-keyword` 和 `noResolve`，按需惰性解析域名。
- 诊断：记录每条连接经过的组路径、实际服务器，以及 DNS、连接、握手、首字节的耗时；失败时标出阶段（`dns`、`connect`、`handshake`、`upstream`、`route`）。

下一步：

1. 不用 TUN 也能识别发起连接的进程：在 macOS 上通过 `net.inet.tcp.pcblist_n` 和 `proc_pidpath`，由本地连接的源端口找到进程，用于诊断显示和 `process-name` 规则。
2. 规则集（远程 `RULE-SET`、GeoSite/GeoIP 的 `.srs` 文件）和订阅定时刷新，刷新失败时保留上一次可用的配置。
3. 可恢复的系统代理开关，覆盖睡眠唤醒、网络切换（切换后清空 DNS 缓存、重新测速）以及内核崩溃后的还原。
4. 用 Network Extension 做 TUN，处理 UDP、DNS 和 IPv6。
