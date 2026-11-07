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
