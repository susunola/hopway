import Foundation
import SwiftUI

struct AdvancedSettingsDraft {
    struct Values: Equatable {
        var socksPort = "1080"
        var httpPort = "8080"
        var handshakeTimeout = ""
        var httpIdleTimeout = ""
        var systemProxy = false
        var tunEnabled = false
        var ipv6 = false
        var mtu = ""
        var probeURL = ""
        var fallbackURL = ""
        var probeInterval = ""
        var maxDialAttempts = ""
        var dialTimeout = ""
        var failoverTimeout = ""
        var probeTimeout = ""
        var probeConcurrency = ""
        var autoRouteInterval = ""
        var autoGainMS = ""
        var autoGainPercent = ""
        var autoConfirmations = ""
        var autoFailoverFailures = ""
        var autoRecoverySuccesses = ""
        var subscriptionRefresh = ""
        var ruleSetRefresh = ""
        var connectionLimit = ""
        var udpSessionLimit = ""
        var udpOpenLimit = ""
        var endpointDialLimit = ""
        var udpIdleTimeout = ""
        var tcpIdleTimeout = ""
        var connectionHistory = true
        var historyLimit = ""
        var historyRetention = ""
    }

    let source: String
    let original: Values
    var values: Values
    var error: String?

    init?(source: String) {
        guard let config = (try? JSONSerialization.jsonObject(with: Data(source.utf8))) as? [String: Any] else {
            return nil
        }
        let tun = config["tun"] as? [String: Any] ?? [:]
        let inbound = config["inbound"] as? [String: Any] ?? [:]
        let health = config["health"] as? [String: Any] ?? [:]
        let performance = config["performance"] as? [String: Any] ?? [:]
        let autoSwitch = config["autoSwitch"] as? [String: Any] ?? [:]
        let resources = config["resources"] as? [String: Any] ?? [:]
        let history = config["connectionHistory"] as? [String: Any] ?? [:]
        let loaded = Values(
            socksPort: String(config["socksPort"] as? Int ?? 1080),
            httpPort: String(config["httpPort"] as? Int ?? 8080),
            handshakeTimeout: Self.nonzeroText(inbound["handshakeTimeoutMs"]),
            httpIdleTimeout: Self.nonzeroText(inbound["httpIdleTimeoutSec"]),
            systemProxy: config["systemProxy"] as? Bool ?? false,
            tunEnabled: tun["enabled"] as? Bool ?? false,
            ipv6: tun["ipv6"] as? Bool ?? false,
            mtu: Self.nonzeroText(tun["mtu"]),
            probeURL: health["url"] as? String ?? "",
            fallbackURL: health["fallbackUrl"] as? String ?? "",
            probeInterval: Self.nonzeroText(health["intervalSec"]),
            maxDialAttempts: Self.nonzeroText(config["maxDialAttempts"]),
            dialTimeout: Self.nonzeroText(performance["dialTimeoutMs"]),
            failoverTimeout: Self.nonzeroText(performance["failoverTimeoutMs"]),
            probeTimeout: Self.nonzeroText(performance["probeTimeoutMs"]),
            probeConcurrency: Self.nonzeroText(performance["probeConcurrency"]),
            autoRouteInterval: Self.nonzeroText(performance["autoRouteIntervalSec"]),
            autoGainMS: Self.nonzeroText(autoSwitch["gainMs"]),
            autoGainPercent: Self.nonzeroText(autoSwitch["gainPercent"]),
            autoConfirmations: Self.nonzeroText(autoSwitch["confirmations"]),
            autoFailoverFailures: Self.nonzeroText(autoSwitch["failoverFailures"]),
            autoRecoverySuccesses: Self.nonzeroText(autoSwitch["recoverySuccesses"]),
            subscriptionRefresh: Self.nonzeroText(config["subscriptionRefreshMin"]),
            ruleSetRefresh: Self.nonzeroText(config["ruleSetRefreshMin"]),
            connectionLimit: Self.nonzeroText(resources["connectionLimit"]),
            udpSessionLimit: Self.nonzeroText(resources["udpSessionLimit"]),
            udpOpenLimit: Self.nonzeroText(resources["udpOpenLimit"]),
            endpointDialLimit: Self.nonzeroText(resources["endpointDialLimit"]),
            udpIdleTimeout: Self.nonzeroText(resources["udpIdleTimeoutSec"]),
            tcpIdleTimeout: Self.nonzeroText(performance["tcpIdleTimeoutSec"]),
            connectionHistory: history["disabled"] as? Bool != true,
            historyLimit: Self.nonzeroText(history["limit"]),
            historyRetention: Self.nonzeroText(history["retentionMin"])
        )
        self.source = source
        original = loaded
        values = loaded
    }

    var changed: Bool { values != original }

    private static func nonzeroText(_ raw: Any?) -> String {
        guard let value = raw as? Int, value != 0 else { return "" }
        return String(value)
    }

    func configuration() throws -> (text: String, activation: String?) {
        guard var config = try JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any] else {
            throw CoreError(message: "无法读取现有配置。")
        }
        let socks = try number(values.socksPort, in: 0...65535, label: "SOCKS5 端口", blank: 1080)
        let http = try number(values.httpPort, in: 0...65535, label: "HTTP 端口", blank: 8080)
        guard socks == 0 || socks != http else { throw CoreError(message: "SOCKS5 和 HTTP 端口不能相同。") }
        if values.socksPort != original.socksPort { config["socksPort"] = socks }
        if values.httpPort != original.httpPort { config["httpPort"] = http }
        if values.systemProxy != original.systemProxy { config["systemProxy"] = values.systemProxy ? true : nil }
        try updateNumbers(in: &config, section: "inbound", fields: [
            ("handshakeTimeoutMs", \.handshakeTimeout, "本机入口握手时限", 250...60000),
            ("httpIdleTimeoutSec", \.httpIdleTimeout, "HTTP 请求间空闲时间", 1...300)
        ])

        let tunChanged = values.tunEnabled != original.tunEnabled || values.ipv6 != original.ipv6 || values.mtu != original.mtu
        if tunChanged {
            var tun = config["tun"] as? [String: Any] ?? [:]
            let minMTU = values.ipv6 ? 1280 : 68
            let mtu = try number(values.mtu, in: 0...65535, label: "TUN MTU", blank: 0)
            guard mtu == 0 || mtu >= minMTU else {
                throw CoreError(message: "TUN MTU 须为 0 或至少 \(minMTU)。")
            }
            tun["enabled"] = values.tunEnabled ? true : nil
            tun["ipv6"] = values.ipv6 ? true : nil
            tun["mtu"] = mtu == 0 ? nil : mtu
            config["tun"] = tun.isEmpty ? nil : tun
        }

        if values.probeURL != original.probeURL || values.fallbackURL != original.fallbackURL ||
            values.probeInterval != original.probeInterval {
            var health = config["health"] as? [String: Any] ?? [:]
            health["url"] = try url(values.probeURL, label: "首选测速地址")
            health["fallbackUrl"] = try url(values.fallbackURL, label: "备用测速地址")
            if values.probeInterval != original.probeInterval {
                let interval = try number(values.probeInterval, in: 0...31536000, label: "自动测速间隔", blank: 0)
                guard interval == 0 || interval >= 30 else { throw CoreError(message: "自动测速间隔至少为 30 秒。") }
                health["intervalSec"] = interval == 0 ? nil : interval
            }
            config["health"] = health.isEmpty ? nil : health
        }

        if values.maxDialAttempts != original.maxDialAttempts {
            let attempts = try number(values.maxDialAttempts, in: 1...8, label: "出站尝试上限", blank: 0)
            config["maxDialAttempts"] = attempts == 0 ? nil : attempts
        }

        if values.subscriptionRefresh != original.subscriptionRefresh {
            let minutes = try number(values.subscriptionRefresh, in: 10...10080, label: "订阅刷新间隔", blank: 0)
            config["subscriptionRefreshMin"] = minutes == 0 ? nil : minutes
        }
        if values.ruleSetRefresh != original.ruleSetRefresh {
            let minutes = try number(values.ruleSetRefresh, in: 10...10080, label: "远程规则集刷新间隔", blank: 0)
            config["ruleSetRefreshMin"] = minutes == 0 ? nil : minutes
        }

        try updateNumbers(in: &config, section: "resources", fields: [
            ("connectionLimit", \.connectionLimit, "代理连接总上限", 16...4096),
            ("udpSessionLimit", \.udpSessionLimit, "UDP 会话上限", 32...1024),
            ("udpOpenLimit", \.udpOpenLimit, "UDP 并发建连上限", 1...64),
            ("endpointDialLimit", \.endpointDialLimit, "每端点拨号并发", 4...64),
            ("udpIdleTimeoutSec", \.udpIdleTimeout, "UDP 空闲回收时间", 15...1800)
        ])

        var history = config["connectionHistory"] as? [String: Any] ?? [:]
        if values.connectionHistory != original.connectionHistory {
            history["disabled"] = values.connectionHistory ? nil : true
        }
        if values.historyLimit != original.historyLimit {
            let limit = try number(values.historyLimit, in: 1...1000, label: "连接记录条数上限", blank: 0)
            history["limit"] = limit == 0 ? nil : limit
        }
        if values.historyRetention != original.historyRetention {
            let minutes = try number(values.historyRetention, in: 1...120, label: "连接记录保留时间", blank: 0)
            history["retentionMin"] = minutes == 0 ? nil : minutes
        }
        config["connectionHistory"] = history.isEmpty ? nil : history

        try updateNumbers(in: &config, section: "performance", fields: [
            ("dialTimeoutMs", \.dialTimeout, "拨号总时限", 250...30000),
            ("failoverTimeoutMs", \.failoverTimeout, "切换前等待上限", 100...29999),
            ("probeTimeoutMs", \.probeTimeout, "单节点测速时限", 1000...12000),
            ("probeConcurrency", \.probeConcurrency, "每批测速并发", 1...8),
            ("autoRouteIntervalSec", \.autoRouteInterval, "自动选路复测间隔", 15...3600),
            ("tcpIdleTimeoutSec", \.tcpIdleTimeout, "TCP 隧道空闲回收时间", 15...86400)
        ])
        let performance = config["performance"] as? [String: Any] ?? [:]
        let configuredDial = performance["dialTimeoutMs"] as? Int ?? 0
        if let failover = performance["failoverTimeoutMs"] as? Int, failover >= (configuredDial == 0 ? 10000 : configuredDial) {
            throw CoreError(message: "切换前等待上限须小于拨号总时限。")
        }
        try updateNumbers(in: &config, section: "autoSwitch", fields: [
            ("gainMs", \.autoGainMS, "最少快多少毫秒", 1...2000),
            ("gainPercent", \.autoGainPercent, "最少快百分之多少", 1...95),
            ("confirmations", \.autoConfirmations, "优势确认轮数", 1...10),
            ("failoverFailures", \.autoFailoverFailures, "故障确认轮数", 1...10),
            ("recoverySuccesses", \.autoRecoverySuccesses, "恢复确认轮数", 1...10)
        ])

        var notes: [String] = []
        if values.systemProxy != original.systemProxy || values.tunEnabled != original.tunEnabled {
            notes.append("启动选项在下次启动时使用。")
        }
        if values.ipv6 != original.ipv6 || values.mtu != original.mtu {
            notes.append("MTU 和 IPv6 设置在重新开启 TUN 时应用。")
        }
        let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        return (String(decoding: data, as: UTF8.self), notes.isEmpty ? nil : notes.joined())
    }

    private func updateNumbers(in config: inout [String: Any], section: String,
                               fields: [(key: String, value: KeyPath<Values, String>, label: String, range: ClosedRange<Int>)]) throws {
        let edits = fields.filter { values[keyPath: $0.value] != original[keyPath: $0.value] }
        guard !edits.isEmpty else { return }
        var object = config[section] as? [String: Any] ?? [:]
        for field in edits {
            let value = try number(values[keyPath: field.value], in: field.range, label: field.label, blank: 0)
            object[field.key] = value == 0 ? nil : value
        }
        config[section] = object.isEmpty ? nil : object
    }

    private func number(_ text: String, in range: ClosedRange<Int>, label: String, blank: Int) throws -> Int {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return blank }
        guard let value = Int(text), range.contains(value) else {
            throw CoreError(message: "\(label)须为 \(range.lowerBound)–\(range.upperBound) 之间的整数。")
        }
        return value
    }

    private func url(_ text: String, label: String) throws -> String? {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return nil }
        guard let parts = URLComponents(string: text), let scheme = parts.scheme,
              ["http", "https"].contains(scheme), let host = parts.host, !host.isEmpty else {
            throw CoreError(message: "\(label)须为带主机名的 HTTP 或 HTTPS 地址。")
        }
        return text
    }
}

struct AdvancedSettingsPanel: View {
    private enum Category: String, CaseIterable {
        case access = "接入与端口"
        case performance = "连接性能"
        case probes = "测速与选路"
        case switching = "自动切换"
        case data = "刷新与记录"
    }

    @ObservedObject var core: CoreModel
    @Binding var draft: AdvancedSettingsDraft?
    let editJSON: () -> Void
    @State private var category = Category.performance

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label("高级配置", systemImage: "slider.horizontal.3").font(.headline)
                Spacer()
                Button("编辑 JSON…", action: editJSON)
                    .disabled(core.saving || draft?.changed == true)
            }
            if core.changed {
                Label("请先保存或还原 JSON 草稿，再编辑高级选项。", systemImage: "doc.badge.clock")
                    .foregroundStyle(.orange)
            } else if let fields = Binding($draft) {
                Text("留空使用默认值。各分组的改动一并保存。")
                    .font(.caption).foregroundStyle(.secondary)
                Picker("配置分类", selection: $category) {
                    ForEach(Category.allCases, id: \.self) { category in
                        Text(category.rawValue).tag(category)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                Divider()
                controls(fields.values)
                    .disabled(core.saving)
                if let error = fields.wrappedValue.error {
                    Label(error, systemImage: "exclamationmark.circle").foregroundStyle(.orange)
                }
                Divider()
                HStack {
                    if fields.wrappedValue.changed {
                        Text("有未保存的修改").foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("还原修改") { draft = AdvancedSettingsDraft(source: core.saved) }
                        .disabled(!fields.wrappedValue.changed || core.saving)
                    Button(core.saving ? "正在校验…" : "保存高级配置", action: save)
                        .buttonStyle(HopPrimaryButton())
                        .keyboardShortcut("s", modifiers: .command)
                        .disabled(!fields.wrappedValue.changed || core.saving || core.configurationConflict || fields.wrappedValue.source != core.saved)
                }
            } else {
                Text("无法读取已保存的配置。可以打开 JSON 编辑器修复。").foregroundStyle(.secondary)
            }
        }
        .font(.callout)
        .hopPanel()
        .onChange(of: core.saved, initial: true) { _, source in
            guard draft?.source != source else { return }
            if let current = draft, current.changed, (try? current.configuration().text) != source {
                draft?.error = "已有更新的配置。请还原此处草稿后再编辑。"
            } else {
                draft = AdvancedSettingsDraft(source: source)
            }
        }
    }

    @ViewBuilder
    private func controls(_ values: Binding<AdvancedSettingsDraft.Values>) -> some View {
        switch category {
        case .access: accessControls(values)
        case .performance: performanceControls(values)
        case .probes: probeControls(values)
        case .switching: switchingControls(values)
        case .data: dataControls(values)
        }
    }

    private func performanceControls(_ values: Binding<AdvancedSettingsDraft.Values>) -> some View {
        VStack(alignment: .leading, spacing: 13) {
            section("连接与故障切换", icon: "arrow.triangle.branch") {
                fieldRow {
                    field("拨号总时限（毫秒）", text: values.dialTimeout, prompt: "10000")
                    field("切换前等待上限（毫秒）", text: values.failoverTimeout, prompt: "5000")
                    field("出站尝试上限", text: values.maxDialAttempts, prompt: "3")
                }
                hint("总时限适用于 TCP 和 UDP 建连。TCP 有备用出站时，前序尝试单独计时，留空最多用总时限的一半。尝试次数包含首次拨号。")
                field("TCP 隧道空闲回收（秒，15–86400）", text: values.tcpIdleTimeout, prompt: "留空关闭")
                hint("适用于 SOCKS5、HTTP CONNECT 和 TUN。任一方向传输数据都会重新计时，保存后对新建隧道生效。")
            }
            Divider()
            section("连接资源上限", icon: "gauge.with.dots.needle.33percent") {
                if let active = core.status?.resources, core.phase == .running, !core.statusReadFailed {
                    if let used = active.connections, let limit = active.connectionLimit {
                        hint("总额度占用 \(used) / \(limit) · 因总上限拒绝 \(active.connectionsRefused ?? 0) 次")
                    }
                    hint("运行中 · UDP 会话 \(active.udpSessions) / \(active.udpSessionLimit) · UDP 正在建连 \(active.udpOpening) / \(active.udpOpenLimit) · 每端点上限 \(active.endpointDialLimit)")
                    if let idle = active.udpIdleTimeoutSec {
                        hint("运行中 · UDP 空闲 \(idle) 秒后回收")
                    }
                }
                fieldRow {
                    field("代理连接总上限（16–4096）", text: values.connectionLimit, prompt: "4096")
                    field("UDP 空闲回收（秒，15–1800）", text: values.udpIdleTimeout, prompt: "300")
                }
                hint("TCP 和 UDP 共用，正在建立的连接也占额度。满额时拒绝新建，已有连接继续传输。")
                fieldRow {
                    field("UDP 会话上限", text: values.udpSessionLimit, prompt: "1024")
                    field("UDP 并发建连上限", text: values.udpOpenLimit, prompt: "64")
                    field("每端点拨号并发", text: values.endpointDialLimit, prompt: "64")
                }
                hint("可填范围依次为 32–1024、1–64、4–64。UDP 会话满时回收最久未活动的会话。同一地址和端口的 TCP、UDP 建连及测速共用端点额度。")
                hint("空闲回收适用于 SOCKS5 和 TUN。此组资源设置在重启代理后生效。")
            }
        }
    }

    private func probeControls(_ values: Binding<AdvancedSettingsDraft.Values>) -> some View {
        section("测速与自动选路", icon: "speedometer") {
            field("首选测速地址", text: values.probeURL, prompt: "随订阅或默认")
            field("备用测速地址", text: values.fallbackURL, prompt: "可留空")
            fieldRow {
                field("单节点测速时限（毫秒）", text: values.probeTimeout, prompt: "6000")
                field("每批测速并发", text: values.probeConcurrency, prompt: "8")
            }
            fieldRow {
                field("策略组测速间隔（秒）", text: values.probeInterval, prompt: "随订阅或 300")
                field("自动选路复测间隔（秒）", text: values.autoRouteInterval, prompt: "60")
            }
            hint("单节点时限涵盖首选和备用测速地址。策略组测速与按地区、服务商自动选路各自计时。")
        }
    }

    private func dataControls(_ values: Binding<AdvancedSettingsDraft.Values>) -> some View {
        VStack(alignment: .leading, spacing: 13) {
            section("后台刷新", icon: "arrow.clockwise") {
                fieldRow {
                    field("订阅刷新间隔（分钟）", text: values.subscriptionRefresh, prompt: "360")
                    field("远程规则集刷新间隔（分钟）", text: values.ruleSetRefresh, prompt: "1440")
                }
                hint("内核运行时每 10 分钟检查是否到期。来源单独指定的刷新间隔优先，保存后可热加载。")
            }
            Divider()
            section("最近连接记录", icon: "clock.arrow.circlepath") {
                Toggle("保留已结束连接", isOn: values.connectionHistory)
                fieldRow {
                    field("条数上限（1–1000）", text: values.historyLimit, prompt: "300")
                    field("保留时间（分钟，1–120）", text: values.historyRetention, prompt: "15")
                }
                .disabled(!values.connectionHistory.wrappedValue)
                hint("记录只保存在内存中，按时间或条数回收。关闭后，连接页只显示活动连接。流量统计独立累计。")
                hint("保存后可热加载，连接记录会从新内核开始累计。")
            }
        }
    }

    private func switchingControls(_ values: Binding<AdvancedSettingsDraft.Values>) -> some View {
        VStack(alignment: .leading, spacing: 13) {
            section("同服务商优选", icon: "point.3.connected.trianglepath.dotted") {
                fieldRow {
                    field("最少快多少毫秒（1–2000）", text: values.autoGainMS, prompt: "50")
                    field("最少快百分之多少（1–95）", text: values.autoGainPercent, prompt: "20")
                    field("优势确认轮数（1–10）", text: values.autoConfirmations, prompt: "2")
                }
                hint("备用节点的平滑延迟须同时达到两个改善门槛，并连续通过指定轮数，才切换新连接。")
            }
            Divider()
            section("故障切换与回切", icon: "arrow.triangle.branch") {
                fieldRow {
                    field("故障确认轮数（1–10）", text: values.autoFailoverFailures, prompt: "2")
                    field("恢复确认轮数（1–10）", text: values.autoRecoverySuccesses, prompt: "2")
                }
                hint("连续测速失败达到门槛后换线。高优先级服务商恢复时，须连续测速成功才从仍健康的备用服务商切回。")
                hint("适用于地区自动选路。保存后可热加载，已建立的连接继续使用原出站。")
            }
        }
    }

    private func accessControls(_ values: Binding<AdvancedSettingsDraft.Values>) -> some View {
        VStack(alignment: .leading, spacing: 13) {
            section("本机监听", icon: "network") {
                fieldRow {
                    field("SOCKS5 端口", text: values.socksPort, prompt: "1080")
                    field("HTTP 端口", text: values.httpPort, prompt: "8080")
                }
                hint("端口填 0 自动分配。")
                fieldRow {
                    field("入口握手时限（毫秒，250–60000）", text: values.handshakeTimeout, prompt: "10000")
                    field("HTTP 请求间空闲（秒，1–300）", text: values.httpIdleTimeout, prompt: "30")
                }
                hint("握手时限适用于 SOCKS5 协商和 HTTP 请求头。空闲时限用于 HTTP 复用连接等待下一次请求。端口和超时在重启代理后生效。")
            }
            Divider()
            section("启动与 TUN", icon: "bolt.shield") {
                fieldRow {
                    Toggle("启动时接管系统代理", isOn: values.systemProxy)
                    Toggle("启动时开启 TUN", isOn: values.tunEnabled)
                    Toggle("TUN 接管 IPv6", isOn: values.ipv6)
                }
                field("TUN MTU", text: values.mtu, prompt: "9000")
                    .frame(maxWidth: 190)
                hint("重新开启 TUN 后应用 MTU 和 IPv6。自定义 MTU 需要新版 TUN 助手。")
            }
        }
    }

    private func section<Content: View>(_ title: String, icon: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: icon).fontWeight(.semibold)
            content()
        }
    }

    private func fieldRow<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        HStack(alignment: .top, spacing: 14, content: content)
    }

    private func hint(_ text: String) -> some View {
        Text(text).font(.caption).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func field(_ title: String, text: Binding<String>, prompt: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            TextField(title, text: text, prompt: Text(prompt))
                .labelsHidden()
                .accessibilityLabel(title)
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
                .monospacedDigit()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func save() {
        guard let current = draft else { return }
        do {
            let candidate = try current.configuration()
            draft?.error = nil
            core.saveAdvanced(candidate.text, basedOn: current.source, activation: candidate.activation)
        } catch {
            draft?.error = error.localizedDescription
        }
    }
}
