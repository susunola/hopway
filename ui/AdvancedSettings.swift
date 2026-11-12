import AppKit
import Foundation
import SwiftUI

struct AdvancedSettingsDraft {
    struct Values: Equatable {
        var socksPort = "1080"
        var httpPort = "8080"
        var systemProxy = false
        var tunEnabled = false
        var ipv6 = false
        var fakeIPExceptions = ""
        var sniffing = true
        var probeURL = ""
        var autoRouteInterval = ""
        var onExhausted = "block"
        var subscriptionRefresh = ""
        var connectionHistory = true
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
        let health = config["health"] as? [String: Any] ?? [:]
        let performance = config["performance"] as? [String: Any] ?? [:]
        let history = config["connectionHistory"] as? [String: Any] ?? [:]
        let loaded = Values(
            socksPort: String(config["socksPort"] as? Int ?? 1080),
            httpPort: String(config["httpPort"] as? Int ?? 8080),
            systemProxy: config["systemProxy"] as? Bool ?? false,
            tunEnabled: tun["enabled"] as? Bool ?? false,
            ipv6: tun["ipv6"] as? Bool ?? false,
            fakeIPExceptions: (tun["fakeIPExceptions"] as? [String] ?? []).joined(separator: "\n"),
            sniffing: tun["disableSniffing"] as? Bool != true,
            probeURL: health["url"] as? String ?? "",
            autoRouteInterval: Self.nonzeroText(performance["autoRouteIntervalSec"]),
            onExhausted: (config["dialPolicy"] as? [String: Any])?["onExhausted"] as? String ?? "block",
            subscriptionRefresh: Self.nonzeroText(config["subscriptionRefreshMin"]),
            connectionHistory: history["disabled"] as? Bool != true
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
            throw CoreError(message: L("无法读取现有配置。"))
        }
        let socks = try number(values.socksPort, in: 0...65535, label: L("SOCKS5 端口"), blank: 1080)
        let http = try number(values.httpPort, in: 0...65535, label: L("HTTP 端口"), blank: 8080)
        guard socks == 0 || socks != http else { throw CoreError(message: L("SOCKS5 和 HTTP 端口不能相同。")) }
        if values.socksPort != original.socksPort { config["socksPort"] = socks }
        if values.httpPort != original.httpPort { config["httpPort"] = http }
        if values.systemProxy != original.systemProxy { config["systemProxy"] = values.systemProxy ? true : nil }

        let ipv6Changed = values.ipv6 != original.ipv6
        let tunNetworkChanged = ipv6Changed || values.fakeIPExceptions != original.fakeIPExceptions ||
            values.sniffing != original.sniffing
        if values.tunEnabled != original.tunEnabled || tunNetworkChanged {
            var tun = config["tun"] as? [String: Any] ?? [:]
            if ipv6Changed {
                if values.ipv6, let mtu = tun["mtu"] as? Int, mtu != 0, mtu < 1280 {
                    throw CoreError(message: L("开启 TUN IPv6 需要至少 1280 的 MTU。可在 JSON 中调整。"))
                }
                tun["ipv6"] = values.ipv6 ? true : nil
            }
            if values.tunEnabled != original.tunEnabled { tun["enabled"] = values.tunEnabled ? true : nil }
            if values.fakeIPExceptions != original.fakeIPExceptions {
                let entries = values.fakeIPExceptions.components(separatedBy: .newlines)
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
                guard entries.count <= 128 else { throw CoreError(message: L("Fake IP 例外最多填写 128 行。")) }
                tun["fakeIPExceptions"] = entries.isEmpty ? nil : entries
            }
            if values.sniffing != original.sniffing { tun["disableSniffing"] = values.sniffing ? nil : true }
            config["tun"] = tun.isEmpty ? nil : tun
        }

        if values.probeURL != original.probeURL {
            var health = config["health"] as? [String: Any] ?? [:]
            health["url"] = try url(values.probeURL, label: L("测速地址"))
            config["health"] = health.isEmpty ? nil : health
        }
        if values.onExhausted != original.onExhausted {
            var dial = config["dialPolicy"] as? [String: Any] ?? [:]
            dial["onExhausted"] = values.onExhausted == "block" ? nil : values.onExhausted
            config["dialPolicy"] = dial.isEmpty ? nil : dial
        }
        if values.autoRouteInterval != original.autoRouteInterval {
            var performance = config["performance"] as? [String: Any] ?? [:]
            let interval = try number(values.autoRouteInterval, in: 15...3600, label: L("自动选路复测间隔"), blank: 0)
            performance["autoRouteIntervalSec"] = interval == 0 ? nil : interval
            config["performance"] = performance.isEmpty ? nil : performance
        }
        if values.subscriptionRefresh != original.subscriptionRefresh {
            let minutes = try number(values.subscriptionRefresh, in: 10...10080, label: L("订阅刷新间隔"), blank: 0)
            config["subscriptionRefreshMin"] = minutes == 0 ? nil : minutes
        }
        if values.connectionHistory != original.connectionHistory {
            var history = config["connectionHistory"] as? [String: Any] ?? [:]
            history["disabled"] = values.connectionHistory ? nil : true
            config["connectionHistory"] = history.isEmpty ? nil : history
        }

        var notes: [String] = []
        if values.systemProxy != original.systemProxy || values.tunEnabled != original.tunEnabled {
            notes.append(L("启动选项在下次启动时使用。"))
        }
        if tunNetworkChanged {
            notes.append(L("TUN 参数在下次开启增强模式时应用。"))
        }
        let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        return (String(decoding: data, as: UTF8.self), notes.isEmpty ? nil : notes.joined())
    }

    private func number(_ text: String, in range: ClosedRange<Int>, label: String, blank: Int) throws -> Int {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return blank }
        guard let value = Int(text), range.contains(value) else {
            throw CoreError(message: L("<1>须为 <2>–<3> 之间的整数。", label, range.lowerBound, range.upperBound))
        }
        return value
    }

    private func url(_ text: String, label: String) throws -> String? {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return nil }
        guard let parts = URLComponents(string: text), let scheme = parts.scheme,
              ["http", "https"].contains(scheme), let host = parts.host, !host.isEmpty else {
            throw CoreError(message: L("<1>须为带主机名的 HTTP 或 HTTPS 地址。", label))
        }
        return text
    }
}

struct AdvancedSettingsPanel<Header: View, Feedback: View>: View {
    @Environment(\.locale) private var interfaceLocale
    @ObservedObject var core: CoreModel
    @Binding var draft: AdvancedSettingsDraft?
    let editJSON: () -> Void
    @ViewBuilder var header: () -> Header
    @ViewBuilder var feedback: () -> Feedback
    @State private var contentHeight: CGFloat = 0
    @State private var viewportHeight: CGFloat = 0

    var body: some View {
        let _ = interfaceLocale
        VStack(spacing: 8) {
            ScrollView(.vertical) {
                VStack(alignment: .leading, spacing: 12) {
                    header()
                    form
                    feedback()
                }
                .padding(.bottom, 2)
                .onGeometryChange(for: CGFloat.self, of: { $0.size.height }) {
                    contentHeight = $0
                }
            }
            .onGeometryChange(for: CGFloat.self, of: { $0.size.height }) {
                viewportHeight = $0
            }
            .scrollBounceBehavior(.basedOnSize)
            .scrollIndicators(contentHeight > viewportHeight + 0.5 ? .automatic : .hidden, axes: .vertical)
            if !core.changed, let fields = draft {
                saveBar(fields)
            }
        }
        .onChange(of: core.saved, initial: true) { _, source in
            guard draft?.source != source else { return }
            if let current = draft, current.changed, (try? current.configuration().text) != source {
                draft?.error = L("已有更新的配置。请还原此处草稿后再编辑。")
            } else {
                draft = AdvancedSettingsDraft(source: source)
            }
        }
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label(L("高级配置"), systemImage: "slider.horizontal.3").labelStyle(HopSectionLabelStyle())
                Spacer()
                Button(L("编辑 JSON…"), action: editJSON)
                    .fixedSize()
                    .disabled(core.saving || draft?.changed == true)
            }
            if core.changed {
                Label(L("请先保存或还原 JSON 草稿，再编辑高级选项。"), systemImage: "doc.badge.clock")
                    .foregroundStyle(HopAppearance.warning)
            } else if let fields = Binding($draft) {
                Text(L("留空使用默认值。修改会一起保存。"))
                    .font(.caption).foregroundStyle(.secondary)
                Divider()
                VStack(alignment: .leading, spacing: 12) {
                    fieldRow {
                        accessControls(fields.values)
                        probeControls(fields.values)
                    }
                    Divider()
                    dnsControls(fields.values)
                    Divider()
                    dataControls(fields.values)
                }
                .disabled(core.saving)
            } else {
                Text(L("无法读取已保存的配置。可以打开 JSON 编辑器修复。")).foregroundStyle(.secondary)
            }
        }
        .font(.callout)
        .hopPanel(verticalPadding: 10)
    }

    private func saveBar(_ fields: AdvancedSettingsDraft) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            if let error = fields.error {
                Label(error, systemImage: "exclamationmark.circle")
                    .foregroundStyle(HopAppearance.warning)
            }
            HStack {
                if fields.changed {
                    Text(L("有未保存的修改")).foregroundStyle(.secondary)
                }
                Spacer()
                if fields.changed {
                    Button(L("还原修改")) { draft = AdvancedSettingsDraft(source: core.saved) }
                        .fixedSize()
                        .disabled(core.saving)
                }
                Button(core.saving ? L("正在校验…") : L("保存更改"), action: save)
                    .buttonStyle(HopPrimaryButton())
                    .fixedSize()
                    .keyboardShortcut("s", modifiers: .command)
                    .accessibilityIdentifier("advanced-settings-save")
                    .disabled(!fields.changed || core.saving || core.configurationConflict || fields.source != core.saved)
            }
        }
        .font(.callout)
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .hopGlass()
    }

    private func dnsControls(_ values: Binding<AdvancedSettingsDraft.Values>) -> some View {
        fieldRow {
            section(L("TUN 域名解析"), icon: "network") {
                Text(L("Fake IP 例外")).font(.caption).foregroundStyle(.secondary)
                TextField(L("Fake IP 例外"), text: values.fakeIPExceptions,
                          prompt: Text(L("每行一个域名后缀，例如 home.example")), axis: .vertical)
                    .labelsHidden()
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .lineLimit(2...5)
                    .accessibilityIdentifier("advanced-settings-fake-ip-exceptions")
                hint(L("每行一个域名后缀，最多 128 条。匹配后使用系统 DNS。"))
            }
            section(L("TUN 连接嗅探"), icon: "waveform.path") {
                Toggle(L("从 TLS SNI 和 HTTP Host 识别目标域名"), isOn: values.sniffing)
                    .accessibilityIdentifier("advanced-settings-sniffing")
                hint(L("关闭后，直接连 IP 的 TCP 流量按原始地址分流。重新开启 TUN 后生效。"))
            }
        }
    }

    private func probeControls(_ values: Binding<AdvancedSettingsDraft.Values>) -> some View {
        section(L("节点测速"), icon: "speedometer") {
            fieldRow {
                field(L("测速地址"), text: values.probeURL, prompt: L("随订阅或使用默认地址"))
                field(L("自动选路复测间隔（秒）"), text: values.autoRouteInterval, prompt: "60")
            }
            hint(L("自动选路复测间隔为 15–3600 秒。"))
            Picker(L("候选全部不可用时"), selection: values.onExhausted) {
                Text(L("阻断连接")).tag("block")
                Text(L("直连")).tag("direct")
            }
            .pickerStyle(.segmented)
            .fixedSize()
            hint(L("默认阻断，避免流量绕过代理。选择直连后，自动选路没有可用节点时新连接直接出门。"))
        }
    }

    private func dataControls(_ values: Binding<AdvancedSettingsDraft.Values>) -> some View {
        fieldRow {
            section(L("订阅刷新"), icon: "arrow.clockwise") {
                field(L("自动刷新间隔（分钟）"), text: values.subscriptionRefresh, prompt: "360")
                    .frame(maxWidth: 260)
                hint(L("默认每 6 小时刷新。订阅单独设置的间隔优先。"))
            }
            section(L("连接记录"), icon: "clock.arrow.circlepath") {
                Toggle(L("在连接页显示最近结束的连接"), isOn: values.connectionHistory)
                hint(L("记录保存在内存中。关闭后只显示活动连接，流量继续累计。"))
            }
        }
    }

    private func accessControls(_ values: Binding<AdvancedSettingsDraft.Values>) -> some View {
        section(L("本机监听"), icon: "network") {
            fieldRow {
                field(L("SOCKS5 端口"), text: values.socksPort, prompt: "1080")
                field(L("HTTP 端口"), text: values.httpPort, prompt: "8080")
            }
            hint(L("填 0 自动分配端口。重启代理后生效。"))
            if let endpoint = core.endpoint, core.phase == .running, !core.statusReadFailed {
                HopDisclosure(L("手动接入地址")) {
                    VStack(alignment: .leading, spacing: 6) {
                        copyAddress("SOCKS5", address: endpoint.socks)
                        copyAddress("HTTP", address: endpoint.http)
                    }
                }
            }
        }
    }

    private func copyAddress(_ title: String, address: String) -> some View {
        HStack(spacing: 8) {
            Text(title).foregroundStyle(.secondary)
            Text(address).font(.system(.callout, design: .monospaced))
                .lineLimit(1)
                .help(address)
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(address, forType: .string)
            } label: {
                Image(systemName: "document.on.document")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(L("复制<1>地址", title))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func section<Content: View>(_ title: String, icon: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Label(title, systemImage: icon).fontWeight(.semibold)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func fieldRow<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        HStack(alignment: .top, spacing: 14, content: content)
    }

    private func hint(_ text: String) -> some View {
        Text(text).font(.caption).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func field(_ title: String, text: Binding<String>, prompt: String) -> some View {
        HopLabeledControl(title: title) {
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

struct StartupAccessSettings: View {
    @Environment(\.locale) private var interfaceLocale
    @ObservedObject var core: CoreModel
    let hasAdvancedEdits: Bool
    @Environment(\.dismiss) private var dismiss
    @State private var draft: AdvancedSettingsDraft?

    var body: some View {
        let _ = interfaceLocale
        VStack(alignment: .leading, spacing: 12) {
            Label(L("启动与 TUN"), systemImage: "bolt.shield").font(.headline)
            if let fields = Binding($draft) {
                VStack(alignment: .leading, spacing: 9) {
                    Toggle(L("启动时接管系统代理"), isOn: fields.values.systemProxy)
                    Toggle(L("启动时开启 TUN"), isOn: fields.values.tunEnabled)
                    Toggle(L("TUN 接管 IPv6"), isOn: fields.values.ipv6)
                }
                .disabled(core.saving || core.changed || hasAdvancedEdits)
                Text(L("IPv6 设置在下次开启 TUN 时生效。")).foregroundStyle(.secondary)
                if core.changed || hasAdvancedEdits {
                    Text(L("请先保存或还原设置页的草稿。")).foregroundStyle(HopAppearance.warning)
                } else if fields.wrappedValue.source != core.saved {
                    HStack {
                        Text(L("配置已更新，请重新载入。")).foregroundStyle(HopAppearance.warning)
                        Button(L("重新载入")) { draft = AdvancedSettingsDraft(source: core.saved) }
                    }
                }
                if let error = fields.wrappedValue.error {
                    Text(error).foregroundStyle(HopAppearance.warning)
                }
            } else {
                Text(L("无法读取已保存的配置。")).foregroundStyle(.secondary)
            }

            Divider()
            let tun = core.status?.tun
            HStack {
                Menu(L("TUN 助手")) {
                    if tun?.outdated == true {
                        // A rebuilt app or a newer protocol version: the
                        // installed helper still works but must be replaced.
                        Button(L("更新助手")) { core.setTUNService(true) }
                        Button(L("移除助手")) { core.setTUNService(false) }
                    } else {
                        Button(tun?.service == true ? L("移除助手") : L("安装助手")) {
                            core.setTUNService(tun?.service != true)
                        }
                    }
                }
                .fixedSize()
                .disabled(core.phase != .running || tun?.supported != true || core.statusReadFailed || core.changingTUN)
                .help(core.phase == .stopped ? L("启动代理后可管理 TUN 助手。") : L("管理 TUN 助手"))
                Spacer()
                Button(L("完成")) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(core.saving ? L("正在保存…") : L("保存偏好"), action: save)
                    .buttonStyle(HopPrimaryButton())
                    .disabled(draft?.changed != true || draft?.source != core.saved ||
                              core.changed || hasAdvancedEdits || core.saving || core.configurationConflict)
            }
        }
        .font(.callout)
        .padding(22)
        .frame(width: 410)
        .onChange(of: core.saved, initial: true) { _, source in
            if draft?.changed != true || (try? draft?.configuration().text) == source {
                draft = AdvancedSettingsDraft(source: source)
            }
        }
    }

    private func save() {
        guard let draft else { return }
        do {
            let candidate = try draft.configuration()
            self.draft?.error = nil
            core.saveAdvanced(candidate.text, basedOn: draft.source, activation: candidate.activation)
        } catch {
            self.draft?.error = error.localizedDescription
        }
    }
}
