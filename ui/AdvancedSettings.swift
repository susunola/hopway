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
            throw CoreError(message: "无法读取现有配置。")
        }
        let socks = try number(values.socksPort, in: 0...65535, label: "SOCKS5 端口", blank: 1080)
        let http = try number(values.httpPort, in: 0...65535, label: "HTTP 端口", blank: 8080)
        guard socks == 0 || socks != http else { throw CoreError(message: "SOCKS5 和 HTTP 端口不能相同。") }
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
                    throw CoreError(message: "开启 TUN IPv6 需要至少 1280 的 MTU。可在 JSON 中调整。")
                }
                tun["ipv6"] = values.ipv6 ? true : nil
            }
            if values.tunEnabled != original.tunEnabled { tun["enabled"] = values.tunEnabled ? true : nil }
            if values.fakeIPExceptions != original.fakeIPExceptions {
                let entries = values.fakeIPExceptions.components(separatedBy: .newlines)
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
                guard entries.count <= 128 else { throw CoreError(message: "Fake IP 例外最多填写 128 行。") }
                tun["fakeIPExceptions"] = entries.isEmpty ? nil : entries
            }
            if values.sniffing != original.sniffing { tun["disableSniffing"] = values.sniffing ? nil : true }
            config["tun"] = tun.isEmpty ? nil : tun
        }

        if values.probeURL != original.probeURL {
            var health = config["health"] as? [String: Any] ?? [:]
            health["url"] = try url(values.probeURL, label: "测速地址")
            config["health"] = health.isEmpty ? nil : health
        }
        if values.autoRouteInterval != original.autoRouteInterval {
            var performance = config["performance"] as? [String: Any] ?? [:]
            let interval = try number(values.autoRouteInterval, in: 15...3600, label: "自动选路复测间隔", blank: 0)
            performance["autoRouteIntervalSec"] = interval == 0 ? nil : interval
            config["performance"] = performance.isEmpty ? nil : performance
        }
        if values.subscriptionRefresh != original.subscriptionRefresh {
            let minutes = try number(values.subscriptionRefresh, in: 10...10080, label: "订阅刷新间隔", blank: 0)
            config["subscriptionRefreshMin"] = minutes == 0 ? nil : minutes
        }
        if values.connectionHistory != original.connectionHistory {
            var history = config["connectionHistory"] as? [String: Any] ?? [:]
            history["disabled"] = values.connectionHistory ? nil : true
            config["connectionHistory"] = history.isEmpty ? nil : history
        }

        var notes: [String] = []
        if values.systemProxy != original.systemProxy || values.tunEnabled != original.tunEnabled {
            notes.append("启动选项在下次启动时使用。")
        }
        if tunNetworkChanged {
            notes.append("TUN 参数在下次开启增强模式时应用。")
        }
        let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        return (String(decoding: data, as: UTF8.self), notes.isEmpty ? nil : notes.joined())
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
        case access = "本机端口"
        case dns = "DNS 与嗅探"
        case probes = "测速与选路"
        case data = "刷新与记录"
    }

    @ObservedObject var core: CoreModel
    @Binding var draft: AdvancedSettingsDraft?
    let editJSON: () -> Void
    @State private var category = Category.access

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label("高级配置", systemImage: "slider.horizontal.3").font(.headline)
                Spacer()
                Button("编辑 JSON…", action: editJSON)
                    .fixedSize()
                    .disabled(core.saving || draft?.changed == true)
            }
            if core.changed {
                Label("请先保存或还原 JSON 草稿，再编辑高级选项。", systemImage: "doc.badge.clock")
                    .foregroundStyle(HopAppearance.warning)
            } else if let fields = Binding($draft) {
                Text("留空使用默认值。修改会一起保存。")
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
                    Label(error, systemImage: "exclamationmark.circle").foregroundStyle(HopAppearance.warning)
                }
                Divider()
                HStack {
                    if fields.wrappedValue.changed {
                        Text("有未保存的修改").foregroundStyle(.secondary)
                    }
                    Spacer()
                    if fields.wrappedValue.changed {
                        Button("还原修改") { draft = AdvancedSettingsDraft(source: core.saved) }
                            .fixedSize()
                            .disabled(core.saving)
                    }
                    Button(core.saving ? "正在校验…" : "保存更改", action: save)
                        .buttonStyle(HopPrimaryButton())
                        .fixedSize()
                        .keyboardShortcut("s", modifiers: .command)
                        .accessibilityIdentifier("advanced-settings-save")
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
        case .dns: dnsControls(values)
        case .probes: probeControls(values)
        case .data: dataControls(values)
        }
    }

    private func dnsControls(_ values: Binding<AdvancedSettingsDraft.Values>) -> some View {
        VStack(alignment: .leading, spacing: 13) {
            section("TUN 域名解析", icon: "network") {
                Text("Fake IP 例外").font(.caption).foregroundStyle(.secondary)
                TextField("Fake IP 例外", text: values.fakeIPExceptions,
                          prompt: Text("每行一个域名后缀，例如 home.example"), axis: .vertical)
                    .labelsHidden()
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .lineLimit(2...5)
                    .accessibilityIdentifier("advanced-settings-fake-ip-exceptions")
                hint("每行一个域名后缀，最多 128 条。匹配后使用系统 DNS。")
            }
            Divider()
            section("TUN 连接嗅探", icon: "waveform.path") {
                Toggle("从 TLS SNI 和 HTTP Host 识别目标域名", isOn: values.sniffing)
                    .accessibilityIdentifier("advanced-settings-sniffing")
                hint("关闭后，直接连 IP 的 TCP 流量按原始地址分流。重新开启 TUN 后生效。")
            }
        }
    }

    private func probeControls(_ values: Binding<AdvancedSettingsDraft.Values>) -> some View {
        section("节点测速", icon: "speedometer") {
            field("测速地址", text: values.probeURL, prompt: "随订阅或使用默认地址")
            field("自动选路复测间隔（秒）", text: values.autoRouteInterval, prompt: "60")
                .frame(maxWidth: 260)
            hint("自动选路复测间隔为 15–3600 秒。")
        }
    }

    private func dataControls(_ values: Binding<AdvancedSettingsDraft.Values>) -> some View {
        VStack(alignment: .leading, spacing: 13) {
            section("订阅刷新", icon: "arrow.clockwise") {
                field("自动刷新间隔（分钟）", text: values.subscriptionRefresh, prompt: "360")
                    .frame(maxWidth: 260)
                hint("默认每 6 小时刷新。订阅单独设置的间隔优先。")
            }
            Divider()
            section("连接记录", icon: "clock.arrow.circlepath") {
                Toggle("在连接页显示最近结束的连接", isOn: values.connectionHistory)
                hint("记录保存在内存中。关闭后只显示活动连接，流量继续累计。")
            }
        }
    }

    private func accessControls(_ values: Binding<AdvancedSettingsDraft.Values>) -> some View {
        VStack(alignment: .leading, spacing: 13) {
            section("本机监听", icon: "network") {
                fieldRow {
                    field("SOCKS5 端口", text: values.socksPort, prompt: "1080")
                        .frame(width: 160)
                    field("HTTP 端口", text: values.httpPort, prompt: "8080")
                        .frame(width: 160)
                }
                hint("填 0 自动分配端口。重启代理后生效。")
                if let endpoint = core.endpoint, core.phase == .running, !core.statusReadFailed {
                    HopDisclosure("手动接入地址") {
                        fieldRow {
                            copyAddress("SOCKS5", address: endpoint.socks)
                            copyAddress("HTTP", address: endpoint.http)
                        }
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
            .accessibilityLabel("复制\(title)地址")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
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
    @ObservedObject var core: CoreModel
    let hasAdvancedEdits: Bool
    @Environment(\.dismiss) private var dismiss
    @State private var draft: AdvancedSettingsDraft?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("启动与 TUN", systemImage: "bolt.shield").font(.headline)
            if let fields = Binding($draft) {
                VStack(alignment: .leading, spacing: 9) {
                    Toggle("启动时接管系统代理", isOn: fields.values.systemProxy)
                    Toggle("启动时开启 TUN", isOn: fields.values.tunEnabled)
                    Toggle("TUN 接管 IPv6", isOn: fields.values.ipv6)
                }
                .disabled(core.saving || core.changed || hasAdvancedEdits)
                Text("IPv6 设置在下次开启 TUN 时生效。").foregroundStyle(.secondary)
                if core.changed || hasAdvancedEdits {
                    Text("请先保存或还原设置页的草稿。").foregroundStyle(HopAppearance.warning)
                } else if fields.wrappedValue.source != core.saved {
                    HStack {
                        Text("配置已更新，请重新载入。").foregroundStyle(HopAppearance.warning)
                        Button("重新载入") { draft = AdvancedSettingsDraft(source: core.saved) }
                    }
                }
                if let error = fields.wrappedValue.error {
                    Text(error).foregroundStyle(HopAppearance.warning)
                }
            } else {
                Text("无法读取已保存的配置。").foregroundStyle(.secondary)
            }

            Divider()
            let tun = core.status?.tun
            HStack {
                Menu("TUN 助手") {
                    Button(tun?.service == true ? "移除助手" : "安装助手") {
                        core.setTUNService(tun?.service != true)
                    }
                }
                .fixedSize()
                .disabled(core.phase != .running || tun?.supported != true || core.statusReadFailed || core.changingTUN)
                .help(core.phase == .stopped ? "启动代理后可管理 TUN 助手。" : "管理 TUN 助手")
                Spacer()
                Button("完成") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(core.saving ? "正在保存…" : "保存偏好", action: save)
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
