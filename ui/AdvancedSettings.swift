import Foundation
import SwiftUI

struct AdvancedSettingsDraft {
    struct Values: Equatable {
        var socksPort = "1080"
        var httpPort = "8080"
        var systemProxy = false
        var tunEnabled = false
        var ipv6 = false
        var mtu = ""
        var probeURL = ""
        var fallbackURL = ""
        var probeInterval = ""
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
        let loaded = Values(
            socksPort: String(config["socksPort"] as? Int ?? 1080),
            httpPort: String(config["httpPort"] as? Int ?? 8080),
            systemProxy: config["systemProxy"] as? Bool ?? false,
            tunEnabled: tun["enabled"] as? Bool ?? false,
            ipv6: tun["ipv6"] as? Bool ?? false,
            mtu: Self.nonzeroText(tun["mtu"]),
            probeURL: health["url"] as? String ?? "",
            fallbackURL: health["fallbackUrl"] as? String ?? "",
            probeInterval: Self.nonzeroText(health["intervalSec"])
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

    func configuration() throws -> (text: String, needsRestart: Bool, activation: String?) {
        guard var config = try JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any] else {
            throw CoreError(message: "无法读取现有配置。")
        }
        let socks = try number(values.socksPort, in: 0...65535, label: "SOCKS5 端口", blank: 1080)
        let http = try number(values.httpPort, in: 0...65535, label: "HTTP 端口", blank: 8080)
        guard socks == 0 || socks != http else { throw CoreError(message: "SOCKS5 和 HTTP 端口不能相同。") }
        let needsRestart = socks != Int(original.socksPort) || http != Int(original.httpPort)
        if values.socksPort != original.socksPort { config["socksPort"] = socks }
        if values.httpPort != original.httpPort { config["httpPort"] = http }
        if values.systemProxy != original.systemProxy { config["systemProxy"] = values.systemProxy ? true : nil }

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

        var notes: [String] = []
        if values.systemProxy != original.systemProxy || values.tunEnabled != original.tunEnabled {
            notes.append("启动选项在下次启动时使用。")
        }
        if values.ipv6 != original.ipv6 || values.mtu != original.mtu {
            notes.append("MTU 和 IPv6 设置在重新开启 TUN 时应用。")
        }
        let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        return (String(decoding: data, as: UTF8.self), needsRestart, notes.isEmpty ? nil : notes.joined())
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
    @ObservedObject var core: CoreModel
    @Binding var draft: AdvancedSettingsDraft?
    let editJSON: () -> Void

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
                        .disabled(!fields.wrappedValue.changed || core.saving || fields.wrappedValue.source != core.saved)
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

    private func controls(_ values: Binding<AdvancedSettingsDraft.Values>) -> some View {
        VStack(alignment: .leading, spacing: 13) {
            VStack(alignment: .leading, spacing: 8) {
                Text("监听端口").fontWeight(.semibold)
                HStack(spacing: 14) {
                    field("SOCKS5 端口", text: values.socksPort, prompt: "1080")
                    field("HTTP 端口", text: values.httpPort, prompt: "8080")
                }
                Text("填 0 自动分配。修改后重启代理生效。").font(.caption).foregroundStyle(.secondary)
            }
            Divider()
            VStack(alignment: .leading, spacing: 8) {
                Text("自动测速").fontWeight(.semibold)
                field("首选测速地址", text: values.probeURL, prompt: "随订阅或默认")
                field("备用测速地址", text: values.fallbackURL, prompt: "可留空")
                HStack(spacing: 8) {
                    field("自动测速间隔", text: values.probeInterval, prompt: "300")
                    Text("秒").foregroundStyle(.secondary).padding(.top, 19)
                }
                .frame(maxWidth: 190)
                Text("整组留空跟随订阅。自定义测速地址时可单独指定备用目标。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Divider()
            VStack(alignment: .leading, spacing: 8) {
                Text("启动与 TUN").fontWeight(.semibold)
                Toggle("启动时接管系统代理", isOn: values.systemProxy)
                Toggle("启动时开启 TUN", isOn: values.tunEnabled)
                Toggle("TUN 接管 IPv6", isOn: values.ipv6)
                field("TUN MTU", text: values.mtu, prompt: "9000")
                    .frame(maxWidth: 190)
                Text("重新开启 TUN 后应用 MTU 和 IPv6。旧版 TUN 助手需更新后才支持自定义 MTU。")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func field(_ title: String, text: Binding<String>, prompt: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            TextField(title, text: text, prompt: Text(prompt))
                .labelsHidden()
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
            core.saveAdvanced(candidate.text, basedOn: current.source, needsRestart: candidate.needsRestart, activation: candidate.activation)
        } catch {
            draft?.error = error.localizedDescription
        }
    }
}
