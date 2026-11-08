import Foundation
import SwiftUI

struct AutoRoutingConfig: Codable, Equatable {
    struct Group: Codable, Equatable {
        let name: String
        let providerId: String?
        let nodes: [String]
    }

    let region: String
    let groups: [Group]
}

struct AutoRoutingStatus: Decodable, Equatable {
    struct Switch: Decodable, Equatable {
        let from: String?
        let to: String?
        let provider: String?
        let reason: String
        let at: Int64

        /// What the console says about the last automatic move. The engine
        /// only keeps the latest change, so this explains the route in use.
        var label: String {
            switch reason {
            case "failover": L("节点失败，已切换")
            case "latency": L("延迟更优，已切换")
            case "fastest": L("按延迟选中")
            case "provider": L("服务商不可用，已更换")
            case "exhausted": L("没有可用节点，已阻断")
            default: L("已切换")
            }
        }

        var detail: String {
            switch (from, to) {
            case let (from?, to?): "\(from) → \(to)"
            case let (nil, to?): to
            case let (from?, nil): from
            default: ""
            }
        }
    }

    let provider: String?
    let node: String?
    let probing: Bool
    let candidates: Int?
    let lastSwitch: Switch?
}

struct AutoRoutingSheet: View {
    @Environment(\.locale) private var interfaceLocale
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var core: CoreModel
    @State private var region = ""
    @State private var preferred = ""

    private var eligibleNodes: [String: String] {
        Dictionary(uniqueKeysWithValues: (core.status?.nodes ?? []).compactMap { node in
            NodeLocation(name: node.name).regionCode.map { (node.name, $0) }
        })
    }

    private var regions: [String] {
        let nodes = eligibleNodes
        return Set(core.subscriptions.flatMap { ($0.nodes ?? []).compactMap { nodes[$0] } })
            .sorted { regionName($0).localizedStandardCompare(regionName($1)) == .orderedAscending }
    }

    private var availableProviders: [SubscriptionSummary] {
        let nodes = eligibleNodes
        return core.subscriptions.filter { subscription in
            (subscription.nodes ?? []).contains { nodes[$0] == region }
        }
    }

    var body: some View {
        let _ = interfaceLocale
        VStack(alignment: .leading, spacing: 15) {
            HopPageHeading(title: L("自动选路"), detail: L("为新连接在同一地区选择服务商和节点。"))
            if regions.isEmpty {
                Text(L("需要至少一份已关联节点的订阅。请用原订阅链接重新导入，或重启代理以载入新节点。"))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                HStack(alignment: .top, spacing: 12) {
                    HopLabeledControl(title: L("地区")) {
                        HopSelectionMenu(title: L("地区"), value: region.isEmpty ? L("请选择地区") : regionName(region),
                                         labelWidth: 176, selection: $region) {
                            Text(L("请选择地区")).tag("")
                            ForEach(regions, id: \.self) { code in
                                Text(regionName(code)).tag(code)
                            }
                        }
                    }
                    .frame(width: 215)
                    HopLabeledControl(title: L("首选服务商")) {
                        HopSelectionMenu(title: L("首选服务商"),
                                         value: availableProviders.first { $0.id == preferred }?.name ?? L("按导入顺序"),
                                         labelWidth: 176, selection: $preferred) {
                            Text(L("按导入顺序")).tag("")
                            ForEach(availableProviders) { subscription in
                                Text(subscription.name).tag(subscription.id)
                            }
                        }
                        .disabled(region.isEmpty)
                    }
                    .frame(width: 215)
                }
                Text(L("首选服务商不可用时按导入顺序尝试备用。同一服务商内会保持当前节点，直到测速确认需要切换。"))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button(L("取消")) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(L("启用自动选路"), action: enable)
                    .buttonStyle(HopPrimaryButton())
                    .keyboardShortcut(.defaultAction)
                    .disabled(region.isEmpty || availableProviders.isEmpty || core.updatingPolicy)
            }
        }
        .padding(24)
        .frame(width: 490)
        .onChange(of: region) { _, _ in preferred = "" }
    }

    private func regionName(_ code: String) -> String {
        interfaceLocale.localizedString(forRegionCode: code) ?? code
    }

    private func enable() {
        guard let policy = core.status?.policy else { return }
        let nodes = eligibleNodes
        var providers = availableProviders
        if let index = providers.firstIndex(where: { $0.id == preferred }) {
            let first = providers.remove(at: index)
            providers.insert(first, at: 0)
        }
        let groups = providers.map { provider in
            AutoRoutingConfig.Group(name: provider.name, providerId: provider.id, nodes: (provider.nodes ?? []).filter { nodes[$0] == region })
        }
        let auto = AutoRoutingConfig(region: regionName(region), groups: groups)
        core.updatePolicy(Policy(mode: "auto", selected: policy.selected, auto: auto))
        dismiss()
    }
}
