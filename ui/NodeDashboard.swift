import SwiftUI

struct NodeProbeResult: Decodable {
    let name: String
    let milliseconds: Int?
    let failure: String?
    var receivedAt = Date.now
    var fromRuntime = false

    private enum CodingKeys: String, CodingKey { case name, milliseconds, failure }

    private var timedOut: Bool {
        guard let failure = failure?.lowercased() else { return false }
        return failure.contains("timeout") || failure.contains("timed out") || failure.contains("deadline exceeded")
    }

    var status: String {
        if failure == nil { return "可用" }
        return timedOut ? "超时" : "失败"
    }

    var explanation: String {
        let source = fromRuntime ? "内核健康记录" : "手动测速"
        let time = receivedAt.formatted(date: .omitted, time: .shortened)
        return "\(source) · \(time)\n" + (failure ?? (fromRuntime ? "节点当前可用" : "节点已通过 HTTPS 测试"))
    }
}

struct NodeDashboard: View {
    @ObservedObject var core: CoreModel
    let importLink: () -> Void
    @State private var filter = ""
    @State private var selectedNode: String?
    @State private var sortByLatency = false
    @State private var showUnavailable = false

    @State private var providerID: String?
    @State private var stateFilter = StateFilter.all

    private enum StateFilter: String, CaseIterable {
        case all = "全部状态"
        case available = "可用"
        case failed = "失败或超时"
        case untested = "未测试"

        func includes(pending: Bool, result: NodeProbeResult?) -> Bool {
            if self == .all { return true }
            guard !pending else { return false }
            switch self {
            case .all: return true
            case .available: return result != nil && result?.failure == nil
            case .failed: return result?.failure != nil
            case .untested: return result == nil
            }
        }
    }

    private struct Row: Identifiable {
        let node: ProxyStatus.Node
        let provider: String?
        let pending: Bool
        let result: NodeProbeResult?
        var id: String { node.name }
        var latency: Int { result?.milliseconds ?? .max }
        var rank: Int {
            if pending { return 1 }
            if result == nil { return 2 }
            return result?.failure == nil ? 0 : 3
        }
    }

    private var providers: [SubscriptionSummary] {
        core.subscriptions.filter { !$0.isPaused && !($0.nodes ?? []).isEmpty }
    }

    private func rows(providers: [SubscriptionSummary]) -> [Row] {
        var source: [String: SubscriptionSummary] = [:]
        for provider in providers {
            for name in provider.nodes ?? [] where source[name] == nil {
                source[name] = provider
            }
        }
        let keyword = filter.trimmingCharacters(in: .whitespacesAndNewlines)
        let health = Dictionary(uniqueKeysWithValues: (core.status?.nodes ?? []).map { ($0.name, $0) })
        let matches = core.configuredNodes.compactMap { node -> Row? in
            let provider = source[node.name]
            guard showUnavailable || !core.hiddenNodes.contains(node.name),
                  providerID == nil || provider?.id == providerID,
                  keyword.isEmpty || node.name.localizedCaseInsensitiveContains(keyword) ||
                    node.type.localizedCaseInsensitiveContains(keyword) ||
                    provider?.name.localizedCaseInsensitiveContains(keyword) == true else { return nil }
            let pending = core.probePending.contains(node.name)
            let result = latestReading(for: node.name, runtime: health[node.name])
            guard stateFilter.includes(pending: pending, result: result) else { return nil }
            return Row(node: node, provider: provider?.name, pending: pending, result: result)
        }
        guard sortByLatency else { return matches }
        return matches.sorted {
            if $0.rank != $1.rank { return $0.rank < $1.rank }
            return $0.rank == 0 && $0.latency < $1.latency
        }
    }

    private func latestReading(for name: String, runtime: ProxyStatus.Node?) -> NodeProbeResult? {
        let manual = core.probeResults[name]
        guard let runtime, let alive = runtime.alive, let observed = runtime.healthAt else { return manual }
        let time = Date(timeIntervalSince1970: observed / 1000)
        if let manual, manual.receivedAt >= time { return manual }
        return NodeProbeResult(
            name: name,
            milliseconds: runtime.latencyMs,
            failure: alive ? nil : runtime.error ?? "内核报告节点不可用",
            receivedAt: time,
            fromRuntime: true
        )
    }

    var body: some View {
        let providers = providers
        let rows = rows(providers: providers)
        let current = core.status?.auto?.node ?? core.status?.policy.selected
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center) {
                HopPageHeading(title: "节点", detail: rows.count == core.configuredNodes.count
                               ? "\(rows.count) 个节点" : "显示 \(rows.count) / \(core.configuredNodes.count) 个节点")
                Spacer()
                Menu {
                    Button("输入链接…", action: importLink)
                    Button("从剪贴板导入", action: core.importClipboard)
                } label: {
                    Label("导入节点", systemImage: "square.and.arrow.down")
                }
                .fixedSize()
                .disabled(core.saving)
                Button(action: core.refreshNodes) {
                    Label("刷新节点", systemImage: "arrow.clockwise")
                }
                .disabled(core.saving || core.probeTotal > 0 || (core.configuredNodes.isEmpty && core.subscriptions.isEmpty))
                if core.probeTotal > 0 {
                    Button("停止测速", action: core.cancelProbe)
                } else {
                    Button {
                        sortByLatency = true
                        core.testNodes()
                    } label: {
                        Label("一键测速", systemImage: "gauge.with.dots.needle.67percent")
                    }
                    .buttonStyle(HopPrimaryButton())
                    .disabled(core.configuredNodes.isEmpty || core.saving)
                }
            }
            if !core.configuredNodes.isEmpty {
                HStack {
                    HopSearchField(placeholder: "搜索节点、协议或订阅", text: $filter)
                        .frame(minWidth: 140, idealWidth: 210, maxWidth: 245)
                    if !providers.isEmpty {
                        Picker("订阅来源", selection: $providerID) {
                            Text("全部订阅").tag(String?.none)
                            ForEach(providers) { provider in
                                Text(provider.name).tag(Optional(provider.id))
                            }
                        }
                        .labelsHidden()
                        .accessibilityLabel("订阅来源")
                        .frame(maxWidth: 145)
                    }
                    Picker("节点状态", selection: $stateFilter) {
                        ForEach(StateFilter.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                    }
                    .labelsHidden()
                    .fixedSize()
                    Spacer()
                    if !core.hiddenNodes.isEmpty {
                        Toggle("显示暂不可用（\(core.hiddenNodes.count)）", isOn: $showUnavailable)
                            .toggleStyle(.checkbox)
                    }
                    Toggle("按延迟排序", isOn: $sortByLatency)
                        .toggleStyle(.checkbox)
                }
            }
            if core.probeTotal > 0 {
                ProgressView(
                    "已完成 \(core.probeTotal - core.probePending.count) / \(core.probeTotal)",
                    value: Double(core.probeTotal - core.probePending.count),
                    total: Double(core.probeTotal)
                )
            }
            if core.configuredNodes.isEmpty {
                ContentUnavailableView {
                    Label("还没有节点", systemImage: "point.3.connected.trianglepath.dotted")
                } description: {
                    Text("导入订阅后，节点和测速状态会显示在这里。")
                } actions: {
                    Button("导入链接…", action: importLink).disabled(core.saving)
                }
            } else if rows.isEmpty {
                ContentUnavailableView(
                    "没有可显示的节点", systemImage: "magnifyingglass",
                    description: Text(core.hiddenNodes.isEmpty || showUnavailable
                        ? "试试其他关键词或订阅。"
                        : "可以清除筛选，或显示暂不可用的节点。")
                )
            } else {
                Table(rows, selection: $selectedNode) {
                    TableColumn("节点名称") { row in
                        let node = row.node
                        let location = NodeLocation(name: node.name)
                        HStack(spacing: 8) {
                            Group {
                                if let flag = location.flag, !location.isSubscriptionNotice {
                                    Text(flag).font(.system(size: 16))
                                } else {
                                    Image(systemName: "globe")
                                        .font(.system(size: 12))
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .frame(width: 22)
                            .accessibilityHidden(true)
                            Text(location.title).lineLimit(1).help(node.name)
                            if current == node.name {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(HopAppearance.accent)
                                    .help("当前选定出站")
                                    .accessibilityLabel("当前选定出站")
                            }
                        }
                    }.width(min: 155, ideal: 265)
                    TableColumn("协议") {
                        Text($0.node.type.uppercased())
                            .font(.caption.weight(.medium))
                            .foregroundStyle(.secondary)
                    }.width(min: 70, ideal: 84)
                    TableColumn("订阅") { row in
                        Text(row.provider ?? "本地").lineLimit(1)
                            .foregroundStyle(.secondary)
                            .help(row.provider ?? "本地节点")
                    }.width(min: 58, ideal: 105)
                    TableColumn("状态") { row in statusCell(row) }.width(min: 72, ideal: 86)
                    TableColumn("延迟") { row in
                        if row.rank == 0, let milliseconds = row.result?.milliseconds {
                            Text("\(milliseconds) ms").monospacedDigit()
                        } else {
                            Text("—").foregroundStyle(.secondary)
                        }
                    }.width(min: 64, ideal: 78)
                    TableColumn("操作") { row in
                        Button("测速") {
                            sortByLatency = true
                            core.testNodes(row.id)
                        }
                        .buttonStyle(.borderless)
                        .disabled(core.probeTotal > 0 || core.saving)
                    }.width(62)
                }
                .contextMenu(forSelectionType: String.self) { selection in
                    if selection.count == 1, let name = selection.first {
                        Button("连接此节点") { core.connectToNode(name) }
                            .disabled(!core.canConnectToNode)
                        if let status = core.status, status.policy.mode != "auto",
                           status.nodes.contains(where: { $0.name == name }) {
                            Button("设为出站") {
                                core.updatePolicy(Policy(mode: status.policy.mode, selected: name))
                            }
                            .disabled(core.updatingPolicy)
                        }
                    }
                } primaryAction: { selection in
                    if selection.count == 1, let name = selection.first {
                        core.connectToNode(name)
                    }
                }
                Text("双击节点即可连接。将鼠标移到状态上可查看测试来源、时间和失败原因。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .onChange(of: providers.map(\.id)) { _, ids in
            if let providerID, !ids.contains(providerID) { self.providerID = nil }
        }
    }

    private func statusCell(_ row: Row) -> some View {
        Group {
            if row.pending {
                Label("测试中", systemImage: "clock").foregroundStyle(.secondary)
            } else if let result = row.result {
                Label(result.status, systemImage: result.failure == nil ? "checkmark.circle.fill" : "exclamationmark.circle")
                    .foregroundStyle(result.failure == nil ? HopAppearance.accent : .orange)
                    .help(result.explanation)
            } else {
                Text("未测试").foregroundStyle(.secondary)
            }
        }
    }
}
