import SwiftUI

struct NodeProbeResult: Decodable {
    let name: String
    let milliseconds: Int?
    let failure: String?
    var probeKey: String?
    var inconclusive: Bool?
    var failureStage: String?
    var failureCode: String?
    var target: String?
    var checkedAt: Double?
    var lastKnownLatency: Int?
    var receivedAt = Date.now
    var fromRuntime = false

    private enum CodingKeys: String, CodingKey { case name, milliseconds, failure, probeKey, inconclusive, failureStage, failureCode, target, checkedAt }

    var isAvailable: Bool { failure == nil && inconclusive != true }
    var isFailure: Bool { failure != nil && inconclusive != true }
    var observedAt: Date { checkedAt.map { Date(timeIntervalSince1970: $0 / 1000) } ?? receivedAt }

    private var timedOut: Bool {
        if failureCode == "timeout" || failureCode == "dns-timeout" { return true }
        guard let failure = failure?.lowercased() else { return false }
        return failure.contains("timeout") || failure.contains("timed out") || failure.contains("deadline exceeded")
    }

    var status: String {
        if inconclusive == true { return "待复测" }
        if isAvailable { return "可用" }
        return timedOut ? "超时" : "失败"
    }

    func isHistorical(at date: Date) -> Bool {
        date.timeIntervalSince(observedAt) >= 15 * 60
    }

    func explanation(at date: Date) -> String {
        let source = fromRuntime ? "内核健康记录" : "手动测速"
        let time = observedAt.formatted(date: .abbreviated, time: .shortened)
        let context = [source, time, target].compactMap { $0 }.joined(separator: " · ")
        let reason = DialDiagnostic.message(failureCode, fallback: failure)
        let detail = [DialDiagnostic.stage(failureStage), reason].compactMap { $0 }.joined(separator: " · ")
        let previous = lastKnownLatency.map { "上次可用延迟 \($0) ms" }
        let age = isHistorical(at: date) ? "此记录已超过 15 分钟" : nil
        return [context, detail.isEmpty ? (isAvailable ? "节点可用" : "本次结果不足以判断节点是否可用") : detail, previous, age].compactMap { $0 }.joined(separator: "\n")
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
        case inconclusive = "待复测"
        case untested = "未测试"

        func includes(pending: Bool, result: NodeProbeResult?) -> Bool {
            if self == .all { return true }
            guard !pending else { return false }
            switch self {
            case .all: return true
            case .available: return result?.isAvailable == true
            case .failed: return result?.isFailure == true
            case .inconclusive: return result?.inconclusive == true
            case .untested: return result == nil
            }
        }
    }

    private struct Row: Identifiable {
        let node: ProxyStatus.Node
        let provider: String?
        let pending: Bool
        let result: NodeProbeResult?
        var id: String { node.probeIdentity }
        var latency: Int { result?.milliseconds ?? .max }
        var rank: Int {
            if pending { return 1 }
            if result == nil { return 2 }
            return result?.isAvailable == true ? 0 : 3
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
        let health = Dictionary((core.status?.nodes ?? []).map { ($0.probeIdentity, $0) }, uniquingKeysWith: { first, _ in first })
        let matches = core.configuredNodes.compactMap { node -> Row? in
            let provider = source[node.name]
            guard showUnavailable || !core.hiddenNodes.contains(node.probeIdentity),
                  providerID == nil || provider?.id == providerID,
                  keyword.isEmpty || node.name.localizedCaseInsensitiveContains(keyword) ||
                    node.type.localizedCaseInsensitiveContains(keyword) ||
                    provider?.name.localizedCaseInsensitiveContains(keyword) == true else { return nil }
            let pending = core.probePending.contains(node.probeIdentity)
            let result = latestReading(for: node, runtime: health[node.probeIdentity])
            guard stateFilter.includes(pending: pending, result: result) else { return nil }
            return Row(node: node, provider: provider?.name, pending: pending, result: result)
        }
        guard sortByLatency else { return matches }
        return matches.sorted {
            if $0.rank != $1.rank { return $0.rank < $1.rank }
            return $0.rank == 0 && $0.latency < $1.latency
        }
    }

    private func latestReading(for node: ProxyStatus.Node, runtime: ProxyStatus.Node?) -> NodeProbeResult? {
        let manual = core.probeResults[node.probeIdentity]
        guard let runtime, let alive = runtime.alive, let observed = runtime.healthAt else { return manual }
        let time = Date(timeIntervalSince1970: observed / 1000)
        if let manual, manual.observedAt >= time { return manual }
        return NodeProbeResult(
            name: node.name,
            milliseconds: runtime.latencyMs,
            failure: alive ? nil : runtime.error ?? "内核报告节点不可用",
            failureStage: runtime.failureStage,
            failureCode: runtime.failureCode,
            target: runtime.probeTarget,
            receivedAt: time,
            fromRuntime: true
        )
    }

    var body: some View {
        let providers = providers
        let rows = rows(providers: providers)
        let currentName = core.status?.auto?.node ?? core.status?.policy.selected
        let current = core.status?.nodes.first(where: { $0.name == currentName })?.probeIdentity
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
                .disabled(core.saving || core.refreshing || core.probeTotal > 0 || (core.configuredNodes.isEmpty && core.subscriptions.isEmpty))
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
                            if current == node.probeIdentity {
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
                            core.testNodes(row.node.name)
                        }
                        .buttonStyle(.borderless)
                        .disabled(core.probeTotal > 0 || core.saving)
                    }.width(62)
                }
                .contextMenu(forSelectionType: String.self) { selection in
                    if selection.count == 1, let id = selection.first, let node = rows.first(where: { $0.id == id })?.node {
                        Button("连接此节点") { core.connectToNode(node.name) }
                            .disabled(!core.canConnectToNode)
                        if let status = core.status, status.policy.mode != "auto",
                           status.nodes.contains(where: { $0.probeIdentity == node.probeIdentity }) {
                            Button("设为出站") {
                                core.selectNode(node, mode: status.policy.mode)
                            }
                            .disabled(core.updatingPolicy)
                        }
                    }
                } primaryAction: { selection in
                    if selection.count == 1, let id = selection.first, let node = rows.first(where: { $0.id == id })?.node {
                        core.connectToNode(node.name)
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
                TimelineView(.periodic(from: .now, by: 60)) { timeline in
                    let historical = result.isHistorical(at: timeline.date)
                    let symbol = result.isAvailable ? "checkmark.circle.fill" : result.isFailure ? "exclamationmark.circle" : "questionmark.circle"
                    Label(historical ? "历史结果" : result.status, systemImage: historical ? "clock.arrow.circlepath" : symbol)
                        .foregroundStyle(historical ? .secondary : result.isAvailable ? HopAppearance.accent : result.isFailure ? .orange : .secondary)
                        .help(result.explanation(at: timeline.date))
                }
            } else {
                Text("未测试").foregroundStyle(.secondary)
            }
        }
    }
}
