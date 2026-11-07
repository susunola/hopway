import SwiftUI

struct NodeProbeResult: Decodable {
    let name: String
    let milliseconds: Int?
    let failure: String?

    private var timedOut: Bool {
        guard let failure = failure?.lowercased() else { return false }
        return failure.contains("timeout") || failure.contains("timed out") || failure.contains("deadline exceeded")
    }

    var status: String {
        if failure == nil { return "可用" }
        return timedOut ? "超时" : "失败"
    }

    var explanation: String {
        failure ?? "节点已通过 HTTPS 测试"
    }
}

struct NodeDashboard: View {
    @ObservedObject var core: CoreModel
    let importLink: () -> Void
    @State private var filter = ""
    @State private var selectedNode: String?
    @State private var sortByLatency = false
    @State private var showUnavailable = false

    private var rows: [ProxyStatus.Node] {
        let matches = core.configuredNodes.filter {
            (showUnavailable || !core.hiddenNodes.contains($0.name)) &&
                (filter.isEmpty || $0.name.localizedCaseInsensitiveContains(filter) || $0.type.localizedCaseInsensitiveContains(filter))
        }
        guard sortByLatency else { return matches }
        return matches.sorted { latencyRank($0.name) < latencyRank($1.name) }
    }

    private func latencyRank(_ name: String) -> Int {
        guard !core.probePending.contains(name), let result = core.probeResults[name],
              result.failure == nil else { return .max }
        return result.milliseconds ?? .max
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center) {
                HopPageHeading(title: "节点", detail: "\(core.configuredNodes.count) 个节点")
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
                    HopSearchField(placeholder: "搜索名称或协议", text: $filter)
                        .frame(width: 215)
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
                    description: Text(core.hiddenNodes.isEmpty ? "试试其他关键词。" : "可开启「显示暂不可用」查看已隐藏的节点。")
                )
            } else {
                Table(rows, selection: $selectedNode) {
                    TableColumn("节点名称") { node in
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
                            if (core.status?.auto?.node ?? core.status?.policy.selected) == node.name {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(HopAppearance.accent)
                                    .help("当前选定出站")
                                    .accessibilityLabel("当前选定出站")
                            }
                        }
                    }.width(min: 155, ideal: 265)
                    TableColumn("协议") {
                        Text($0.type.uppercased())
                            .font(.caption.weight(.medium))
                            .foregroundStyle(.secondary)
                    }.width(min: 70, ideal: 84)
                    TableColumn("状态") { node in statusCell(node.name) }.width(min: 85, ideal: 100)
                    TableColumn("延迟") { node in
                        if !core.probePending.contains(node.name), let result = core.probeResults[node.name],
                           result.failure == nil, let milliseconds = result.milliseconds {
                            Text("\(milliseconds) ms").monospacedDigit()
                        } else {
                            Text("—").foregroundStyle(.secondary)
                        }
                    }.width(min: 85, ideal: 100)
                    TableColumn("操作") { node in
                        Button("测速") {
                            sortByLatency = true
                            core.testNodes(node.name)
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
                Text("双击节点即可连接。连续两次失败的节点会暂时隐藏，复测成功后自动显示。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func statusCell(_ name: String) -> some View {
        Group {
            if core.probePending.contains(name) {
                Label("测试中", systemImage: "clock").foregroundStyle(.secondary)
            } else if let result = core.probeResults[name] {
                Label(result.status, systemImage: result.failure == nil ? "checkmark.circle.fill" : "exclamationmark.circle")
                    .foregroundStyle(result.failure == nil ? Color.green : .orange)
                    .help(result.explanation)
            } else {
                Text("未测试").foregroundStyle(.secondary)
            }
        }
    }
}
