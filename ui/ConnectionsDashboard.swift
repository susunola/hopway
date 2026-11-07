import SwiftUI

struct ConnectionsDashboard: View {
    @ObservedObject var core: CoreModel
    @State private var query = ""
    @State private var scope = Scope.all
    @State private var selection: String?
    @State private var showsUDP = false

    private enum Scope: String, CaseIterable {
        case all = "全部状态"
        case active = "传输中"
        case closed = "已结束"
        case failed = "失败"
        case blocked = "已拦截"

        func includes(_ row: ProxyStatus.Connection) -> Bool {
            switch self {
            case .all: true
            case .active: row.state == "active"
            case .closed: row.state == "closed"
            case .blocked: row.state == "blocked"
            case .failed: row.state != "active" && row.state != "closed" && row.state != "blocked" && row.state != "canceled"
            }
        }
    }

    private struct Row: Identifiable {
        let connection: ProxyStatus.Connection
        let generation: UInt64?
        var id: String { "\(generation ?? 0):\(connection.id)" }
    }

    var body: some View {
        let all = core.connections
        let keyword = query.trimmingCharacters(in: .whitespacesAndNewlines)
        let rows = all
            .filter { row in
                scope.includes(row) && (keyword.isEmpty ||
                    [row.target, row.via, row.inboundLabel, row.stateLabel, row.rule, row.process ?? "",
                     row.processPath ?? "", row.processBundleId ?? "", row.server ?? ""].contains { $0.localizedCaseInsensitiveContains(keyword) })
            }
            .sorted { lhs, rhs in
                if (lhs.state == "active") != (rhs.state == "active") { return lhs.state == "active" }
                return lhs.id > rhs.id
            }
            .map { Row(connection: $0, generation: core.status?.generation) }
        let selected = rows.first { $0.id == selection }?.connection
        VStack(alignment: .leading, spacing: HopAppearance.pageSpacing) {
            HopPageHeading(title: "连接", detail: core.status.map { "\($0.active) 个活动连接" }
                           ?? "查看流量去了哪里")
            if core.connectionReadFailed || core.statusReadFailed {
                Label(core.connectionReadAt.map {
                    "连接暂未更新 · 上次读取 " + $0.formatted(date: .omitted, time: .standard)
                } ?? "暂时无法读取连接", systemImage: "exclamationmark.circle")
                .font(.caption).foregroundStyle(HopAppearance.warning)
            }
            HStack(spacing: 12) {
                HopSearchField(placeholder: "筛选目标、应用、节点或规则", text: $query)
                    .frame(minWidth: 180, idealWidth: 255, maxWidth: 290)
                Picker("连接状态", selection: $scope) {
                    ForEach(Scope.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                .labelsHidden()
                .fixedSize()
                Spacer()
                if !all.isEmpty {
                    Text("显示 \(rows.count) / \(all.count)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                if let drops = core.status?.udpDrops, !drops.isEmpty {
                    Button("UDP 诊断") { showsUDP.toggle() }
                        .popover(isPresented: $showsUDP, arrowEdge: .bottom) {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("本机 UDP 丢弃").font(.headline)
                                ForEach(drops.keys.sorted(), id: \.self) { inbound in
                                    if let counts = drops[inbound] {
                                        Text(inbound).font(.callout.weight(.semibold))
                                        Text(counts.detail).font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                            }
                            .padding(16)
                        }
                }
            }
            if rows.isEmpty {
                ContentUnavailableView(
                    all.isEmpty ? "暂无连接" : "没有匹配的连接",
                    systemImage: all.isEmpty ? "arrow.left.arrow.right" : "magnifyingglass",
                    description: Text(all.isEmpty ? "代理收到流量后，连接会显示在这里。" : "调整关键词或连接状态。")
                )
                .frame(maxWidth: .infinity)
                .padding(.top, 20)
                Spacer(minLength: 0)
            } else {
                table(rows).frame(minHeight: 125,
                                  maxHeight: rows.count < 8 ? CGFloat(max(125, 37 + 24 * rows.count)) : .infinity)
                if let selected {
                    detail(selected)
                } else {
                    Text("选中连接可查看匹配规则和详细信息。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if rows.count < 8 { Spacer(minLength: 0) }
            }
        }
        .onAppear { core.watchConnections(true) }
        .onDisappear { core.watchConnections(false) }
    }

    private func table(_ rows: [Row]) -> some View {
        Table(rows, selection: $selection) {
            TableColumn("目标") { Text($0.connection.target).lineLimit(1).help($0.connection.diagnosis) }
                .width(min: 140, ideal: 174)
            TableColumn("应用") { Text($0.connection.process ?? "—").lineLimit(1) }
                .width(80)
            TableColumn("出站") { Text($0.connection.via).lineLimit(1) }
                .width(96)
            TableColumn("状态") { row in
                Text(row.connection.stateLabel)
                    .foregroundStyle(row.connection.state == "active" ? HopAppearance.accent :
                                        Scope.failed.includes(row.connection) ? HopAppearance.warning : .secondary)
            }.width(60)
            TableColumn("上传 / 下载") { row in
                let connection = row.connection
                Text("\(connectionBytes(connection.sent)) / \(connectionBytes(connection.received))")
                    .monospacedDigit()
                    .lineLimit(1)
                    .help("\(connection.sent.formatted()) B / \(connection.received.formatted()) B")
            }.width(125)
        }
        .alternatingRowBackgrounds(rows.count < 8 ? .disabled : .enabled)
    }

    private func connectionBytes(_ count: Int64) -> String {
        let bytes = UInt64(clamping: count)
        return bytes < 1024 ? "\(bytes) B" : trafficBytes(bytes)
    }

    private func detail(_ row: ProxyStatus.Connection) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack {
                Text(row.target).font(.headline).textSelection(.enabled).lineLimit(1)
                Spacer()
                Text(row.stateLabel).font(.caption).foregroundStyle(.secondary)
                Button { selection = nil } label: { Image(systemName: "xmark") }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("关闭连接详情")
            }
            Text("\(row.inboundLabel) · \(row.rule) · " + row.routeLabel)
                .lineLimit(1)
                .help(row.routeLabel)
            if let source = row.targetSourceLabel {
                Text("目标来源 · " + source).font(.caption).foregroundStyle(.secondary)
            }
            if let failure = row.failureStage ?? row.failureMessage {
                let explanation = [row.failureStage, row.failureMessage].compactMap { $0 }.joined(separator: " · ")
                Label(explanation.isEmpty ? failure : explanation, systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(HopAppearance.warning)
                    .lineLimit(2)
                    .textSelection(.enabled)
                    .help(explanation)
            }
            DisclosureGroup("诊断详情") {
                VStack(alignment: .leading, spacing: 6) {
                    let context = [row.process.map { "应用 \($0)" }, row.server.map { "服务器 \($0)" },
                                   row.start.map { Date(timeIntervalSince1970: $0 / 1000).formatted(date: .omitted, time: .standard) }]
                        .compactMap { $0 }.joined(separator: " · ")
                    if !context.isEmpty { Text(context).lineLimit(1).help(context) }
                    if let bundleID = row.processBundleId { Text("应用标识 · " + bundleID) }
                    if !row.timingLabel.isEmpty { Text(row.timingLabel).monospacedDigit() }
                    if let failures = row.failures, failures.count > 1 || row.state == "active" || row.state == "closed" {
                        ForEach(Array(failures.enumerated()), id: \.offset) { _, failure in
                            Text(failure.label).lineLimit(1).help(failure.label)
                        }
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .padding(.top, 5)
            }
        }
        .font(.callout)
        .hopPanel()
    }
}
