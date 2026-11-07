import SwiftUI

struct ConnectionsDashboard: View {
    @ObservedObject var core: CoreModel
    @State private var query = ""
    @State private var scope = Scope.all
    @State private var selection: String?

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
        let generation: Double?
        var id: String { "\(generation ?? 0):\(connection.id)" }
    }

    var body: some View {
        let all = core.status?.connections ?? []
        let keyword = query.trimmingCharacters(in: .whitespacesAndNewlines)
        let rows = all
            .filter { row in
                scope.includes(row) && (keyword.isEmpty ||
                    [row.target, row.via, row.inboundLabel, row.stateLabel, row.rule, row.process ?? "",
                     row.processPath ?? "", row.server ?? ""].contains { $0.localizedCaseInsensitiveContains(keyword) })
            }
            .sorted { lhs, rhs in
                if (lhs.state == "active") != (rhs.state == "active") { return lhs.state == "active" }
                return lhs.id > rhs.id
            }
            .map { Row(connection: $0, generation: core.status?.reloaded) }
        let selected = rows.first { $0.id == selection }?.connection
        VStack(alignment: .leading, spacing: 12) {
            HopPageHeading(title: "连接", detail: core.status == nil
                           ? "查看应用、出站和匹配规则。"
                           : "\(core.status?.active ?? 0) 个活动 · \(all.filter(Scope.failed.includes).count) 个失败 · \(all.filter(Scope.blocked.includes).count) 个拦截")
            if let drops = core.status?.udpDrops, !drops.isEmpty {
                HStack(spacing: 12) {
                    Label("本机 UDP 丢弃", systemImage: "exclamationmark.circle")
                    ForEach(drops.keys.sorted(), id: \.self) { inbound in
                        if let counts = drops[inbound] {
                            Text("\(inbound) \(counts.total.formatted()) 包")
                                .monospacedDigit()
                                .help(counts.detail)
                                .accessibilityLabel("\(inbound) · \(counts.detail)")
                        }
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
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
                Text("显示 \(rows.count) / \(all.count)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            if rows.isEmpty {
                ContentUnavailableView(
                    all.isEmpty ? "暂无连接" : "没有匹配的连接",
                    systemImage: all.isEmpty ? "arrow.left.arrow.right" : "magnifyingglass",
                    description: Text(all.isEmpty ? "代理收到流量后，连接会显示在这里。" : "调整关键词或连接状态。")
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                table(rows).frame(minHeight: 125)
                if let selected {
                    detail(selected)
                } else {
                    Text("选中一条连接可查看完整路由、服务器和阶段耗时。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func table(_ rows: [Row]) -> some View {
        Table(rows, selection: $selection) {
            TableColumn("目标") { Text($0.connection.target).lineLimit(1).help($0.connection.diagnosis) }
                .width(min: 120, ideal: 150)
            TableColumn("应用") { Text($0.connection.process ?? "—").lineLimit(1) }
                .width(min: 58, ideal: 90)
            TableColumn("出站") { Text($0.connection.via).lineLimit(1) }
                .width(min: 64, ideal: 90)
            TableColumn("规则") { Text($0.connection.rule).lineLimit(1) }
                .width(min: 56, ideal: 95)
            TableColumn("状态") { row in
                Text(row.connection.stateLabel)
                    .foregroundStyle(row.connection.state == "active" ? HopAppearance.accent :
                                        Scope.failed.includes(row.connection) ? Color.orange : .secondary)
            }.width(63)
            TableColumn("上传 / 下载") { row in
                let connection = row.connection
                Text("\(trafficBytes(UInt64(clamping: connection.sent))) / \(trafficBytes(UInt64(clamping: connection.received)))")
                    .monospacedDigit()
                    .lineLimit(1)
                    .help("\(connection.sent.formatted()) B / \(connection.received.formatted()) B")
            }.width(min: 105, ideal: 130)
        }
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
            let context = [row.process.map { "应用 \($0)" }, row.server.map { "服务器 \($0)" },
                           row.start.map { Date(timeIntervalSince1970: $0 / 1000).formatted(date: .omitted, time: .standard) }]
                .compactMap { $0 }.joined(separator: " · ")
            if !context.isEmpty { Text(context).foregroundStyle(.secondary).lineLimit(1).help(context) }
            if !row.timingLabel.isEmpty {
                Text(row.timingLabel).font(.caption).monospacedDigit().foregroundStyle(.secondary)
            }
            if let failure = row.failureStage ?? row.failureMessage {
                let explanation = [row.failureStage, row.failureMessage].compactMap { $0 }.joined(separator: " · ")
                Label(explanation.isEmpty ? failure : explanation, systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .lineLimit(2)
                    .textSelection(.enabled)
                    .help(explanation)
            }
            if let failures = row.failures, failures.count > 1 || row.state == "active" || row.state == "closed" {
                ForEach(Array(failures.enumerated()), id: \.offset) { _, failure in
                    Text(failure.label)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .help(failure.label)
                }
            }
        }
        .font(.callout)
        .hopPanel()
    }
}
