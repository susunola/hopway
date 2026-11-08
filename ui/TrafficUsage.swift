import Charts
import Foundation
import SwiftUI

struct TrafficHistory: Decodable, Sendable {
    struct Count: Decodable, Equatable, Sendable {
        var upload: UInt64 = 0
        var download: UInt64 = 0
        var total: UInt64 { Self.sum(upload, download) }

        mutating func add(_ count: Count) {
            upload = Self.sum(upload, count.upload)
            download = Self.sum(download, count.download)
        }

        private static func sum(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
            let (sum, overflow) = lhs.addingReportingOverflow(rhs)
            return overflow ? .max : sum
        }
    }

    struct Day: Identifiable {
        let date: Date
        let nodes: [String: Count]
        let count: Count
        var id: Date { date }
    }

    let since: String
    let days: [String: [String: Count]]
    private let through: UInt64?

    private struct Batch: Decodable {
        let since: String
        let sequence: UInt64
        let days: [String: [String: Count]]
    }

    struct DiskStamp: Equatable, Sendable {
        let checkpoint: Date?
        let journal: Date?
    }

    static func stamp(at url: URL) -> DiskStamp {
        func modified(_ file: URL) -> Date? {
            let attributes = try? FileManager.default.attributesOfItem(atPath: file.path)
            return attributes?[.modificationDate] as? Date
        }
        return DiskStamp(checkpoint: modified(url), journal: modified(url.appendingPathExtension("journal")))
    }

    static func load(at url: URL) -> TrafficHistory? {
        let journal = url.appendingPathExtension("journal")
        let decoder = JSONDecoder()
        // Capture names before reading the snapshot. Compaction installs the
        // snapshot before removing its batches, so disappearing files are
        // covered by a newer snapshot.
        for _ in 0..<2 {
            let files = ((try? FileManager.default.contentsOfDirectory(atPath: journal.path)) ?? []).sorted()
            let snapshot = (try? Data(contentsOf: url)).flatMap { try? decoder.decode(Self.self, from: $0) }
            var since = snapshot?.since
            var days = snapshot?.days ?? [:]
            var through = snapshot?.through ?? 0
            var removed = false
            for name in files {
                guard name.utf8.count == 25, name.hasSuffix(".json"),
                      let sequence = UInt64(name.prefix(20)), sequence > through,
                      name == String(format: "%020llu.json", sequence) else { continue }
                let data: Data
                do {
                    data = try Data(contentsOf: journal.appendingPathComponent(name))
                } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
                    removed = true
                    break
                } catch {
                    continue
                }
                guard let batch = try? decoder.decode(Batch.self, from: data), batch.sequence == sequence else { continue }
                since = since ?? batch.since
                for (day, nodes) in batch.days {
                    days[day, default: [:]].merge(nodes) { _, new in new }
                }
                through = sequence
            }
            if !removed { return since.map { Self(since: $0, days: days, through: through) } }
        }
        return nil
    }

    func series(from start: Date, through end: Date, calendar: Calendar, includeLeadingDays: Bool = false) -> [Day] {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = calendar
        formatter.timeZone = calendar.timeZone
        formatter.dateFormat = "yyyy-MM-dd"
        guard let since = formatter.date(from: since) else { return [] }
        var date = includeLeadingDays ? start : max(since, start)
        var result: [Day] = []
        while date <= end {
            let nodes = days[formatter.string(from: date)] ?? [:]
            var total = Count()
            for count in nodes.values { total.add(count) }
            result.append(Day(date: date, nodes: nodes, count: total))
            guard let next = calendar.date(byAdding: .day, value: 1, to: date) else { break }
            date = next
        }
        return result
    }
}

struct TrafficRate: Equatable {
    let upload: Double
    let download: Double

    static func label(_ bytesPerSecond: Double) -> String {
        let bytes = UInt64(min(bytesPerSecond.rounded(), Double(Int64.max)))
        return bytes == 0 ? "0 KB/s" : trafficBytes(bytes) + "/s"
    }
}

struct TrafficDashboard: View {
    @Environment(\.locale) private var interfaceLocale
    @ObservedObject var core: CoreModel

    var body: some View {
        let _ = interfaceLocale
        ScrollView {
            VStack(alignment: .leading, spacing: HopAppearance.pageSpacing) {
                HopPageHeading(title: L("用量"), detail: L("监测本机经过 HopWay 的流量"))
                liveMonitor.hopPanel(verticalPadding: 10)
                LocalTrafficView(history: core.trafficHistory, subscriptions: core.subscriptions)
                    .hopPanel()
            }
            .padding(.bottom, 12)
        }
        .scrollBounceBehavior(.basedOnSize)
    }

    private var liveMonitor: some View {
        let running = core.phase == .running
        let rate = running ? core.liveTraffic : nil
        return HStack(spacing: 18) {
            Label(L("实时流量"), systemImage: "waveform.path").labelStyle(HopSectionLabelStyle())
            if let rate {
                Spacer()
                liveMetric(L("下载"), rate.download)
                liveMetric(L("上传"), rate.upload)
            } else {
                Spacer()
                Text(running ? L("等待流量数据") : L(core.phase.rawValue))
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func liveMetric(_ title: String, _ rate: Double) -> some View {
        HStack(spacing: 6) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(TrafficRate.label(rate)).font(.callout.weight(.semibold).monospacedDigit())
        }
        .frame(width: 132, alignment: .leading)
    }
}

struct LocalTrafficView: View {
    @Environment(\.locale) private var interfaceLocale
    let history: TrafficHistory?
    let subscriptions: [SubscriptionSummary]
    @State private var period = Period.fortnight
    @State private var source = Source.all
    @State private var node: String?

    private enum Source: Hashable {
        case all, direct, proxy, subscription(String)
    }

    private enum Period: String, CaseIterable {
        case today = "今天"
        case fortnight = "近 14 天"
        case month = "本月"

        func start(before today: Date, calendar: Calendar) -> Date {
            switch self {
            case .today: today
            case .fortnight: calendar.date(byAdding: .day, value: -13, to: today) ?? today
            case .month: calendar.dateInterval(of: .month, for: today)?.start ?? today
            }
        }
    }

    private struct Node: Identifiable {
        let name: String
        let provider: String
        let count: TrafficHistory.Count
        var id: String { name }
    }

    private struct Report {
        var days: [TrafficHistory.Day] = []
        var nodes: [Node] = []
        var eligibleNodes: [String] = []
        var total = TrafficHistory.Count()
    }

    private var report: Report {
        guard let history else { return Report() }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = .current
        let today = calendar.startOfDay(for: .now)
        let start = period.start(before: today, calendar: calendar)
        var providers: [String: [SubscriptionSummary]] = [:]
        for subscription in subscriptions {
            for name in Set(subscription.nodes ?? []) {
                providers[name, default: []].append(subscription)
            }
        }
        func matchesSource(_ name: String) -> Bool {
            switch source {
            case .all: true
            case .direct: name == "DIRECT"
            case .proxy: name != "DIRECT"
            case .subscription(let id): name != "DIRECT" && providers[name]?.contains { $0.id == id } == true
            }
        }

        var report = Report()
        var counts: [String: TrafficHistory.Count] = [:]
        var eligible = Set<String>()
        for day in history.series(from: start, through: today, calendar: calendar) {
            var scopedNodes: [String: TrafficHistory.Count] = [:]
            var total = TrafficHistory.Count()
            for (name, value) in day.nodes where matchesSource(name) {
                eligible.insert(name)
                if node == nil || node == name {
                    scopedNodes[name] = value
                    total.add(value)
                    counts[name, default: .init()].add(value)
                }
            }
            report.days.append(.init(date: day.date, nodes: scopedNodes, count: total))
            report.total.add(total)
        }
        report.eligibleNodes = eligible.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
        report.nodes = counts.map { name, count in
            let sources = providers[name] ?? []
            let provider = name == "DIRECT" ? L("直连") : sources.count > 1 ? L("多个订阅") : sources.first?.name ?? L("未归属")
            return Node(name: name, provider: provider, count: count)
        }.sorted { lhs, rhs in
            lhs.count.total == rhs.count.total ? lhs.name < rhs.name : lhs.count.total > rhs.count.total
        }
        return report
    }

    var body: some View {
        let _ = interfaceLocale
        let data = report
        VStack(alignment: .leading, spacing: 15) {
            HStack {
                Text(L("历史用量")).font(.headline)
                Spacer()
                Picker(L("统计范围"), selection: $period) {
                    ForEach(Period.allCases, id: \.self) { Text(L($0.rawValue)).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .id(interfaceLocale.identifier)
                .fixedSize()
            }
            HStack(alignment: .bottom, spacing: 12) {
                historyFilter(L("来源"), value: sourceLabel, selection: $source) {
                    Text(L("全部出站")).tag(Source.all)
                    Text(L("仅直连")).tag(Source.direct)
                    Text(L("仅代理节点")).tag(Source.proxy)
                    ForEach(subscriptions.filter { !($0.nodes ?? []).isEmpty }) { subscription in
                        Text(subscription.name).tag(Source.subscription(subscription.id))
                    }
                }
                historyFilter(L("节点"), value: node.map { $0 == "DIRECT" ? L("直连") : NodeLocation(name: $0).title } ?? L("全部节点"),
                              selection: $node) {
                    Text(L("全部节点")).tag(String?.none)
                    ForEach(data.eligibleNodes, id: \.self) { name in
                        Text(name == "DIRECT" ? L("直连") : NodeLocation(name: name).title)
                            .tag(Optional(name))
                    }
                }
                .disabled(data.eligibleNodes.isEmpty)
                if source != .all || node != nil {
                    Button(L("清除筛选")) {
                        source = .all
                        node = nil
                    }
                    .fixedSize()
                }
            }
            .font(.callout)
            Divider()
            HStack(spacing: 16) {
                metric(L("合计"), data.total.total)
                metric(L("下载"), data.total.download)
                metric(L("上传"), data.total.upload)
                metric(L("日均"), data.total.total / UInt64(max(data.days.count, 1)))
            }
            if data.total.total > 0 {
                TrafficTrendChart(days: data.days, height: 138)
                breakdown(data.nodes, total: data.total.total)
            } else {
                Label(
                    history == nil ? L("启动代理后开始记录本机流量。") : L("当前时间和筛选范围内暂无流量。"),
                    systemImage: "chart.bar"
                )
                .foregroundStyle(.secondary)
                .font(.callout)
                .padding(.vertical, 23)
            }
        }
        .onChange(of: source) { _, _ in node = nil }
        .onChange(of: data.eligibleNodes) { _, names in
            if let node, !names.contains(node) { self.node = nil }
        }
        .onChange(of: subscriptions.filter { !($0.nodes ?? []).isEmpty }.map(\.id)) { _, ids in
            if case .subscription(let id) = source, !ids.contains(id) { source = .all }
        }
    }

    private var sourceLabel: String {
        switch source {
        case .all: L("全部出站")
        case .direct: L("仅直连")
        case .proxy: L("仅代理节点")
        case .subscription(let id): subscriptions.first { $0.id == id }?.name ?? L("订阅")
        }
    }

    private func historyFilter<Value: Hashable, Options: View>(
        _ title: String, value: String, selection: Binding<Value>, @ViewBuilder options: () -> Options
    ) -> some View {
        HopLabeledControl(title: title) {
            HopSelectionMenu(title: title, value: value, labelWidth: nil, selection: selection, options: options)
        }
    }

    private func metric(_ title: String, _ count: UInt64) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(trafficBytes(count)).font(.system(.title2, design: .rounded).weight(.semibold).monospacedDigit())
                .lineLimit(1).minimumScaleFactor(0.85)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func breakdown(_ nodes: [Node], total: UInt64) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L("按节点")).font(.callout.weight(.semibold)).foregroundStyle(.secondary)
            ForEach(nodes.prefix(5)) { usageRow($0, total: total) }
            if nodes.count > 5 {
                HopDisclosure(L("还有 <1> 个节点", nodes.count - 5)) {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(nodes.dropFirst(5)) { usageRow($0, total: total) }
                    }
                }
                .font(.callout)
            }
        }
    }

    private func usageRow(_ node: Node, total: UInt64) -> some View {
        let ratio = Double(node.count.total) / Double(total)
        return HStack(spacing: 12) {
            Text(node.name == "DIRECT" ? L("直连") : NodeLocation(name: node.name).title)
                .lineLimit(1)
                .frame(maxWidth: .infinity, alignment: .leading)
                .help(node.name)
            Text(node.provider)
                .lineLimit(1)
                .foregroundStyle(.secondary)
                .frame(width: 98, alignment: .leading)
            ProgressView(value: ratio)
                .tint(node.name == "DIRECT" ? .gray : HopAppearance.accent)
                .frame(maxWidth: 135)
                .accessibilityHidden(true)
            Text(trafficBytes(node.count.total)).monospacedDigit().frame(width: 87, alignment: .trailing)
            Text(ratio.formatted(.percent.precision(.fractionLength(0))))
                .monospacedDigit().foregroundStyle(.secondary).frame(width: 42, alignment: .trailing)
        }
        .font(.callout)
    }
}

struct TrafficTrendChart: View {
    @Environment(\.locale) private var interfaceLocale
    let days: [TrafficHistory.Day]
    let height: CGFloat
    var barWidth: MarkDimension = .automatic
    var maxHeight: CGFloat? = nil
    var showsGrid = false

    var body: some View {
        let _ = interfaceLocale
        VStack(alignment: .leading, spacing: 8) {
            Chart(days) { day in
                BarMark(
                    x: .value(L("日期"), day.date, unit: .day),
                    y: .value(L("下载"), Double(day.count.download)),
                    width: barWidth
                )
                .foregroundStyle(by: .value(L("方向"), L("下载")))
                BarMark(
                    x: .value(L("日期"), day.date, unit: .day),
                    y: .value(L("上传"), Double(day.count.upload)),
                    width: barWidth
                )
                .foregroundStyle(by: .value(L("方向"), L("上传")))
            }
            .chartForegroundStyleScale([L("下载"): HopAppearance.accent, L("上传"): HopAppearance.chartUpload])
            .chartLegend(.hidden)
            .chartXAxis {
                AxisMarks(values: .stride(by: .day, count: showsGrid ? 1 : days.count > 15 ? 5 : days.count > 6 ? 3 : 1)) {
                    AxisValueLabel(format: .dateTime.month(.defaultDigits).day(.defaultDigits), centered: showsGrid ? true : nil)
                }
            }
            .chartYAxis {
                if showsGrid {
                    AxisMarks(values: .automatic(desiredCount: 4)) {
                        AxisGridLine().foregroundStyle(Color.primary.opacity(0.09))
                    }
                }
            }
            .chartYAxis(showsGrid ? .visible : .hidden)
            .frame(minHeight: height, idealHeight: height, maxHeight: maxHeight ?? height)
            HStack(spacing: 12) {
                legend(L("下载"), color: HopAppearance.accent)
                legend(L("上传"), color: HopAppearance.chartUpload)
            }
        }
    }

    private func legend(_ title: String, color: Color) -> some View {
        HStack(spacing: 5) {
            RoundedRectangle(cornerRadius: 2).fill(color).frame(width: 9, height: 9)
            Text(title)
        }
        .font(.caption)
        .foregroundStyle(.secondary)
    }
}

func trafficBytes(_ count: UInt64) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(clamping: count), countStyle: .binary)
}
