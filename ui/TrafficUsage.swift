import Charts
import Foundation
import SwiftUI

struct TrafficHistory: Decodable {
    struct Count: Decodable {
        var upload: UInt64 = 0
        var download: UInt64 = 0
        var total: UInt64 { upload + download }

        mutating func add(_ count: Count) {
            upload += count.upload
            download += count.download
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

    func series(from start: Date, through end: Date, calendar: Calendar) -> [Day] {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = calendar
        formatter.timeZone = calendar.timeZone
        formatter.dateFormat = "yyyy-MM-dd"
        guard let since = formatter.date(from: since) else { return [] }
        var date = max(since, start)
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
        trafficBytes(UInt64(min(bytesPerSecond.rounded(), Double(Int64.max)))) + "/s"
    }
}

struct TrafficDashboard: View {
    @ObservedObject var core: CoreModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HopPageHeading(title: "用量", detail: "监测本机经过 HopWay 的流量")
                liveMonitor.hopPanel()
                LocalTrafficView(history: core.trafficHistory, subscriptions: core.subscriptions)
                    .hopPanel()
            }
            .padding(.bottom, 12)
        }
    }

    private var liveMonitor: some View {
        let running = core.phase == .running
        let rate = running ? core.liveTraffic : nil
        return VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("实时流量", systemImage: "waveform.path").font(.headline)
                Spacer()
                Text(rate != nil ? "监测中" : running ? "等待采样" : core.phase.rawValue)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(rate != nil ? HopAppearance.accent : Color.secondary)
            }
            HStack(spacing: 28) {
                liveMetric("下载速率", rate?.download)
                liveMetric("上传速率", rate?.upload)
                Spacer()
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func liveMetric(_ title: String, _ rate: Double?) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(rate.map(TrafficRate.label) ?? "—")
                .font(.system(.title2, design: .rounded).weight(.semibold).monospacedDigit())
        }
        .frame(maxWidth: 148, alignment: .leading)
    }
}

struct LocalTrafficView: View {
    let history: TrafficHistory?
    let subscriptions: [SubscriptionSummary]
    @State private var period = Period.fortnight

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
        var total = TrafficHistory.Count()
    }

    private var report: Report {
        guard let history else { return Report() }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = .current
        let today = calendar.startOfDay(for: .now)
        let start = period.start(before: today, calendar: calendar)
        var report = Report(days: history.series(from: start, through: today, calendar: calendar))
        var counts: [String: TrafficHistory.Count] = [:]
        for day in report.days {
            for (name, value) in day.nodes { counts[name, default: .init()].add(value) }
            report.total.add(day.count)
        }

        var providers: [String: [String]] = [:]
        for subscription in subscriptions {
            for node in Set(subscription.nodes ?? []) {
                providers[node, default: []].append(subscription.name)
            }
        }
        report.nodes = counts.map { name, count in
            let sources = providers[name] ?? []
            let provider = name == "DIRECT" ? "直连" : sources.count > 1 ? "多个订阅" : sources.first ?? "未归属"
            return Node(name: name, provider: provider, count: count)
        }.sorted { lhs, rhs in
            lhs.count.total == rhs.count.total ? lhs.name < rhs.name : lhs.count.total > rhs.count.total
        }
        return report
    }

    var body: some View {
        let data = report
        VStack(alignment: .leading, spacing: 15) {
            HStack {
                Text("历史用量").font(.headline)
                Spacer()
                Picker("统计范围", selection: $period) {
                    ForEach(Period.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 205)
            }
            HStack(spacing: 28) {
                metric("下载", data.total.download)
                metric("上传", data.total.upload)
                metric("日均", data.total.total / UInt64(max(data.days.count, 1)))
                Spacer()
            }
            if data.total.total > 0 {
                TrafficTrendChart(days: data.days, height: 138)
                breakdown(data.nodes, total: data.total.total)
            } else {
                Label(
                    history == nil ? "启动代理后开始记录本机流量。" : "这段时间还没有经过 HopWay 的流量。",
                    systemImage: "chart.bar"
                )
                .foregroundStyle(.secondary)
                .font(.callout)
                .padding(.vertical, 23)
            }
        }
    }

    private func metric(_ title: String, _ count: UInt64) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(trafficBytes(count)).font(.system(.title2, design: .rounded).weight(.semibold).monospacedDigit())
        }
    }

    private func breakdown(_ nodes: [Node], total: UInt64) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("按节点").font(.callout.weight(.semibold)).foregroundStyle(.secondary)
            ForEach(nodes) { node in
                let ratio = Double(node.count.total) / Double(total)
                HStack(spacing: 12) {
                    Text(node.name == "DIRECT" ? "DIRECT" : NodeLocation(name: node.name).title)
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
    }
}

struct TrafficTrendChart: View {
    let days: [TrafficHistory.Day]
    let height: CGFloat

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Chart(days) { day in
                BarMark(
                    x: .value("日期", day.date, unit: .day),
                    y: .value("下载", Double(day.count.download))
                )
                .foregroundStyle(by: .value("方向", "下载"))
                BarMark(
                    x: .value("日期", day.date, unit: .day),
                    y: .value("上传", Double(day.count.upload))
                )
                .foregroundStyle(by: .value("方向", "上传"))
            }
            .chartForegroundStyleScale(["下载": HopAppearance.accent, "上传": HopAppearance.mint.opacity(0.76)])
            .chartLegend(.hidden)
            .chartXAxis {
                AxisMarks(values: .stride(by: .day, count: days.count > 15 ? 5 : days.count > 6 ? 3 : 1)) {
                    AxisValueLabel(format: .dateTime.month(.defaultDigits).day(.defaultDigits))
                }
            }
            .chartYAxis(.hidden)
            .frame(height: height)
            HStack(spacing: 12) {
                legend("下载", color: HopAppearance.accent)
                legend("上传", color: HopAppearance.mint.opacity(0.76))
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
