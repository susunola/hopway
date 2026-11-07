import Foundation
import SwiftUI

struct SubscriptionSummary: Decodable, Identifiable {
    struct Sample: Decodable {
        let time: Int64
        let used: UInt64
        let total: UInt64
    }

    struct Meter: Decodable, Equatable {
        let used: UInt64?
        let total: UInt64?
        let expiresAt: Int64?
        let expiryDate: String?
        let updatedAt: Int64

        var expiration: Date? {
            if let expiryDate {
                let formatter = DateFormatter()
                formatter.locale = Locale(identifier: "en_US_POSIX")
                formatter.timeZone = .current
                formatter.dateFormat = "yyyy-MM-dd"
                return formatter.date(from: expiryDate)
            }
            guard let expiresAt, expiresAt > 0 else { return nil }
            return Date(timeIntervalSince1970: Double(expiresAt))
        }
    }

    let id: String
    let originalName: String
    let alias: String?
    let paused: Bool?
    var isPaused: Bool { paused == true }
    var name: String { alias ?? originalName }
    let usage: Meter?
    let nodes: [String]?
    let usageSamples: [Sample]?

    enum CodingKeys: String, CodingKey {
        case id, alias, paused, usage, nodes, usageSamples
        case originalName = "name"
    }

    var projectedDays: Int? {
        guard let usage, let used = usage.used, let total = usage.total,
              used < total, let usageSamples else { return nil }
        let day: Int64 = 86_400
        var following = used
        for sample in usageSamples.reversed() {
            guard sample.total == total, sample.used <= following else { break }
            following = sample.used
            let elapsed = usage.updatedAt - sample.time
            if elapsed >= 6 * day && elapsed <= 8 * day && sample.used < used {
                let rate = Double(used - sample.used) / (Double(elapsed) / Double(day))
                let remaining = Double(total - used) / rate
                if remaining >= 1 && remaining <= 30 { return Int(ceil(remaining)) }
            }
        }
        return nil
    }
}

struct SubscriptionDashboard: View {
    @ObservedObject var core: CoreModel
    let importLink: () -> Void
    @State private var editing: SubscriptionSummary?
    @State private var newName = ""
    @State private var removing: SubscriptionSummary?

    var body: some View {
        let active = core.subscriptions.filter { !$0.isPaused }.count
        let paused = core.subscriptions.count - active
        ScrollView {
            VStack(alignment: .leading, spacing: HopAppearance.pageSpacing) {
                HStack {
                    HopPageHeading(
                        title: "订阅",
                        detail: core.subscriptions.isEmpty ? "管理服务商套餐、额度和到期时间" :
                            "\(core.subscriptions.count) 份订阅 · \(active) 份启用 · \(paused) 份暂停"
                    )
                    Spacer()
                    Button(action: core.refreshAllSubscriptions) {
                        Label("刷新全部", systemImage: "arrow.clockwise")
                    }
                    .disabled(core.saving || core.refreshing || !core.subscriptions.contains { !$0.isPaused })
                    Button("导入订阅…", action: importLink)
                        .buttonStyle(HopPrimaryButton())
                        .disabled(core.saving)
                }
                if core.subscriptions.isEmpty {
                    ContentUnavailableView("还没有订阅", systemImage: "tray.full",
                                           description: Text("导入后可以查看剩余流量和到期时间。"))
                        .frame(maxWidth: .infinity)
                } else {
                    ForEach(core.subscriptions) { subscription in
                        plan(subscription)
                            .hopPanel()
                    }
                }
            }
            .padding(.bottom, 12)
        }
        .alert("移除订阅", isPresented: Binding(
            get: { removing != nil },
            set: { if !$0 { removing = nil } }
        ), presenting: removing) { subscription in
            Button("移除", role: .destructive) { core.removeSubscription(subscription.id) }
            Button("取消", role: .cancel) {}
        } message: { subscription in
            Text("移除「\(subscription.name)」及仅属于它的节点。")
        }
        .sheet(item: $editing) { subscription in
            VStack(alignment: .leading, spacing: 13) {
                Text("编辑订阅名称").font(.headline)
                TextField("显示名称", text: $newName)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                Text("默认名称 · \(subscription.originalName)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack {
                    if subscription.alias != nil {
                        Button("恢复默认") { saveName(subscription, "") }
                    }
                    Spacer()
                    Button("取消") { editing = nil }.keyboardShortcut(.cancelAction)
                    Button("保存") { saveName(subscription, newName) }
                        .keyboardShortcut(.defaultAction)
                        .disabled(newName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || newName.count > 80)
                }
            }
            .padding(22)
            .frame(width: 365)
        }
    }

    private func saveName(_ subscription: SubscriptionSummary, _ name: String) {
        core.renameSubscription(subscription.id, to: name)
        editing = nil
    }

    private func plan(_ subscription: SubscriptionSummary) -> some View {
        let runtime = core.status?.subscriptions?.first { $0.id == subscription.id }
        let meter = runtime?.usage ?? subscription.usage
        let used = meter?.used
        let total = meter?.total.flatMap { $0 > 0 ? $0 : nil }
        let ratio = used.flatMap { used in total.map { Double(used) / Double($0) } }
        let warning = (ratio ?? 0) >= 0.8
        let nodeSync = max(runtime?.updated ?? 0, core.configuredProfile?.snapshotAt?[subscription.id] ?? 0)
        return VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 10) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(subscription.name).font(.headline).lineLimit(1).help(subscription.name)
                    if subscription.isPaused {
                        Text("已暂停").font(.caption).foregroundStyle(.secondary).fixedSize()
                    } else if let nodes = subscription.nodes {
                        Text("\(nodes.count) 个节点").foregroundStyle(.secondary).fixedSize()
                    }
                }
                Divider().frame(height: 24)
                syncSummary(nodeSync: nodeSync, quotaSync: meter?.updatedAt, checked: runtime?.checked)
                Spacer(minLength: 6)
                if let used {
                    Text(trafficBytes(used))
                        .font(.system(.title2, design: .rounded).weight(.semibold).monospacedDigit())
                        .foregroundStyle(warning ? HopAppearance.warning : Color.primary)
                }
                if let total {
                    Text("/ \(trafficBytes(total))").monospacedDigit().foregroundStyle(.secondary)
                }
                Menu {
                    Button("编辑名称…") {
                        newName = subscription.name
                        editing = subscription
                    }
                    Button("刷新订阅") { core.refreshSubscription(subscription.id) }
                        .disabled(core.refreshing || subscription.isPaused)
                    Button(subscription.isPaused ? "恢复订阅" : "暂停订阅") {
                        core.pauseSubscription(subscription.id, paused: !subscription.isPaused)
                    }
                    Button("移除订阅…", role: .destructive) { removing = subscription }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .disabled(core.saving)
                .accessibilityLabel("\(subscription.name) 的订阅操作")
            }
            if let ratio {
                ProgressView(value: min(1, ratio))
                    .tint(warning ? HopAppearance.warning : HopAppearance.accent)
                    .accessibilityLabel("已用流量占比")
            }
            HStack(spacing: 10) {
                if let used, let total, let ratio {
                    let remaining = "剩余 \(trafficBytes(total > used ? total - used : 0))"
                    let detail = subscription.projectedDays.map { "近 7 天用量推算约 \($0) 天用完" }
                        ?? "已用 \(ratio.formatted(.percent.precision(.fractionLength(0))))"
                    if warning {
                        Label("\(remaining) · \(detail)", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(HopAppearance.warning)
                    } else {
                        Text("\(remaining) · \(detail)")
                    }
                } else if meter == nil {
                    Text("服务商暂未提供用量。")
                } else {
                    Text("服务商未提供完整额度。")
                }
                Spacer(minLength: 8)
                if let expiration = meter?.expiration {
                    Text(expirationText(expiration))
                }
            }
            .font(.callout)
            .foregroundStyle(.secondary)
            if let error = runtime?.error {
                VStack(alignment: .leading, spacing: 3) {
                    Label(nodeSync > 0 ? "刷新失败 · 使用上次缓存" : "刷新失败", systemImage: "exclamationmark.circle")
                        .foregroundStyle(HopAppearance.warning)
                    Text(error)
                        .lineLimit(2)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .help(error)
                }
                .font(.caption)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func syncSummary(nodeSync: Double, quotaSync: Int64?, checked: Double?) -> some View {
        let nodes = nodeSync > 0 ? Date(timeIntervalSince1970: nodeSync / 1000) : nil
        let quota = quotaSync.flatMap { $0 > 0 ? Date(timeIntervalSince1970: Double($0)) : nil }
        let compact = Date.FormatStyle().month(.defaultDigits).day(.defaultDigits)
            .hour(.twoDigits(amPM: .omitted)).minute(.twoDigits)
        let nodeDetail = nodes.map { "节点同步 " + $0.formatted(date: .abbreviated, time: .shortened) } ?? "节点待同步"
        let quotaDetail = quota.map { "额度更新 " + $0.formatted(date: .abbreviated, time: .shortened) }
        let checkDetail = checked.flatMap { time in
            time > nodeSync ? "已检查 · 节点未变更 " + Date(timeIntervalSince1970: time / 1000).formatted(date: .abbreviated, time: .shortened) : nil
        }
        return VStack(alignment: .leading, spacing: 2) {
            Text(nodes.map { "节点同步 " + $0.formatted(compact) } ?? "节点待同步")
            if let quota { Text("额度更新 " + quota.formatted(compact)) }
        }
        .font(.caption.monospacedDigit())
        .foregroundStyle(.secondary)
        .fixedSize()
        .help([nodeDetail, quotaDetail, checkDetail].compactMap { $0 }.joined(separator: "\n"))
    }

    private func expirationText(_ date: Date) -> String {
        let calendar = Calendar.current
        let days = calendar.dateComponents(
            [.day], from: calendar.startOfDay(for: .now), to: calendar.startOfDay(for: date)
        ).day ?? 0
        let label = date.formatted(.dateTime.month().day())
        if days < 0 { return "\(label) 到期 · 已过期" }
        if days == 0 { return "\(label) 到期 · 今天" }
        return "\(label) 到期 · 还剩 \(days) 天"
    }
}
