import AppKit
import SwiftUI

struct OverviewDashboard: View {
    @ObservedObject var core: CoreModel
    let showNodes: () -> Void
    let showUsage: () -> Void
    let showSubscriptions: () -> Void
    let importLink: () -> Void
    @State private var showsAuto = false
    @State private var configuration: ConfigurationSummary?

    private struct ConfigurationSummary: Decodable {
        let socksPort: Int?
        let httpPort: Int?
    }

    private enum OutboundChoice: Hashable {
        case fastest, rule, direct, region, node(String)

        init(policy: Policy) {
            switch policy.mode {
            case "fastest": self = .fastest
            case "auto": self = .region
            case "direct": self = .direct
            case "global": self = policy.selected == "DIRECT" ? .direct : .node(policy.selected)
            default: self = .rule
            }
        }
    }

    private var running: Bool { core.phase == .running }
    private var busy: Bool { core.phase == .starting || core.phase == .stopping || core.saving }

    var body: some View {
        ViewThatFits(in: .vertical) {
            content(chartHeight: 120)
                .fixedSize(horizontal: false, vertical: true)
            content(chartHeight: 80)
                .fixedSize(horizontal: false, vertical: true)
            ScrollView { content(chartHeight: 80) }
        }
        .onChange(of: core.saved, initial: true) { _, text in
            configuration = try? JSONDecoder().decode(ConfigurationSummary.self, from: Data(text.utf8))
        }
        .sheet(isPresented: $showsAuto) { AutoRoutingSheet(core: core) }
    }

    private func content(chartHeight: CGFloat) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("概览")
                .font(.system(size: 27, weight: .semibold))
                .accessibilityAddTraits(.isHeader)
                .padding(.bottom, 2)
            proxyControl
            if core.statusReadFailed {
                Label(core.statusReadAt.map { "状态读取失败，显示 " + $0.formatted(date: .omitted, time: .standard) + " 的记录" }
                      ?? "暂时无法读取内核状态", systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            routing
            localAccess
            traffic(chartHeight: chartHeight)
            subscriptionsOverview
        }
        .padding(.bottom, 16)
    }

    private var proxyControl: some View {
        HStack(spacing: 14) {
            Image(systemName: "point.3.connected.trianglepath.dotted")
                .font(.system(size: 18, weight: .medium))
                .foregroundStyle(HopAppearance.mint)
                .frame(width: 38, height: 38)
                .background(.white.opacity(0.09), in: RoundedRectangle(cornerRadius: 9))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text("本机代理")
                    .font(.caption)
                    .foregroundStyle(.white.opacity(0.72))
                HStack(spacing: 7) {
                    Circle()
                        .fill(running ? HopAppearance.mint : Color.white.opacity(0.48))
                        .frame(width: 6, height: 6)
                        .accessibilityHidden(true)
                    Text(core.phase.rawValue)
                        .font(.system(size: 19, weight: .semibold))
                }
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 10)
            controlMetric("接入方式", value: core.status.map(accessMode) ?? (core.phase == .stopped ? "未接管" : "读取中"))
            controlMetric("活动连接", value: core.status.map { $0.active.formatted() } ?? (core.phase == .stopped ? "0" : "—"))
            Button(action: core.toggle) {
                Label(running || core.phase == .stopping ? "停止代理" : "启动代理", systemImage: "power")
            }
            .buttonStyle(HopPrimaryButton())
            .disabled(busy)
        }
        .foregroundStyle(.white)
        .padding(.horizontal, 16)
        .padding(.vertical, 20)
        .frame(maxWidth: .infinity)
        .background {
            RoundedRectangle(cornerRadius: 12)
                .fill(LinearGradient(
                    colors: [HopAppearance.navy, Color(red: 0.08, green: 0.20, blue: 0.25)],
                    startPoint: .leading, endPoint: .trailing
                ))
        }
    }

    private func controlMetric(_ title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption).foregroundStyle(.white.opacity(0.72))
            Text(value).font(.callout.weight(.semibold)).monospacedDigit()
        }
        .frame(minWidth: 66, alignment: .leading)
        .accessibilityElement(children: .combine)
    }

    private func accessMode(_ status: ProxyStatus) -> String {
        switch (status.tun?.enabled == true, status.systemProxy?.enabled == true) {
        case (true, true): "TUN + 系统代理"
        case (true, false): "TUN"
        case (false, true): "系统代理"
        case (false, false): "手动接入"
        }
    }

    private var routing: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 10) {
                Label("路由策略", systemImage: "arrow.triangle.branch").font(.headline)
                Spacer()
                if running {
                    Button("按地区选路…") { showsAuto = true }.disabled(core.updatingPolicy || core.statusReadFailed)
                }
                if core.configuredNodes.isEmpty {
                    Button("导入链接…", action: importLink).disabled(core.saving)
                }
                overviewLink("查看节点", action: showNodes)
            }

            if running, let status = core.status {
                policyControls(status)
            } else if !running, let mode = core.configuredProfile?.mode {
                HStack(spacing: 18) {
                    LabeledContent("启动出站", value: Policy.label(mode))
                        .fixedSize()
                    if mode == "global", let selected = core.configuredProfile?.selected {
                        Text(selected).lineLimit(1).help(selected)
                    }
                }
                .font(.callout)
            } else {
                Text(running ? "正在读取当前出站…" : "正在读取启动出站…")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .hopPanel(verticalPadding: 12)
    }

    private func policyControls(_ status: ProxyStatus) -> some View {
        HStack(alignment: .center, spacing: 14) {
            Picker("出站", selection: Binding(
                get: { OutboundChoice(policy: status.policy) },
                set: { selectOutbound($0, status: status) }
            )) {
                Text("自动最快").tag(OutboundChoice.fastest)
                Text("按规则").tag(OutboundChoice.rule)
                Text("直连").tag(OutboundChoice.direct)
                if status.policy.mode == "auto" { Text("按地区自动").tag(OutboundChoice.region) }
                if status.policy.mode == "global", status.policy.selected == "REJECT" {
                    Text("阻断连接").tag(OutboundChoice.node("REJECT"))
                }
                Section("手动节点") {
                    ForEach(status.nodes.filter { $0.name != "DIRECT" && $0.name != "REJECT" && $0.type != "group" }) { node in
                        Text(node.name).tag(OutboundChoice.node(node.name))
                    }
                }
                let groups = status.nodes.filter { $0.type == "group" }
                if !groups.isEmpty {
                    Section("策略组") {
                        ForEach(groups) { group in Text(group.name).tag(OutboundChoice.node(group.name)) }
                    }
                }
            }
            .pickerStyle(.menu)
            .frame(maxWidth: 320)
            .disabled(core.updatingPolicy || core.statusReadFailed)
            if let auto = status.auto {
                if let node = auto.node {
                    let latency = status.nodes.first { $0.name == node }?.latencyMs.map { "\($0) ms" }
                    let detail = [auto.provider, node, latency].compactMap { $0 }.joined(separator: " · ")
                    Label(detail, systemImage: "point.3.connected.trianglepath.dotted")
                        .font(.callout)
                        .lineLimit(1)
                        .help(detail)
                } else {
                    let detail = if auto.probing {
                        "正在测速，等待可用节点…"
                    } else if status.policy.mode == "fastest", auto.candidates == nil {
                        "没有可测速的代理节点"
                    } else {
                        "暂未找到可用节点"
                    }
                    Text(detail).font(.callout).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
        }
    }

    private func selectOutbound(_ option: OutboundChoice, status: ProxyStatus) {
        switch option {
        case .fastest: core.updatePolicy(Policy(mode: "fastest", selected: status.policy.selected))
        case .rule: core.updatePolicy(Policy(mode: "rule", selected: status.policy.selected))
        case .direct: core.updatePolicy(Policy(mode: "direct", selected: "DIRECT"))
        case .region: break
        case .node(let name):
            if let node = status.nodes.first(where: { $0.name == name }) {
                core.selectNode(node, mode: "global")
            }
        }
    }

    private var localAccess: some View {
        let socks = configuredAddress(configuration.map { $0.socksPort ?? 1080 })
        let http = configuredAddress(configuration.map { $0.httpPort ?? 8080 })
        return VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                Label("本机入口", systemImage: "network").font(.headline)
                if !running {
                    Text(core.phase == .stopped ? "未监听" : core.phase.rawValue)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Text(verificationLabel)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .help(verificationLabel)
                    .accessibilityAddTraits(.updatesFrequently)
                Button("验证联网", action: core.verifyConnection)
                    .disabled(!running || core.verifying)
                    .fixedSize()
            }
            Divider()
            HStack(spacing: 16) {
                address("SOCKS5", value: core.endpoint?.socks ?? socks)
                Divider().frame(height: 25)
                address("HTTP / CONNECT", value: core.endpoint?.http ?? http)
            }
        }
        .hopPanel(verticalPadding: 12)
    }

    private var verificationLabel: String {
        if !running { return "启动后可验证" }
        if core.verifying { return "正在验证当前路由…" }
        return core.verification ?? "当前路由待验证"
    }

    private func configuredAddress(_ port: Int?) -> String? {
        guard let port, (1...65535).contains(port) else { return nil }
        return "127.0.0.1:\(port)"
    }

    private func address(_ title: String, value: String?) -> some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.caption).foregroundStyle(.secondary)
                if let value {
                    Text(value)
                        .font(.system(.callout, design: .monospaced).weight(.medium))
                        .lineLimit(1)
                        .help(value)
                } else {
                    Text("启动后显示地址")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
            if let value {
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(value, forType: .string)
                } label: {
                    Image(systemName: "document.on.document")
                }
                .buttonStyle(.borderless)
                .help(running ? "复制代理地址" : "复制配置地址")
                .accessibilityLabel("复制\(title)地址")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func traffic(chartHeight: CGFloat) -> some View {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = .current
        let today = calendar.startOfDay(for: .now)
        let start = calendar.date(byAdding: .day, value: -6, to: today) ?? today
        let days = core.trafficHistory?.series(from: start, through: today, calendar: calendar) ?? []
        let todayCount = days.last?.count
        let rates = running ? core.liveTraffic : nil
        let ratePlaceholder = running ? "等待采样" : core.phase.rawValue

        return VStack(alignment: .leading, spacing: 11) {
            HStack(spacing: 8) {
                Label("流量概况", systemImage: "chart.bar.xaxis").font(.headline)
                Text("经过 HopWay").font(.caption).foregroundStyle(.secondary)
                Spacer()
                overviewLink("查看用量", action: showUsage)
            }
            Divider()
            HStack(alignment: .top, spacing: 18) {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 11) {
                    GridRow {
                        trafficMetric("今日下载", value: todayCount.map { trafficBytes($0.download) } ?? "无记录")
                        trafficMetric("今日上传", value: todayCount.map { trafficBytes($0.upload) } ?? "无记录")
                    }
                    GridRow {
                        trafficMetric("实时下载", value: rates.map { TrafficRate.label($0.download) } ?? ratePlaceholder)
                        trafficMetric("实时上传", value: rates.map { TrafficRate.label($0.upload) } ?? ratePlaceholder)
                    }
                }
                .frame(width: 244, alignment: .leading)
                Divider().frame(height: chartHeight + 39)
                VStack(alignment: .leading, spacing: 5) {
                    Text("近 7 天")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                    if days.contains(where: { $0.count.total > 0 }) {
                        TrafficTrendChart(days: days, height: chartHeight)
                    } else {
                        Text("近 7 天暂无流量记录")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .frame(height: chartHeight, alignment: .center)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .hopPanel(verticalPadding: 14)
    }

    private func trafficMetric(_ title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value)
                .font(.system(.title3, design: .rounded).weight(.semibold))
                .monospacedDigit()
                .lineLimit(1)
                .minimumScaleFactor(0.85)
        }
        .frame(width: 116, alignment: .leading)
        .accessibilityElement(children: .combine)
    }

    private var subscriptionsOverview: some View {
        let subscriptions = core.subscriptions
        let active = subscriptions.filter { !$0.isPaused }
        let visible = (active + subscriptions.filter(\.isPaused)).prefix(3)

        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Label("订阅速览", systemImage: "tray.full").font(.headline)
                if !subscriptions.isEmpty {
                    Text("\(subscriptions.count) 份 · \(active.count) 份启用")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
                Spacer()
                overviewLink("管理订阅", action: showSubscriptions)
            }
            if visible.isEmpty {
                Text(core.profileReadFailed ? "暂时无法读取订阅" :
                        core.configuredProfile == nil ? "正在读取订阅…" : "暂无订阅")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                HStack(spacing: 14) {
                    ForEach(visible) { subscription in
                        if subscription.id != visible.first?.id { Divider().frame(height: 30) }
                        subscriptionSummary(subscription)
                    }
                }
            }
        }
        .hopPanel(verticalPadding: 12)
    }

    private func subscriptionSummary(_ subscription: SubscriptionSummary) -> some View {
        let meter = subscription.usage
        let remaining: String
        if let used = meter?.used, let total = meter?.total, total > 0 {
            remaining = "剩余 " + trafficBytes(total > used ? total - used : 0)
        } else {
            remaining = "额度未提供"
        }
        let expiration = meter?.expiration
        let expired = expiration.map { $0 < Calendar.current.startOfDay(for: .now) } ?? false
        let expiry = expiration.map { $0.formatted(.dateTime.month(.defaultDigits).day(.defaultDigits)) + " 到期" }
            ?? "到期日未知"
        let detail = remaining + " · " + (expired ? "已到期" : expiry)

        return VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(subscription.name).font(.callout.weight(.semibold)).lineLimit(1)
                if subscription.isPaused {
                    Text("已暂停").font(.caption).foregroundStyle(.secondary)
                }
            }
            Text(detail)
                .font(.caption.monospacedDigit())
                .foregroundStyle(expired ? Color.orange : .secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.82)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
        .help(subscription.name + " · " + remaining + " · " + expiry)
    }

    private func overviewLink(_ title: String, action: @escaping () -> Void) -> some View {
        Button(title, action: action)
            .buttonStyle(.plain)
            .font(.callout.weight(.medium))
            .foregroundStyle(HopAppearance.accent)
    }
}
