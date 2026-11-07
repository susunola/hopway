import SwiftUI

struct OverviewDashboard: View {
    @ObservedObject var core: CoreModel
    let showNodes: () -> Void
    let showPolicies: () -> Void
    let showUsage: () -> Void
    let showSubscriptions: () -> Void
    let importLink: () -> Void

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
    }

    private func content(chartHeight: CGFloat) -> some View {
        VStack(alignment: .leading, spacing: HopAppearance.pageSpacing) {
            HopPageHeading(title: "概览").padding(.bottom, 2)
            proxyControl
            accessIssues
            if core.statusReadFailed {
                Label(core.statusReadAt.map { "状态读取失败，显示 " + $0.formatted(date: .omitted, time: .standard) + " 的记录" }
                      ?? "暂时无法读取内核状态", systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(HopAppearance.warning)
            }
            routing
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
            proxyAccessControls
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

    private var proxyAccessControls: some View {
        let status = core.status
        let ready = running && !core.statusReadFailed
        return VStack(alignment: .leading, spacing: 5) {
            Text("macOS 接入 · " + (core.phase == .stopped ? "启动后可切换" : core.accessLabel))
                .font(.caption)
                .foregroundStyle(.white.opacity(0.72))
                .lineLimit(1)
            HStack(spacing: 12) {
                Toggle("系统代理", isOn: Binding(
                    get: { status?.systemProxy?.enabled == true }, set: core.setSystemProxy))
                    .disabled(!ready || status?.systemProxy?.supported != true)
                Toggle("TUN 增强模式", isOn: Binding(
                    get: { status?.tun?.enabled == true }, set: core.setTUN))
                    .disabled(!ready || status?.tun?.supported != true || core.changingTUN)
            }
            .font(.callout)
            .toggleStyle(.checkbox)
            .tint(HopAppearance.mint)
        }
        .fixedSize(horizontal: true, vertical: false)
    }

    @ViewBuilder
    private var accessIssues: some View {
        if running, let status = core.status {
            if let error = status.systemProxy?.error {
                accessIssue("系统代理 · " + error)
            }
            if let error = status.tun?.error {
                accessIssue("TUN · " + error)
            }
        }
    }

    private func accessIssue(_ text: String) -> some View {
        Label(text, systemImage: "exclamationmark.circle")
            .font(.callout)
            .foregroundStyle(HopAppearance.warning)
    }

    private func controlMetric(_ title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption).foregroundStyle(.white.opacity(0.72))
            Text(value).font(.callout.weight(.semibold)).monospacedDigit()
        }
        .frame(minWidth: 66, alignment: .leading)
        .accessibilityElement(children: .combine)
    }

    private var routing: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 10) {
                Label("出站与联网", systemImage: "arrow.triangle.branch").font(.headline)
                Spacer()
                if core.configuredNodes.isEmpty {
                    Button("导入链接…", action: importLink).disabled(core.saving)
                }
                overviewLink("策略模板", action: showPolicies)
                overviewLink("查看节点", action: showNodes)
            }

            if running, let status = core.status {
                policyControls(status)
            } else if !running, let mode = core.configuredProfile?.mode {
                HStack(spacing: 18) {
                    Text("启动出站").foregroundStyle(.secondary).fixedSize()
                    if mode == "global", let selected = core.configuredProfile?.selected {
                        Text(selected).fontWeight(.medium).lineLimit(1).help(selected)
                    }
                    routingContext(mode: mode, status: nil)
                }
                .font(.callout)
            } else {
                Text(running ? "正在读取当前出站…" : "正在读取启动出站…")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Divider()
            outletStatus
        }
        .hopPanel(verticalPadding: 12)
    }

    private func policyControls(_ status: ProxyStatus) -> some View {
        let choice = OutboundChoice(policy: status.policy)
        let value: String = switch choice {
        case .fastest: "自动最快"
        case .rule: "按规则"
        case .direct: "直连"
        case .region: "按地区自动"
        case .node(let name): name == "REJECT" ? "阻断连接" : name
        }
        return HStack(alignment: .center, spacing: 14) {
            Text("出站").font(.callout).foregroundStyle(.secondary)
                .accessibilityHidden(true)
            HopSelectionMenu(title: "出站", value: value, labelWidth: 144, selection: Binding(
                get: { choice },
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
            .disabled(core.updatingPolicy || core.statusReadFailed)
            routingContext(mode: status.policy.mode, status: status)
            Spacer(minLength: 0)
        }
    }

    private func routingContext(mode: String, status: ProxyStatus?) -> some View {
        let detail: String = switch mode {
        case "fastest":
            status?.auto?.candidates.map { "\($0) 个候选节点" } ?? "按延迟选可用节点"
        case "rule":
            "\(core.configuredProfile?.ruleCount ?? 0) 条配置规则"
        case "auto":
            status?.policy.auto?.region ?? "同地区自动切换"
        case "direct":
            "新连接直达目标"
        default:
            status?.policy.selected == "REJECT" ? "阻断新连接" : "新连接走所选出站"
        }
        return HStack(spacing: 9) {
            Divider().frame(height: 16)
            if status == nil || mode == "global" {
                Text(Policy.label(mode)).fontWeight(.medium).fixedSize()
            }
            Text(detail).foregroundStyle(.secondary).lineLimit(1).help(detail)
        }
        .font(.callout)
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

    private var outletStatus: some View {
        let status = core.status
        let outbound = status?.currentOutbound
        let node = status?.nodes.first { $0.name == outbound && $0.name != "DIRECT" && $0.name != "REJECT" }
        let health = outletHealth(node)
        return HStack(spacing: 12) {
            if running, let status {
                if let node {
                    let location = NodeLocation(name: node.name)
                    let name = if let flag = location.flag, !location.title.contains(flag) {
                        flag + " " + location.title
                    } else {
                        location.title
                    }
                    let source = subscription(for: node.name)?.name ?? status.auto?.provider
                    HStack(spacing: 14) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(name).font(.callout.weight(.semibold)).lineLimit(1).help(node.name)
                            Text(source.map { "订阅 · " + $0 } ?? "本地节点")
                                .font(.caption).foregroundStyle(.secondary).lineLimit(1).help(source ?? "本地节点")
                        }
                        if let latency = node.latencyMs {
                            Text("\(latency) ms").font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                                .fixedSize()
                        }
                    }
                    .accessibilityElement(children: .combine)
                } else {
                    Text(outletDescription(status))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            } else {
                Label("联网验证", systemImage: "network")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 4)
            Text(health.label)
                .font(.caption)
                .foregroundStyle(health.color)
                .fixedSize()
                .help(core.verification?.detail ?? health.label)
                .accessibilityAddTraits(.updatesFrequently)
            Button("验证联网", action: core.verifyConnection)
                .disabled(!running || core.verifying || core.statusReadFailed || core.status == nil)
                .fixedSize()
        }
    }

    private func outletHealth(_ node: ProxyStatus.Node?) -> (label: String, color: Color) {
        if !running || core.statusReadFailed || core.verifying { return (core.reachabilityLabel, .secondary) }
        if let check = core.verification {
            return (check.title, check.failed ? HopAppearance.warning : HopAppearance.accent)
        }
        if let healthAt = node?.healthAt, Date.now.timeIntervalSince1970 - healthAt / 1000 > 15 * 60 {
            return ("等待复测", .secondary)
        }
        if node?.alive == true { return ("节点可用", HopAppearance.accent) }
        if node?.alive == false { return ("节点不可用", HopAppearance.warning) }
        return (core.reachabilityLabel, .secondary)
    }

    private func outletDescription(_ status: ProxyStatus) -> String {
        switch status.currentOutbound {
        case "DIRECT": return "当前出口 · 直连"
        case "REJECT": return "当前出口 · 阻断连接"
        default:
            if status.policy.mode == "rule" { return "按规则分流，出口随目标而变" }
            if status.auto?.probing == true { return "正在测速，等待可用节点" }
            return "暂无可用节点"
        }
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
        let enabled = subscriptions.filter { !$0.isPaused }
        let selected = running && !core.statusReadFailed ? core.status?.currentOutbound.flatMap(subscription(for:)) : nil
        let visible = ([selected].compactMap { $0 }
                       + enabled.filter { $0.id != selected?.id }
                       + subscriptions.filter(\.isPaused)).prefix(3)

        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Label("订阅速览", systemImage: "tray.full").font(.headline)
                if !subscriptions.isEmpty {
                    Text("\(subscriptions.count) 份 · \(enabled.count) 份启用")
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
                        subscriptionSummary(subscription, inUse: subscription.id == selected?.id)
                    }
                }
            }
        }
        .hopPanel(verticalPadding: 12)
    }

    private func subscription(for node: String) -> SubscriptionSummary? {
        let matches = core.subscriptions.filter { !$0.isPaused && $0.nodes?.contains(node) == true }
        return matches.count == 1 ? matches.first : nil
    }

    private func subscriptionSummary(_ subscription: SubscriptionSummary, inUse: Bool) -> some View {
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
                if inUse {
                    HStack(spacing: 4) {
                        Circle().fill(HopAppearance.accent).frame(width: 6, height: 6)
                            .accessibilityHidden(true)
                        Text("使用中").font(.caption.weight(.medium))
                    }
                    .foregroundStyle(HopAppearance.accent)
                    .fixedSize()
                } else if subscription.isPaused {
                    Text("已暂停").font(.caption).foregroundStyle(.secondary)
                        .fixedSize()
                }
            }
            Text(detail)
                .font(.caption.monospacedDigit())
                .foregroundStyle(expired ? HopAppearance.warning : .secondary)
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
