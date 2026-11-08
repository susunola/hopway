import SwiftUI

struct OverviewDashboard: View {
    @Environment(\.locale) private var interfaceLocale
    @ObservedObject var core: CoreModel
    let hasAdvancedEdits: Bool
    @State private var showsStartupSettings = false
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
        let _ = interfaceLocale
        ViewThatFits(in: .vertical) {
            content(compact: false)
            content(compact: true).fixedSize(horizontal: false, vertical: true)
            ScrollView { content(compact: true) }
        }
        .sheet(isPresented: $showsStartupSettings) {
            StartupAccessSettings(core: core, hasAdvancedEdits: hasAdvancedEdits)
        }
    }

    private func content(compact: Bool) -> some View {
        VStack(alignment: .leading, spacing: compact ? 8 : HopAppearance.pageSpacing) {
            HopPageHeading(title: L("概览")).padding(.bottom, compact ? 0 : 2)
            VStack(spacing: 0) {
                proxyControl(compact: compact)
                proxyAccessControls(compact: compact)
            }
            .background(HopAppearance.panelSurface)
            .clipShape(RoundedRectangle(cornerRadius: HopAppearance.panelRadius))
            .overlay(RoundedRectangle(cornerRadius: HopAppearance.panelRadius).strokeBorder(HopAppearance.panelBorder))
            .fixedSize(horizontal: false, vertical: true)
            accessIssues
            if core.statusReadFailed {
                Label(core.statusReadAt.map { L("状态读取失败，显示 <1> 的记录", $0.formatted(date: .omitted, time: .standard)) }
                      ?? L("暂时无法读取内核状态"), systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(HopAppearance.warning)
            }
            routing(compact: compact).fixedSize(horizontal: false, vertical: true)
            traffic(compact: compact)
            subscriptionsOverview(compact: compact).fixedSize(horizontal: false, vertical: true)
        }
        .padding(.bottom, compact ? 12 : 20)
    }

    private func proxyControl(compact: Bool) -> some View {
        HStack(spacing: 14) {
            Image(systemName: "point.3.connected.trianglepath.dotted")
                .font(.system(size: 18, weight: .medium))
                .foregroundStyle(HopAppearance.mint)
                .frame(width: 38, height: 38)
                .background(.white.opacity(0.10), in: RoundedRectangle(cornerRadius: 9))
                .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(.white.opacity(0.13)))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(L("本机代理"))
                    .font(.caption)
                    .foregroundStyle(.white.opacity(0.72))
                HStack(spacing: 7) {
                    Circle()
                        .fill(running ? HopAppearance.mint : Color.white.opacity(0.48))
                        .frame(width: 6, height: 6)
                        .accessibilityHidden(true)
                    Text(L(core.phase.rawValue))
                        .font(.system(size: 19, weight: .semibold))
                }
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 10)
            controlMetric(L("活动连接"), value: core.status.map { $0.active.formatted() } ?? (core.phase == .stopped ? "0" : "—"))
                .padding(.horizontal, 11)
                .padding(.vertical, 5)
                .background(.white.opacity(0.09), in: RoundedRectangle(cornerRadius: 8))
            Button(action: core.toggle) {
                Label(running || core.phase == .stopping ? L("停止代理") : L("启动代理"), systemImage: "power")
            }
            .buttonStyle(HopPrimaryButton(onDarkSurface: true))
            .disabled(busy)
        }
        .foregroundStyle(.white)
        .padding(.horizontal, 16)
        .padding(.vertical, compact ? 10 : 14)
        .frame(maxWidth: .infinity)
        .background {
            LinearGradient(colors: [HopAppearance.navy, Color(red: 0.07, green: 0.23, blue: 0.27)],
                           startPoint: .leading, endPoint: .trailing)
                .overlay { signalTrace }
        }
    }

    private var signalTrace: some View {
        Canvas { context, size in
            let start = size.width * 0.37
            let step = size.width * 0.067
            let bottom = size.height * 0.72
            let middle = size.height * 0.49
            let top = size.height * 0.25
            var line = Path()
            line.move(to: CGPoint(x: start, y: bottom))
            line.addLine(to: CGPoint(x: start + step, y: bottom))
            line.addQuadCurve(to: CGPoint(x: start + step * 1.45, y: middle),
                              control: CGPoint(x: start + step * 1.22, y: bottom))
            line.addLine(to: CGPoint(x: start + step * 2.35, y: middle))
            line.addQuadCurve(to: CGPoint(x: start + step * 2.8, y: top),
                              control: CGPoint(x: start + step * 2.58, y: middle))
            line.addLine(to: CGPoint(x: start + step * 3.45, y: top))
            context.stroke(line, with: .color(HopAppearance.mint.opacity(0.22)),
                           style: StrokeStyle(lineWidth: 1.2, lineCap: .round, lineJoin: .round))
            for point in [CGPoint(x: start, y: bottom), CGPoint(x: start + step * 3.45, y: top)] {
                context.fill(Path(ellipseIn: CGRect(x: point.x - 2.5, y: point.y - 2.5, width: 5, height: 5)),
                             with: .color(HopAppearance.mint.opacity(0.34)))
            }
        }
        .accessibilityHidden(true)
        .allowsHitTesting(false)
    }

    private func proxyAccessControls(compact: Bool) -> some View {
        let status = core.status
        return HStack(spacing: 12) {
            Text(L("macOS 接入")).fontWeight(.medium).fixedSize()
            if running {
                Text(core.accessLabel).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                Divider().frame(height: 16)
                Toggle(L("系统代理"), isOn: Binding(
                    get: { status?.systemProxy?.enabled == true }, set: core.setSystemProxy))
                    .disabled(core.statusReadFailed || status?.systemProxy?.supported != true)
                    .fixedSize()
                Toggle("TUN", isOn: Binding(
                    get: { status?.tun?.enabled == true }, set: core.setTUN))
                    .accessibilityLabel(L("TUN 增强模式"))
                    .disabled(core.statusReadFailed || status?.tun?.supported != true || core.changingTUN)
                    .fixedSize()
            } else {
                Text(L("启动后可切换系统代理与 TUN"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 6)
            Button(L("启动与 TUN…")) { showsStartupSettings = true }
                .fixedSize()
        }
        .font(.callout)
        .controlSize(.small)
        .padding(.horizontal, 16)
        .padding(.vertical, compact ? 6 : 8)
    }

    @ViewBuilder
    private var accessIssues: some View {
        if running, let status = core.status {
            if let error = status.systemProxy?.error {
                accessIssue(L("系统代理 · ") + error)
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

    private func routing(compact: Bool) -> some View {
        VStack(alignment: .leading, spacing: compact ? 6 : 9) {
            HStack(spacing: 10) {
                Label(L("出站与联网"), systemImage: "arrow.triangle.branch").labelStyle(HopSectionLabelStyle())
                Spacer()
                if core.configuredNodes.isEmpty {
                    Button(L("导入链接…"), action: importLink).disabled(core.saving)
                }
                overviewLink(L("策略模板"), action: showPolicies)
                overviewLink(L("查看节点"), action: showNodes)
            }

            if running, let status = core.status {
                policyControls(status)
            } else if !running, let mode = core.configuredProfile?.mode {
                HStack(spacing: 18) {
                    Text(L("启动出站")).foregroundStyle(.secondary).fixedSize()
                    if mode == "global", let selected = core.configuredProfile?.selected {
                        Text(core.groupLabel(selected)).fontWeight(.medium).lineLimit(1).help(selected)
                    }
                    routingContext(mode: mode, status: nil)
                    Spacer(minLength: 6)
                    Text(L("启动后自动验证")).font(.caption).foregroundStyle(.secondary).fixedSize()
                }
                .font(.callout)
            } else {
                Text(running ? L("正在读取当前出站…") : L("正在读取启动出站…"))
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            if running {
                outletStatus
                    .padding(.horizontal, 9)
                    .padding(.vertical, compact ? 3 : 6)
                    .background(HopAppearance.insetSurface, in: RoundedRectangle(cornerRadius: 8))
            }
        }
        .hopPanel(verticalPadding: compact ? 8 : 12)
    }

    private func policyControls(_ status: ProxyStatus) -> some View {
        let choice = OutboundChoice(policy: status.policy)
        let value: String = switch choice {
        case .fastest: L("自动最快")
        case .rule: L("按规则")
        case .direct: L("直连")
        case .region: L("按地区自动")
        case .node(let name): name == "REJECT" ? L("阻断连接") : core.groupLabel(name)
        }
        return HStack(alignment: .center, spacing: 14) {
            Text(L("出站")).font(.callout).foregroundStyle(.secondary)
                .accessibilityHidden(true)
            HopSelectionMenu(title: L("出站"), value: value, labelWidth: 144, selection: Binding(
                get: { choice },
                set: { selectOutbound($0, status: status) }
            )) {
                Text(L("自动最快")).tag(OutboundChoice.fastest)
                Text(L("按规则")).tag(OutboundChoice.rule)
                Text(L("直连")).tag(OutboundChoice.direct)
                if status.policy.mode == "auto" { Text(L("按地区自动")).tag(OutboundChoice.region) }
                if status.policy.mode == "global", status.policy.selected == "REJECT" {
                    Text(L("阻断连接")).tag(OutboundChoice.node("REJECT"))
                }
                Section(L("手动节点")) {
                    ForEach(status.nodes.filter { $0.name != "DIRECT" && $0.name != "REJECT" && $0.type != "group" }) { node in
                        Text(node.name).tag(OutboundChoice.node(node.name))
                    }
                }
                let groups = status.nodes.filter { $0.type == "group" }
                if !groups.isEmpty {
                    Section(L("策略组")) {
                        ForEach(groups) { group in Text(core.groupLabel(group.name)).tag(OutboundChoice.node(group.name)) }
                    }
                }
            }
            .disabled(core.updatingPolicy || core.statusReadFailed)
            routingContext(mode: status.policy.mode, status: status)
            Spacer(minLength: 0)
        }
    }

    private func routingContext(mode: String, status: ProxyStatus?) -> some View {
        let lastSwitch = status?.auto?.lastSwitch
        let switchNote = lastSwitch.map { " · " + $0.label } ?? ""
        let detail: String = switch mode {
        case "fastest":
            (status?.auto?.candidates.map { L("<1> 个候选节点", $0) } ?? L("按延迟选可用节点")) + switchNote
        case "rule":
            L("<1> 条配置规则", core.configuredProfile?.ruleCount ?? 0)
        case "auto":
            (status?.policy.auto?.region ?? L("同地区自动切换")) + switchNote
        case "direct":
            L("新连接直达目标")
        default:
            status?.policy.selected == "REJECT" ? L("阻断新连接") : L("新连接走所选出站")
        }
        return HStack(spacing: 9) {
            Divider().frame(height: 16)
            if status == nil || mode == "global" {
                Text(Policy.label(mode)).fontWeight(.medium).fixedSize()
            }
            Text(detail).foregroundStyle(.secondary).lineLimit(1)
                .help(lastSwitch.map { $0.label + " " + $0.detail } ?? detail)
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
                            Text(source.map { L("订阅 · ") + $0 } ?? L("本地节点"))
                                .font(.caption).foregroundStyle(.secondary).lineLimit(1).help(source ?? L("本地节点"))
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
                Label(L("联网验证"), systemImage: "network")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 4)
            Label(health.label, systemImage: core.verifying ? "arrow.clockwise" : "circle.fill")
                .font(.caption.weight(.medium))
                .foregroundStyle(health.color)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(health.color.opacity(0.10), in: Capsule())
                .fixedSize()
                .help(core.verification?.detail ?? health.label)
                .accessibilityAddTraits(.updatesFrequently)
        }
    }

    private func outletHealth(_ node: ProxyStatus.Node?) -> (label: String, color: Color) {
        if !running || core.statusReadFailed || core.verifying { return (core.reachabilityLabel, .secondary) }
        if let check = core.verification {
            return (check.title, check.failed ? HopAppearance.warning : HopAppearance.accent)
        }
        if let healthAt = node?.healthAt, Date.now.timeIntervalSince1970 - healthAt / 1000 > 15 * 60 {
            return (L("等待复测"), .secondary)
        }
        if node?.alive == true { return (L("节点可用"), HopAppearance.accent) }
        if node?.alive == false { return (L("节点不可用"), HopAppearance.warning) }
        return (core.reachabilityLabel, .secondary)
    }

    private func outletDescription(_ status: ProxyStatus) -> String {
        switch status.currentOutbound {
        case "DIRECT": return L("当前出口 · 直连")
        case "REJECT": return L("当前出口 · 阻断连接")
        default:
            if status.policy.mode == "rule" { return L("按规则分流，出口随目标而变") }
            if status.auto?.probing == true { return L("正在测速，等待可用节点") }
            return L("暂无可用节点")
        }
    }

    private func traffic(compact: Bool) -> some View {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = .current
        let today = calendar.startOfDay(for: .now)
        let start = calendar.date(byAdding: .day, value: -6, to: today) ?? today
        let days = core.trafficHistory?.series(from: start, through: today, calendar: calendar, includeLeadingDays: true) ?? []
        let todayCount = days.last?.count
        let weekCount = days.reduce(into: TrafficHistory.Count()) { $0.add($1.count) }
        let hasTraffic = weekCount.total > 0
        let rates = running ? core.liveTraffic : nil
        let chartHeight: CGFloat = compact ? 42 : 54
        let ratePlaceholder = L("等待采样")

        return VStack(alignment: .leading, spacing: compact ? 7 : 11) {
            HStack(spacing: 8) {
                Label(L("流量概况"), systemImage: "chart.bar.xaxis").labelStyle(HopSectionLabelStyle())
                Spacer()
                overviewLink(L("查看用量"), action: showUsage)
            }
            Divider()
            HStack(alignment: .top, spacing: 18) {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: compact ? 6 : 11) {
                    GridRow {
                        trafficMetric(L("今日下载"), value: todayCount.map { trafficBytes($0.download) } ?? L("无记录"))
                        trafficMetric(L("今日上传"), value: todayCount.map { trafficBytes($0.upload) } ?? L("无记录"))
                    }
                    if running {
                        GridRow {
                            trafficMetric(L("实时下载"), value: rates.map { TrafficRate.label($0.download) } ?? ratePlaceholder)
                            trafficMetric(L("实时上传"), value: rates.map { TrafficRate.label($0.upload) } ?? ratePlaceholder)
                        }
                    } else if hasTraffic {
                        GridRow {
                            trafficMetric(L("近 7 天下载"), value: trafficBytes(weekCount.download))
                            trafficMetric(L("近 7 天上传"), value: trafficBytes(weekCount.upload))
                        }
                    }
                }
                .frame(width: 244, alignment: .leading)
                VStack(alignment: .leading, spacing: 6) {
                    Text(L("近 7 天"))
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                    if hasTraffic {
                        TrafficTrendChart(days: days, height: chartHeight, barWidth: .fixed(24),
                                          maxHeight: compact ? nil : 210, showsGrid: true)
                    } else {
                        Text(L("近 7 天暂无流量记录"))
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity)
                            .frame(minHeight: chartHeight, idealHeight: chartHeight, maxHeight: compact ? chartHeight : 120)
                            .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 7))
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 10)
                .padding(.vertical, compact ? 3 : 6)
                .background(HopAppearance.insetSurface, in: RoundedRectangle(cornerRadius: 8))
            }
        }
        .hopPanel(verticalPadding: compact ? 8 : 14)
    }

    private func trafficMetric(_ title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary).lineLimit(1).minimumScaleFactor(0.84)
            Text(value)
                .font(.system(.title3, design: .rounded).weight(.semibold))
                .monospacedDigit()
                .lineLimit(1)
                .minimumScaleFactor(0.85)
        }
        .frame(width: 116, alignment: .leading)
        .accessibilityElement(children: .combine)
    }

    private func subscriptionsOverview(compact: Bool) -> some View {
        let subscriptions = core.subscriptions
        let enabled = subscriptions.filter { !$0.isPaused }
        let selected = running && !core.statusReadFailed ? core.status?.currentOutbound.flatMap(subscription(for:)) : nil
        let visible = ([selected].compactMap { $0 }
                       + enabled.filter { $0.id != selected?.id }
                       + subscriptions.filter(\.isPaused)).prefix(4)

        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Label(L("订阅速览"), systemImage: "tray.full").labelStyle(HopSectionLabelStyle())
                if !subscriptions.isEmpty {
                    Text(L("<1>/<2> 份启用", enabled.count, subscriptions.count))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
                Spacer()
                let more = subscriptions.count - visible.count
                overviewLink(more > 0 ? L("查看其余 <1> 份", more) : L("管理订阅"), action: showSubscriptions)
            }
            if visible.isEmpty {
                Text(core.profileReadFailed ? L("暂时无法读取订阅") :
                        core.configuredProfile == nil ? L("正在读取订阅…") : L("暂无订阅"))
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                HStack(spacing: 8) {
                    ForEach(visible) { subscription in
                        subscriptionSummary(subscription, inUse: subscription.id == selected?.id, compact: compact)
                    }
                }
            }
        }
        .hopPanel(verticalPadding: compact ? 8 : 12)
    }

    private func subscription(for node: String) -> SubscriptionSummary? {
        let matches = core.subscriptions.filter { !$0.isPaused && $0.nodes?.contains(node) == true }
        return matches.count == 1 ? matches.first : nil
    }

    private func subscriptionSummary(_ subscription: SubscriptionSummary, inUse: Bool, compact: Bool) -> some View {
        let meter = subscription.usage
        let remaining: String
        if let used = meter?.used, let total = meter?.total, total > 0 {
            remaining = L("剩余 ") + trafficBytes(total > used ? total - used : 0)
        } else {
            remaining = L("额度未提供")
        }
        let expiration = meter?.expiration
        let expired = expiration.map { $0 < Calendar.current.startOfDay(for: .now) } ?? false
        let expiry = expiration.map { $0.formatted(.dateTime.month(.defaultDigits).day(.defaultDigits)) + L(" 到期") }
            ?? L("到期日未知")
        let detail = remaining + " · " + (expired ? L("已到期") : expiry)

        return VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(subscription.name).font(.callout.weight(.semibold)).lineLimit(1)
                if inUse {
                    HStack(spacing: 4) {
                        Circle().fill(HopAppearance.accent).frame(width: 6, height: 6)
                            .accessibilityHidden(true)
                        Text(L("使用中")).font(.caption.weight(.medium))
                    }
                    .foregroundStyle(HopAppearance.accent)
                    .fixedSize()
                } else if subscription.isPaused {
                    Text(L("已暂停")).font(.caption).foregroundStyle(.secondary)
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
        .padding(.horizontal, 9)
        .padding(.vertical, compact ? 5 : 7)
        .background(inUse ? HopAppearance.accent.opacity(0.08) : Color.primary.opacity(0.035),
                    in: RoundedRectangle(cornerRadius: 7))
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
