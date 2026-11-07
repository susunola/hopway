import AppKit
import SwiftUI

struct OverviewDashboard: View {
    @ObservedObject var core: CoreModel
    let showNodes: () -> Void
    let showUsage: () -> Void
    let importLink: () -> Void
    @State private var showsAuto = false
    @State private var configuration: ConfigurationSummary?

    private struct ConfigurationSummary: Decodable {
        let socksPort: Int?
        let httpPort: Int?
        let mode: String?
        let selected: String?

        var modeLabel: String {
            switch mode {
            case "global": "全局"
            case "direct": "直连"
            case "auto": "自动"
            default: "按规则"
            }
        }
    }

    private var running: Bool { core.phase == .running }
    private var busy: Bool { core.phase == .starting || core.phase == .stopping || core.saving }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("概览")
                    .font(.system(size: 27, weight: .semibold))
                    .accessibilityAddTraits(.isHeader)
                    .padding(.bottom, 2)
                proxyControl
                routing
                localAccess
                traffic
            }
            .padding(.bottom, 12)
        }
        .onChange(of: core.saved, initial: true) { _, text in
            configuration = try? JSONDecoder().decode(ConfigurationSummary.self, from: Data(text.utf8))
        }
        .sheet(isPresented: $showsAuto) { AutoRoutingSheet(core: core) }
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
        .padding(.vertical, 12)
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
                    Button("自动选路…") { showsAuto = true }.disabled(core.updatingPolicy)
                }
                if core.configuredNodes.isEmpty {
                    Button("导入链接…", action: importLink).disabled(core.saving)
                }
                overviewLink("查看节点", action: showNodes)
            }

            if running, let status = core.status {
                policyControls(status)
            } else if !running, let configuration {
                HStack(spacing: 18) {
                    LabeledContent("配置模式", value: configuration.modeLabel)
                        .fixedSize()
                    if let selected = configuration.selected, !selected.isEmpty {
                        HStack(spacing: 8) {
                            Text("配置出站").foregroundStyle(.secondary)
                            Text(selected).lineLimit(1).help(selected)
                        }
                    }
                }
                .font(.callout)
            } else {
                Text(running ? "正在读取当前策略…" : "启动代理后可切换模式和出站。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .hopPanel()
    }

    private func policyControls(_ status: ProxyStatus) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(alignment: .center, spacing: 16) {
                Picker("模式", selection: Binding(
                    get: { status.policy.mode },
                    set: { if $0 != "auto" { core.updatePolicy(Policy(mode: $0, selected: status.policy.selected)) } }
                )) {
                    Text("按规则").tag("rule")
                    Text("全局").tag("global")
                    Text("直连").tag("direct")
                    if status.policy.mode == "auto" { Text("自动").tag("auto") }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 226)
                if status.policy.mode != "auto" {
                    Picker("出站", selection: Binding(
                        get: { status.policy.selected },
                        set: { core.updatePolicy(Policy(mode: status.policy.mode, selected: $0)) }
                    )) {
                        ForEach(status.nodes) { node in
                            Text(node.name).tag(node.name)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                } else if let auto = status.auto {
                    if let provider = auto.provider, let node = auto.node {
                        Label("\(provider) · \(node)", systemImage: "point.3.connected.trianglepath.dotted")
                            .font(.callout)
                            .lineLimit(1)
                            .help(node)
                    } else {
                        Text(auto.probing ? "正在检测同地区节点…" : "暂未找到可用节点。")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .disabled(core.updatingPolicy)
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
        .hopPanel()
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

    private var traffic: some View {
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
                Divider().frame(height: 123)
                VStack(alignment: .leading, spacing: 5) {
                    Text("近 7 天")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                    if days.contains(where: { $0.count.total > 0 }) {
                        TrafficTrendChart(days: days, height: 84)
                    } else {
                        Text("近 7 天暂无流量记录")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .frame(height: 84, alignment: .center)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .hopPanel()
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

    private func overviewLink(_ title: String, action: @escaping () -> Void) -> some View {
        Button(title, action: action)
            .buttonStyle(.plain)
            .font(.callout.weight(.medium))
            .foregroundStyle(HopAppearance.accent)
    }
}
