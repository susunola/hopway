import AppKit
import SwiftUI

struct OverviewDashboard: View {
    @ObservedObject var core: CoreModel
    let showNodes: () -> Void
    let importLink: () -> Void
    @State private var showsAuto = false

    private var running: Bool { core.phase == .running }
    private var busy: Bool { core.phase == .starting || core.phase == .stopping || core.saving }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HopPageHeading(title: "概览", detail: "管理本机代理，查看当前连接状态。")
                hero
                if core.configuredNodes.isEmpty {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("添加你的第一个订阅").font(.headline)
                            Text("导入后可以查看节点、测速并验证联网。")
                                .font(.callout).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("导入链接…", action: importLink).disabled(core.saving)
                    }
                    .hopPanel()
                }
                HStack(spacing: 12) {
                    metric("SOCKS5", value: core.endpoint?.socks, icon: "point.topleft.down.to.point.bottomright.curvepath", address: true)
                    metric("HTTP / CONNECT", value: core.endpoint?.http, icon: "globe", address: true)
                    metric("活动连接", value: core.status.map { $0.active.formatted() }, icon: "waveform")
                }
                HStack(spacing: 12) {
                    metric("系统接管", value: core.status.map {
                        if $0.tun?.enabled == true { return "TUN" }
                        if $0.systemProxy?.enabled == true { return "系统代理" }
                        return "手动接入"
                    }, icon: "network")
                    VStack(alignment: .leading, spacing: 8) {
                        Text(core.verification ?? "尚未验证当前路由")
                            .font(.callout)
                            .accessibilityAddTraits(.updatesFrequently)
                        Button(core.verifying ? "正在验证…" : "验证联网", action: core.verifyConnection)
                            .disabled(!running || core.verifying)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .hopPanel()
                }
                routing
            }
        }
        .scrollIndicators(.hidden)
        .sheet(isPresented: $showsAuto) { AutoRoutingSheet(core: core) }
    }

    private var hero: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack(spacing: 6) {
                Circle()
                    .fill(running ? HopAppearance.mint : Color.white.opacity(0.55))
                    .frame(width: 6, height: 6)
                Text("本机代理").font(.caption.weight(.medium))
            }
            .foregroundStyle(.white.opacity(0.8))
            Text(core.phase.rawValue)
                .font(.system(size: 36, weight: .semibold))
                .accessibilityAddTraits(.isHeader)
            Button(action: core.toggle) {
                Label(running ? "停止代理" : "启动代理", systemImage: "power")
            }
            .buttonStyle(HopPrimaryButton())
            .disabled(busy)
            .padding(.top, 3)
        }
        .foregroundStyle(.white)
        .padding(23)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(alignment: .trailing) {
            ZStack(alignment: .trailing) {
                LinearGradient(
                    colors: [HopAppearance.navy, Color(red: 0.08, green: 0.21, blue: 0.28)],
                    startPoint: .leading, endPoint: .trailing
                )
                routeMark
                    .frame(width: 265, height: 130)
                    .padding(.trailing, 30)
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 15))
    }

    private var routeMark: some View {
        Canvas { context, size in
            let x = size.width
            let y = size.height
            let start = CGPoint(x: x * 0.08, y: y * 0.80)
            let end = CGPoint(x: x * 0.91, y: y * 0.20)
            var path = Path()
            path.move(to: start)
            path.addLine(to: CGPoint(x: x * 0.24, y: start.y))
            path.addCurve(
                to: CGPoint(x: x * 0.43, y: y * 0.50),
                control1: CGPoint(x: x * 0.34, y: start.y),
                control2: CGPoint(x: x * 0.33, y: y * 0.50)
            )
            path.addLine(to: CGPoint(x: x * 0.57, y: y * 0.50))
            path.addCurve(
                to: CGPoint(x: x * 0.76, y: end.y),
                control1: CGPoint(x: x * 0.67, y: y * 0.50),
                control2: CGPoint(x: x * 0.66, y: end.y)
            )
            path.addLine(to: end)
            let color = HopAppearance.mint.opacity(running ? 0.85 : 0.36)
            context.stroke(path, with: .color(color), style: StrokeStyle(lineWidth: 4, lineCap: .round))
            for point in [start, end] {
                context.fill(Path(ellipseIn: CGRect(x: point.x - 6, y: point.y - 6, width: 12, height: 12)), with: .color(color))
            }
        }
        .accessibilityHidden(true)
    }

    private func metric(_ title: String, value: String?, icon: String, address: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: icon).font(.caption).foregroundStyle(.secondary)
            HStack(spacing: 5) {
                Text(value ?? "—")
                    .font(.system(size: 15, weight: .medium, design: address ? .monospaced : .default))
                    .monospacedDigit()
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                Spacer(minLength: 0)
                if address, let value {
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(value, forType: .string)
                    } label: {
                        Image(systemName: "document.on.document")
                    }
                    .buttonStyle(.borderless)
                    .help("复制代理地址")
                    .accessibilityLabel("复制\(title)地址")
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .hopPanel()
    }

    private var routing: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("路由策略", systemImage: "arrow.triangle.branch").font(.headline)
                Spacer()
                if running {
                    Button("自动选路…") { showsAuto = true }.disabled(core.updatingPolicy)
                }
                Button("查看节点", action: showNodes)
                    .buttonStyle(.plain)
                    .font(.callout.weight(.medium))
                    .foregroundStyle(HopAppearance.accent)
            }
            if let status = core.status {
                HStack(alignment: .center, spacing: 14) {
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
                    .frame(maxWidth: 245)
                    if status.policy.mode != "auto" {
                        Picker("出站", selection: Binding(
                        get: { status.policy.selected },
                        set: { core.updatePolicy(Policy(mode: status.policy.mode, selected: $0)) }
                    )) {
                            ForEach(status.nodes) { node in
                                Text(node.name).tag(node.name)
                            }
                        }
                    }
                }
                .disabled(core.updatingPolicy)
                if let auto = status.auto {
                    if let provider = auto.provider, let node = auto.node {
                        Label("\(provider) · \(node)", systemImage: "point.3.connected.trianglepath.dotted")
                            .font(.callout)
                            .lineLimit(1)
                            .help(node)
                    } else {
                        Text(auto.probing ? "正在检测同地区节点…" : "暂未找到通过测速的节点。")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
            } else {
                Text("启动代理后可切换路由模式和出站节点。")
                    .foregroundStyle(.secondary)
                    .font(.callout)
            }
        }
        .hopPanel()
    }
}
