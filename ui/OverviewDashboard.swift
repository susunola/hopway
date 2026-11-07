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
            VStack(alignment: .leading, spacing: 12) {
                Text("概览")
                    .font(.system(size: 27, weight: .semibold))
                    .accessibilityAddTraits(.isHeader)
                    .padding(.bottom, 2)
                proxyControl
                routing
                if running, let endpoint = core.endpoint {
                    localAccess(endpoint)
                }
            }
            .padding(.bottom, 12)
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
            if running, let status = core.status {
                controlMetric("接入方式", value: accessMode(status))
                controlMetric("活动连接", value: status.active.formatted())
            }
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
                Button("查看节点", action: showNodes)
                    .buttonStyle(.plain)
                    .font(.callout.weight(.medium))
                    .foregroundStyle(HopAppearance.accent)
            }

            if running, let status = core.status {
                policyControls(status)
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

    private func localAccess(_ endpoint: Endpoint) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                Label("本机入口", systemImage: "network").font(.headline)
                Spacer()
                Text(core.verifying ? "正在验证当前路由…" : core.verification ?? "当前路由待验证")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .help(core.verification ?? "验证当前路由能否访问测试地址")
                    .accessibilityAddTraits(.updatesFrequently)
                Button("验证联网", action: core.verifyConnection)
                    .disabled(core.verifying)
                    .fixedSize()
            }
            Divider()
            HStack(spacing: 16) {
                address("SOCKS5", value: endpoint.socks)
                Divider().frame(height: 25)
                address("HTTP / CONNECT", value: endpoint.http)
            }
        }
        .hopPanel()
    }

    private func address(_ title: String, value: String) -> some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.caption).foregroundStyle(.secondary)
                Text(value)
                    .font(.system(.callout, design: .monospaced).weight(.medium))
                    .lineLimit(1)
                    .help(value)
            }
            Spacer(minLength: 0)
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
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
