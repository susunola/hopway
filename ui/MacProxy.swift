import AppKit
import SwiftUI
import UniformTypeIdentifiers

@main
struct MacProxyApp: App {
    @StateObject private var core = CoreModel()

    var body: some Scene {
        Window("HopWay", id: "dashboard") {
            Dashboard(core: core)
        }
        .defaultSize(width: 930, height: 620)

        MenuBarExtra("HopWay", systemImage: core.phase == .running ? "point.3.connected.trianglepath.dotted" : "point.3.filled.connected.trianglepath.dotted") {
            StatusMenu(core: core)
        }
    }
}

private struct StatusMenu: View {
    @Environment(\.openWindow) private var openWindow
    @ObservedObject var core: CoreModel

    var body: some View {
        Text("代理 · " + core.phase.rawValue)
        Button(core.phase == .running ? "停止代理" : "启动代理", action: core.toggle)
            .disabled(core.phase == .starting || core.phase == .stopping || core.saving)
        Button("打开控制台") {
            openWindow(id: "dashboard")
            NSApp.activate(ignoringOtherApps: true)
        }
        Divider()
        Button("退出 HopWay") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}

private struct Dashboard: View {
    @ObservedObject var core: CoreModel
    @State private var filter = ""
    @State private var selectedTab = "overview"

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 13) {
                Image(systemName: "point.3.connected.trianglepath.dotted")
                    .font(.title2.weight(.semibold))
                    .foregroundStyle(Color.accentColor)
                    .frame(width: 42, height: 42)
                    .background(Color.accentColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 11))
                VStack(alignment: .leading, spacing: 3) {
                    Text("HopWay").font(.title2.bold())
                    Label(core.phase.rawValue, systemImage: "circle.fill")
                        .font(.caption)
                        .foregroundStyle(core.phase == .running ? Color.green : .secondary)
                }
                Spacer()
                Button(action: core.toggle) {
                    Label(core.phase == .running ? "停止代理" : "启动代理", systemImage: "power")
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(core.phase == .starting || core.phase == .stopping || core.saving)
            }
            .padding(20)
            Divider()
            TabView(selection: $selectedTab) {
                overview.tabItem { Label("概览", systemImage: "gauge.with.dots.needle.33percent") }.tag("overview")
                connections.tabItem { Label("连接", systemImage: "arrow.left.arrow.right") }.tag("connections")
                configuration.tabItem { Label("配置", systemImage: "slider.horizontal.3") }.tag("configuration")
            }
            .padding(16)
            if let message = core.message {
                Text(message)
                    .font(.callout)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 24)
                    .padding(.bottom, 14)
            }
        }
        .frame(minWidth: 810, minHeight: 490)
    }

    private var overview: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 12) {
                    metric("SOCKS5", core.endpoint?.socks, icon: "point.topleft.down.to.point.bottomright.curvepath")
                    metric("HTTP / CONNECT", core.endpoint?.http, icon: "globe")
                    metric("活动连接", core.status.map { String($0.active) }, icon: "waveform", copyable: false)
                }
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        if let status = core.status {
                            Picker("路由模式", selection: Binding(
                                get: { status.policy.mode },
                                set: { core.updatePolicy(Policy(mode: $0, selected: status.policy.selected)) }
                            )) {
                                Text("按规则").tag("rule")
                                Text("全局").tag("global")
                                Text("直连").tag("direct")
                            }
                            .pickerStyle(.segmented)
                            Picker("选定出站", selection: Binding(
                                get: { status.policy.selected },
                                set: { core.updatePolicy(Policy(mode: status.policy.mode, selected: $0)) }
                            )) {
                                ForEach(status.nodes) { node in
                                    Text(node.label).tag(node.name)
                                }
                            }
                            Text("全局模式和规则中的 SELECT 使用选定出站。界面切换只对本次运行生效。")
                                .font(.caption).foregroundStyle(.secondary)
                        } else {
                            Text("启动内核后，可在这里切换路由模式和出站。")
                                .foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .disabled(core.updatingPolicy)
                } label: {
                    Label("路由策略", systemImage: "arrow.triangle.branch")
                }
                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("在应用里填入上方代理地址。若想在 macOS 设置系统代理，打开「系统设置 → 网络 → 当前网络 → 详细信息 → 代理」，按需填写 Web、安全 Web 或 SOCKS 代理。停用内核前关闭这些设置。")
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        HStack {
                            Button("一键导入", action: core.importClipboard).disabled(core.saving)
                            Button("编辑节点与规则") { selectedTab = "configuration" }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                } label: {
                    Label("接入方式", systemImage: "network")
                }
            }
            .padding(14)
        }
    }

    private func metric(_ title: String, _ value: String?, icon: String, copyable: Bool = true) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            Label(title, systemImage: icon).font(.callout.weight(.medium)).foregroundStyle(.secondary)
            HStack {
                Text(value ?? "—").font(.system(.title3, design: .monospaced).weight(.medium))
                Spacer()
                if copyable, let value {
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(value, forType: .string)
                    } label: { Image(systemName: "document.on.document") }
                    .buttonStyle(.borderless)
                    .help("复制代理地址")
                    .accessibilityLabel("复制\(title)地址")
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.28), in: RoundedRectangle(cornerRadius: 10))
    }

    private var rows: [ProxyStatus.Connection] {
        (core.status?.connections ?? [])
            .filter { row in
                filter.isEmpty || [row.target, row.via, row.inbound, row.stateLabel, row.rule]
                    .contains { $0.localizedCaseInsensitiveContains(filter) }
            }
            .sorted { lhs, rhs in
                if (lhs.state == "active") != (rhs.state == "active") { return lhs.state == "active" }
                return lhs.id > rhs.id
            }
    }

    private var connections: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("连接记录").font(.headline)
                Spacer()
                TextField("筛选目标、协议或规则", text: $filter).frame(width: 220)
            }
            if rows.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "arrow.left.arrow.right").font(.largeTitle)
                    Text(filter.isEmpty ? "暂无连接" : "没有匹配的连接").font(.headline)
                    Text("代理收到流量后，目标和规则会显示在这里。").font(.callout)
                }
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Table(rows) {
                    TableColumn("目标") { Text($0.target).textSelection(.enabled).help($0.diagnosis) }.width(min: 135, ideal: 180)
                    TableColumn("入站", value: \.inbound).width(min: 80, ideal: 105)
                    TableColumn("出站", value: \.via).width(min: 80, ideal: 100)
                    TableColumn("规则", value: \.rule).width(min: 65, ideal: 130)
                    TableColumn("状态") { row in
                        Text(row.stateLabel)
                            .foregroundStyle(row.state == "active" ? Color.green : row.state == "failed" ? .red : .secondary)
                            .help(row.diagnosis)
                    }.width(66)
                    TableColumn("发送 / 接收") {
                        Text("\($0.sent.formatted()) / \($0.received.formatted()) B").monospacedDigit()
                    }.width(min: 110, ideal: 140)
                }
            }
        }
        .padding(14)
    }

    private var configuration: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("内核配置").font(.headline)
                if core.changed { Text("有未保存修改").font(.caption).foregroundStyle(.orange) }
                Spacer()
                Button("一键导入", action: core.importClipboard).disabled(core.saving)
                Button("打开 JSON", action: core.importDraft).disabled(core.saving)
                Menu("插入节点模板") {
                    ForEach(["socks5", "http", "https", "trojan", "shadowsocks", "vless", "vmess"], id: \.self) { type in
                        Button(type) { core.insertTemplate(type) }
                    }
                }.disabled(core.saving)
                Button(core.saving ? "正在校验…" : "校验并保存", action: core.save)
                    .buttonStyle(.borderedProminent)
                    .disabled(core.saving || !core.changed)
            }
            TextEditor(text: $core.draft)
                .disabled(core.saving)
                .font(.system(.body, design: .monospaced))
                .autocorrectionDisabled()
                .padding(6)
                .border(.quaternary)
                .accessibilityLabel("JSON 配置编辑器")
            Text("一键导入读取剪贴板。支持订阅链接、Clash 内联节点和分享链接，保存后于下次启动生效。")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(14)
    }
}
