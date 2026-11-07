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
        if let proxy = core.status?.systemProxy, proxy.supported {
            Button(proxy.enabled ? "关闭系统代理" : "设为系统代理") { core.setSystemProxy(!proxy.enabled) }
        }
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
                policies.tabItem { Label("策略", systemImage: "square.stack.3d.up") }.tag("policies")
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
                            if let proxy = status.systemProxy, proxy.supported {
                                Toggle("设为系统代理", isOn: Binding(
                                    get: { proxy.enabled },
                                    set: { core.setSystemProxy($0) }
                                ))
                                Text(proxy.error ?? "开启后，所有网络服务的 HTTP、HTTPS 和 SOCKS 代理都指向 HopWay；停止或退出时会还原原来的设置。")
                                    .font(.caption).foregroundStyle(proxy.error == nil ? Color.secondary : .red)
                            }
                            if let tun = status.tun, tun.supported {
                                Toggle("增强模式（TUN）", isOn: Binding(
                                    get: { tun.enabled },
                                    set: { core.setTUN($0) }
                                ))
                                Text(tun.error ?? (tun.enabled
                                    ? "已接管全部流量（\(tun.device ?? "utun")）。不认系统代理的应用、命令行工具和 DNS 也会经过 HopWay。"
                                    : (tun.service == true ? "接管所有应用的流量，包括不认系统代理的应用。" : "接管所有应用的流量，包括不认系统代理的应用。开启时需要输入一次管理员密码。")))
                                    .font(.caption).foregroundStyle(tun.error == nil ? Color.secondary : .red)
                                Button(tun.service == true ? "卸载免密服务" : "安装免密服务（开启 TUN 不再询问密码）") {
                                    core.setTUNService(tun.service != true)
                                }
                                .buttonStyle(.link)
                                .font(.caption)
                            }
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
                        Text("打开上方「设为系统代理」，大多数应用会自动经过 HopWay；不认系统代理的应用和命令行工具，可以打开增强模式（TUN），或者在应用里手动填写上方的代理地址。")
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

    private var policies: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                if let status = core.status {
                    HStack {
                        Text("策略组").font(.headline)
                        Spacer()
                        Button("测速全部节点") { core.trigger("probe", done: "正在测速…") }
                    }
                    if let groups = status.groups, !groups.isEmpty {
                        ForEach(groups) { group in
                            GroupBox {
                                VStack(alignment: .leading, spacing: 8) {
                                    if group.type == "select" {
                                        Picker("使用", selection: Binding(
                                            get: { group.selected ?? group.now },
                                            set: { core.selectInGroup(group.name, member: $0) }
                                        )) {
                                            ForEach(group.members, id: \.self) { member in
                                                Text(core.memberLabel(member)).tag(member)
                                            }
                                        }
                                    } else {
                                        Text("正在使用 " + core.memberLabel(group.now)).monospacedDigit()
                                        Text(group.members.map { core.memberLabel($0) }.joined(separator: "，"))
                                            .font(.caption).foregroundStyle(.secondary)
                                            .fixedSize(horizontal: false, vertical: true)
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(8)
                            } label: {
                                Text(group.name + " · " + group.typeLabel)
                            }
                        }
                    } else {
                        Text("还没有策略组。导入 Clash 订阅时会一并导入，也可以在配置里编写 groups。")
                            .foregroundStyle(.secondary)
                    }
                    if let subscriptions = status.subscriptions, !subscriptions.isEmpty {
                        HStack {
                            Text("订阅").font(.headline)
                            Spacer()
                            Button("立即更新") { core.trigger("subscriptions/refresh", done: "正在更新订阅…") }
                        }
                        ForEach(subscriptions) { sub in
                            sourceRow(sub.name, detail: "\(sub.nodes) 个节点", updated: sub.updated, error: sub.error)
                        }
                    }
                    if let sets = status.ruleSets, !sets.isEmpty {
                        HStack {
                            Text("规则集").font(.headline)
                            Spacer()
                            Button("立即更新") { core.trigger("rulesets/refresh", done: "正在更新规则集…") }
                        }
                        ForEach(sets) { item in
                            sourceRow(item.name, detail: "\(item.entries) 条", updated: item.updated, error: item.error)
                        }
                    }
                } else {
                    Text("启动内核后，可以在这里切换策略组、测速和更新订阅。")
                        .foregroundStyle(.secondary)
                }
            }
            .padding(14)
        }
    }

    private func sourceRow(_ name: String, detail: String, updated: Double?, error: String?) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(name)
            Text(detail).foregroundStyle(.secondary).monospacedDigit()
            Spacer()
            if let error {
                Text(error).foregroundStyle(.red).lineLimit(1).help(error)
            } else if let updated {
                Text(Date(timeIntervalSince1970: updated / 1000).formatted(date: .abbreviated, time: .shortened))
                    .foregroundStyle(.secondary)
            } else {
                Text("尚未下载").foregroundStyle(.secondary)
            }
        }
        .font(.callout)
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
                filter.isEmpty || [row.target, row.via, row.inbound, row.stateLabel, row.rule, row.process ?? ""]
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
                    TableColumn("应用") { Text($0.process ?? "—").help($0.processPath ?? "") }.width(min: 80, ideal: 120)
                    TableColumn("入站", value: \.inboundLabel).width(min: 80, ideal: 105)
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
