import AppKit
import SwiftUI
import UniformTypeIdentifiers

private final class HopWayAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        guard let iconFile = Bundle.main.object(forInfoDictionaryKey: "CFBundleIconFile") as? String,
              let iconURL = Bundle.main.url(forResource: iconFile, withExtension: nil),
              let icon = NSImage(contentsOf: iconURL) else { return }
        NSApplication.shared.applicationIconImage = icon
    }
}

@main
struct MacProxyApp: App {
    @NSApplicationDelegateAdaptor(HopWayAppDelegate.self) private var appDelegate
    @StateObject private var core = CoreModel()

    var body: some Scene {
        Window("HopWay", id: "dashboard") {
            Dashboard(core: core)
        }
        .defaultSize(width: 1040, height: 690)

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

private enum DashboardPage: String, CaseIterable {
    case overview, nodes, policies, subscriptions, usage, connections, settings

    var title: String {
        switch self {
        case .overview: "概览"
        case .nodes: "节点"
        case .subscriptions: "订阅"
        case .usage: "用量"
        case .policies: "策略"
        case .connections: "连接"
        case .settings: "设置"
        }
    }

    var icon: String {
        switch self {
        case .overview: "house"
        case .nodes: "point.3.connected.trianglepath.dotted"
        case .subscriptions: "tray.full"
        case .usage: "chart.bar.xaxis"
        case .policies: "point.3.connected.trianglepath.dotted"
        case .connections: "arrow.left.arrow.right"
        case .settings: "gearshape"
        }
    }
}

private struct Dashboard: View {
    @ObservedObject var core: CoreModel
    @State private var filter = ""
    @State private var routeHost = ""
    @State private var routeResult: String?
    @State private var testingRoute = false
    @State private var page: DashboardPage = .overview
    @State private var showsLinkImport = false
    @State private var importLink = ""
    @State private var preview: CoreModel.ImportPreview?
    @State private var importError: String?
    @State private var previewing = false
    @State private var showsConfigurationEditor = false

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
            VStack(spacing: 0) {
                Group {
                    switch page {
                    case .overview:
                        OverviewDashboard(core: core, showNodes: { page = .nodes }, importLink: { showsLinkImport = true })
                    case .nodes:
                        NodeDashboard(core: core) { showsLinkImport = true }
                    case .policies:
                        ScrollView { VStack(alignment: .leading, spacing: 16) { routeTester; policies } }
                    case .subscriptions:
                        SubscriptionDashboard(core: core) { showsLinkImport = true }
                    case .usage:
                        TrafficDashboard(core: core)
                    case .connections:
                        connections
                    case .settings:
                        configuration
                    }
                }
                .padding(26)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                if let message = core.message {
                    Divider()
                    Label(message, systemImage: "info.circle")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 26)
                        .padding(.vertical, 11)
                }
            }
            .background(Color(nsColor: .controlBackgroundColor))
        }
        .tint(HopAppearance.accent)
        .frame(minWidth: 880, minHeight: 525)
        .onChange(of: core.importCount) { _, _ in
            if page != .subscriptions { page = .nodes }
        }
        .sheet(isPresented: $showsLinkImport, onDismiss: { importLink = ""; preview = nil; importError = nil }) {
            VStack(alignment: .leading, spacing: 12) {
                Text("导入链接").font(.headline)
                Text("粘贴 Shadowrocket 或 Clash 的一键导入链接，也可直接填订阅地址。")
                    .foregroundStyle(.secondary)
                TextField("订阅或节点链接", text: $importLink)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                if let preview {
                    Text("识别到 \(preview.added) 个节点 · 跳过 \(preview.skipped) 条")
                        .font(.headline)
                    ForEach(Array(preview.notes.enumerated()), id: \.offset) { _, note in
                        Text(note).font(.caption).foregroundStyle(.secondary)
                    }
                }
                if let importError {
                    Label(importError, systemImage: "exclamationmark.circle")
                        .font(.callout).foregroundStyle(.orange)
                }
                HStack {
                    Spacer()
                    Button("取消") { showsLinkImport = false }.keyboardShortcut(.cancelAction)
                    Button(previewing ? "正在预览…" : preview == nil ? "预览" : "确认导入") {
                        if preview != nil {
                            core.importContent(importLink)
                            showsLinkImport = false
                        } else {
                            let link = importLink
                            previewing = true
                            importError = nil
                            Task {
                                defer { previewing = false }
                                do {
                                    let result = try await core.previewImport(link)
                                    if importLink == link && showsLinkImport { preview = result }
                                } catch {
                                    if importLink == link && showsLinkImport { importError = error.localizedDescription }
                                }
                            }
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(previewing || importLink.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || core.saving)
                }
            }
            .padding(22)
            .frame(width: 490)
            .onChange(of: importLink) { _, _ in preview = nil; importError = nil }
        }
        .sheet(isPresented: $showsConfigurationEditor) {
            configurationEditor
        }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 9) {
                Image(nsImage: NSApplication.shared.applicationIconImage)
                    .resizable()
                    .frame(width: 35, height: 35)
                    .accessibilityHidden(true)
                Text("HopWay").font(.system(size: 17, weight: .semibold))
            }
            .padding(.horizontal, 8)
            .padding(.bottom, 19)

            ForEach(DashboardPage.allCases, id: \.self) { destination in
                Button {
                    page = destination
                } label: {
                    HStack(spacing: 10) {
                        Image(systemName: destination.icon).frame(width: 17)
                        Text(destination.title)
                        Spacer(minLength: 0)
                        if destination == .nodes && !core.configuredNodes.isEmpty {
                            Text(core.configuredNodes.count.formatted())
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.secondary)
                        }
                    }
                    .font(.system(size: 13, weight: page == destination ? .semibold : .regular))
                    .foregroundStyle(page == destination ? HopAppearance.accent : Color.primary)
                    .padding(.horizontal, 10)
                    .frame(height: 34)
                    .background(page == destination ? HopAppearance.accent.opacity(0.12) : .clear, in: RoundedRectangle(cornerRadius: 8))
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(page == destination ? .isSelected : [])
            }

            Spacer()
            Divider().padding(.bottom, 8)
            HStack(spacing: 7) {
                Circle()
                    .fill(core.phase == .running ? HopAppearance.accent : Color.secondary)
                    .frame(width: 7, height: 7)
                Text(core.phase.rawValue).font(.caption).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 10)
            .padding(.bottom, 5)
        }
        .padding(14)
        .frame(width: 172)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var routeTester: some View {
        VStack(alignment: .leading, spacing: 10) {
            HopPageHeading(title: "策略", detail: "试跑一个地址，查看内核当前会选择的出口。")
            HStack {
                TextField("域名或 IP", text: $routeHost)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel("待测试地址")
                Button(testingRoute ? "正在试跑…" : "试跑") {
                    testingRoute = true
                    let address = routeHost
                    Task {
                        defer { testingRoute = false }
                        do {
                            let result = try await core.explainRoute(address)
                            routeResult = result.rule + " · " + ((result.path ?? []) + [result.outbound]).joined(separator: " → ")
                        } catch {
                            routeResult = error.localizedDescription
                        }
                    }
                }
                .disabled(core.phase != .running || routeHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || testingRoute)
            }
            if let routeResult { Text(routeResult).textSelection(.enabled) }
        }
        .hopPanel()
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
            HopPageHeading(title: "连接", detail: "查看流量经过的节点和命中的规则。")
            HStack {
                HopSearchField(placeholder: "筛选目标、节点或规则", text: $filter)
                    .frame(width: 235)
                Spacer()
                Text("\(core.status?.active ?? 0) 个活动连接")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            if rows.isEmpty {
                ContentUnavailableView(
                    filter.isEmpty ? "暂无连接" : "没有匹配的连接",
                    systemImage: filter.isEmpty ? "arrow.left.arrow.right" : "magnifyingglass",
                    description: Text(filter.isEmpty ? "代理收到流量后，连接会显示在这里。" : "试试其他关键词。")
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Table(rows) {
                    TableColumn("目标") { Text($0.target).textSelection(.enabled).help($0.diagnosis) }.width(min: 120, ideal: 150)
                    TableColumn("入站", value: \.inboundLabel).width(min: 68, ideal: 85)
                    TableColumn("出站", value: \.via).width(min: 68, ideal: 95)
                    TableColumn("规则", value: \.rule).width(min: 60, ideal: 95)
                    TableColumn("状态") { row in
                        Text(row.stateLabel)
                            .foregroundStyle(row.state == "active" ? Color.green : row.state == "failed" ? .red : .secondary)
                            .help(row.error ?? row.stateLabel)
                    }.width(66)
                    TableColumn("发送 / 接收") {
                        Text("\($0.sent.formatted()) / \($0.received.formatted()) B").monospacedDigit()
                    }.width(min: 110, ideal: 140)
                }
            }
        }
    }

    private var configuration: some View {
        VStack(alignment: .leading, spacing: 20) {
            HopPageHeading(title: "设置", detail: "管理 macOS 接入方式和内核配置。")
            VStack(alignment: .leading, spacing: 9) {
                switch core.phase {
                case .stopped:
                    Text("启动代理后，即可在这里设置系统代理、TUN 增强模式和 TUN 助手。")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Button("启动代理", action: core.toggle)
                        .buttonStyle(HopPrimaryButton())
                        .disabled(core.saving)
                case .starting, .stopping:
                    ProgressView(core.phase.rawValue)
                        .controlSize(.small)
                case .running:
                    if core.status == nil {
                        ProgressView("正在读取接入状态…")
                            .controlSize(.small)
                    } else {
                        Toggle("系统代理", isOn: Binding(
                            get: { core.status?.systemProxy?.enabled ?? false },
                            set: core.setSystemProxy))
                            .disabled(core.status?.systemProxy?.supported != true)
                        Toggle("TUN 增强模式", isOn: Binding(
                            get: { core.status?.tun?.enabled ?? false },
                            set: core.setTUN))
                            .disabled(core.status?.tun?.supported != true)
                        Button(core.status?.tun?.service == true ? "移除 TUN 助手" : "安装 TUN 助手") {
                            core.setTUNService(core.status?.tun?.service != true)
                        }
                        .disabled(core.status?.tun?.supported != true)
                        if let error = core.status?.systemProxy?.error ?? core.status?.tun?.error {
                            Text(error).font(.callout).foregroundStyle(.orange)
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .hopPanel()
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    Label("高级配置", systemImage: "chevron.left.forwardslash.chevron.right")
                        .font(.headline)
                    Text(core.changed ? "有未保存的草稿" : "编辑内核的节点、规则和监听端口。")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("编辑 JSON…") { showsConfigurationEditor = true }
            }
            .hopPanel()
            Spacer(minLength: 0)
        }
    }

    private var configurationEditor: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("高级配置").font(.headline)
                if core.changed { Text("未保存").font(.caption).foregroundStyle(.orange) }
                Spacer()
                Button("关闭") { showsConfigurationEditor = false }.keyboardShortcut(.cancelAction)
            }
            HStack {
                Button("打开 JSON", action: core.importDraft).disabled(core.saving)
                Menu("插入节点模板") {
                    ForEach(["socks5", "http", "https", "trojan", "shadowsocks", "anytls", "vless", "vmess"], id: \.self) { type in
                        Button(type) { core.insertTemplate(type) }
                    }
                }.disabled(core.saving)
                Spacer()
                Button(core.saving ? "正在校验…" : "校验并保存", action: core.save)
                    .buttonStyle(HopPrimaryButton())
                    .disabled(core.saving || !core.changed)
            }
            TextEditor(text: $core.draft)
                .disabled(core.saving)
                .font(.system(.body, design: .monospaced))
                .autocorrectionDisabled()
                .padding(6)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(.quaternary))
                .accessibilityLabel("JSON 配置编辑器")
            Text(core.message ?? "保存后于下次启动生效。关闭会保留草稿。")
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .padding(20)
        .frame(width: 650, height: 395)
    }
}
