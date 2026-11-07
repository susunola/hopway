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
        case .policies: "arrow.triangle.branch"
        case .connections: "arrow.left.arrow.right"
        case .settings: "gearshape"
        }
    }
}

private struct Dashboard: View {
    @ObservedObject var core: CoreModel
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
    @State private var advancedDraft: AdvancedSettingsDraft?

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
            VStack(spacing: 0) {
                Group {
                    switch page {
                    case .overview:
                        OverviewDashboard(
                            core: core,
                            showNodes: { page = .nodes },
                            showUsage: { page = .usage },
                            showSubscriptions: { page = .subscriptions },
                            importLink: { showsLinkImport = true }
                        )
                    case .nodes:
                        NodeDashboard(core: core) { showsLinkImport = true }
                    case .policies:
                        ScrollView {
                            VStack(alignment: .leading, spacing: 14) {
                                HopPageHeading(title: "策略", detail: "查看路由配置、策略组和规则集。")
                                policySummary
                                routeTester
                                policies
                            }
                            .padding(.bottom, 12)
                        }
                    case .subscriptions:
                        SubscriptionDashboard(core: core) { showsLinkImport = true }
                    case .usage:
                        TrafficDashboard(core: core)
                    case .connections:
                        ConnectionsDashboard(core: core)
                    case .settings:
                        configuration
                    }
                }
                .padding(.horizontal, 26)
                .padding(.top, 26)
                .padding(.bottom, page == .overview ? 0 : 26)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                if let message = core.tunProgress ?? core.message {
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
                    .fill(core.statusReadFailed ? Color.orange :
                          core.phase == .running ? HopAppearance.accent : Color.secondary)
                    .frame(width: 7, height: 7)
                Text(core.statusReadFailed ? "状态更新失败" : core.phase.rawValue)
                    .font(.caption)
                    .foregroundStyle(core.statusReadFailed ? Color.orange : .secondary)
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
            HStack {
                Label("路由试跑", systemImage: "arrow.triangle.branch").font(.headline)
                Spacer()
                if core.phase != .running {
                    Text("启动代理后可试跑").font(.caption).foregroundStyle(.secondary)
                }
            }
            HStack {
                TextField("域名或 IP", text: $routeHost)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel("待测试地址")
                Button(testingRoute ? "正在试跑…" : "试跑") {
                    testingRoute = true
                    let address = routeHost
                    let policy = core.status?.policy
                    let reload = core.status?.reloaded
                    Task {
                        defer { testingRoute = false }
                        do {
                            let result = try await core.explainRoute(address)
                            guard routeHost == address, core.phase == .running,
                                  core.status?.policy == policy, core.status?.reloaded == reload else { return }
                            routeResult = result.rule + " · " + ((result.path ?? []) + [result.outbound]).joined(separator: " → ")
                        } catch {
                            if routeHost == address, core.phase == .running {
                                routeResult = error.localizedDescription
                            }
                        }
                    }
                }
                .disabled(core.phase != .running || routeHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || testingRoute)
            }
            if let routeResult { Text(routeResult).textSelection(.enabled) }
        }
        .hopPanel()
        .onChange(of: routeHost) { _, _ in routeResult = nil }
        .onChange(of: core.status?.policy) { _, _ in routeResult = nil }
        .onChange(of: core.status?.reloaded) { _, _ in routeResult = nil }
        .onChange(of: core.phase) { _, _ in routeResult = nil }
    }

    private var policySummary: some View {
        let profile = core.configuredProfile
        let status = core.status
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(status == nil ? "配置摘要" : "当前路由", systemImage: "point.3.connected.trianglepath.dotted")
                    .font(.headline)
                Spacer()
                Button("管理订阅") { page = .subscriptions }
                    .buttonStyle(.plain)
                    .foregroundStyle(HopAppearance.accent)
            }
            if let mode = status?.policy.mode ?? profile?.mode {
                let outbound: String? = if mode == "auto", status != nil {
                    status?.auto?.node ?? "等待可用节点"
                } else if mode == "direct" {
                    "DIRECT"
                } else {
                    status?.policy.selected ?? profile?.selected
                }
                Text([Policy.label(mode), outbound].compactMap { $0 }.joined(separator: " · "))
                    .font(.callout.weight(.medium))
                    .lineLimit(1)
                    .help(outbound ?? Policy.label(mode))
            }
            if let profile {
                Text("\(profile.ruleCount ?? 0) 条配置规则 · \(profile.groups?.count ?? 0) 个策略组 · \(profile.ruleSets?.count ?? 0) 个规则集")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
            if core.profileReadFailed {
                Label("配置读取失败，请在设置中检查已保存的配置。", systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
        .hopPanel()
    }

    private var policies: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("策略组").font(.headline)
                Spacer()
                Button("测速全部节点") { core.trigger("probe", done: "正在测速…") }
                    .disabled(core.phase != .running || core.statusReadFailed || core.configuredNodes.isEmpty)
            }
            if let status = core.status, let groups = status.groups, !groups.isEmpty {
                ForEach(groups) { group in
                    VStack(alignment: .leading, spacing: 7) {
                        Text(group.name + " · " + group.typeLabel).font(.callout.weight(.semibold))
                        if group.type == "select" {
                            Picker("使用", selection: Binding(
                                get: { group.selected ?? group.now },
                                set: { core.selectInGroup(group.name, member: $0) }
                            )) {
                                ForEach(group.members, id: \.self) { Text(core.memberLabel($0)).tag($0) }
                            }
                            .disabled(core.phase != .running || core.statusReadFailed)
                        } else {
                            Text("正在使用 " + core.memberLabel(group.now))
                                .font(.callout).monospacedDigit()
                            groupMembers(group.members)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .hopPanel()
                }
            } else if let groups = core.configuredProfile?.groups, !groups.isEmpty {
                ForEach(groups) { group in
                    VStack(alignment: .leading, spacing: 7) {
                        Text(group.name).font(.callout.weight(.semibold))
                        if let selected = group.selected {
                            Text("配置成员 " + selected).font(.callout).foregroundStyle(.secondary)
                        }
                        groupMembers(group.members)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .hopPanel()
                }
            } else {
                Text(core.configuredProfile == nil ? "正在读取已保存的策略。" : "当前配置没有策略组。")
                    .foregroundStyle(.secondary)
                    .font(.callout)
            }

            if let sets = core.status?.ruleSets, !sets.isEmpty {
                HStack {
                    Text("规则集").font(.headline)
                    Spacer()
                    Button("更新规则集") { core.trigger("rulesets/refresh", done: "正在更新规则集…") }
                        .disabled(core.phase != .running || core.statusReadFailed)
                }
                ForEach(sets) { item in
                    sourceRow(item.name, detail: "\(item.entries) 条", updated: item.updated, error: item.error)
                }
            } else if let names = core.configuredProfile?.ruleSets, !names.isEmpty {
                Text("已配置的规则集").font(.headline)
                ForEach(names, id: \.self) { name in
                    Text(name).font(.callout)
                }
            }
        }
    }

    private func groupMembers(_ names: [String]) -> some View {
        DisclosureGroup("\(names.count) 个成员") {
            Text(names.map { core.memberLabel($0) }.joined(separator: "，"))
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.callout)
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

    private var configuration: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HopPageHeading(title: "设置", detail: "接入方式、监听端口和内核配置。")
                accessSettings
                coreSettings
                AdvancedSettingsPanel(core: core, draft: $advancedDraft) { showsConfigurationEditor = true }
            }
            .padding(.bottom, 12)
        }
    }

    private var accessSettings: some View {
        VStack(alignment: .leading, spacing: 9) {
            Label("macOS 接入", systemImage: "network").font(.headline)
            switch core.phase {
            case .stopped:
                Text("启动代理后可以接管系统代理或开启 TUN。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                if let profile = core.configuredProfile {
                    let enabled = [
                        profile.systemProxy == true ? "系统代理" : nil,
                        profile.tunEnabled == true ? "TUN" : nil
                    ].compactMap { $0 }
                    Text(enabled.isEmpty ? "启动后手动接入" : "启动时开启 " + enabled.joined(separator: "、"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Button("启动代理", action: core.toggle)
                    .buttonStyle(HopPrimaryButton())
                    .disabled(core.saving)
            case .starting, .stopping:
                ProgressView(core.phase.rawValue).controlSize(.small)
            case .running:
                if let status = core.status {
                    Toggle("系统代理", isOn: Binding(
                        get: { status.systemProxy?.enabled ?? false }, set: core.setSystemProxy))
                        .disabled(status.systemProxy?.supported != true || core.statusReadFailed)
                    Toggle("TUN 增强模式", isOn: Binding(
                        get: { status.tun?.enabled ?? false }, set: core.setTUN))
                        .disabled(status.tun?.supported != true || core.statusReadFailed || core.changingTUN)
                    HStack {
                        Button(status.tun?.service == true ? "移除 TUN 助手" : "安装 TUN 助手") {
                            core.setTUNService(status.tun?.service != true)
                        }
                        .disabled(status.tun?.supported != true || core.statusReadFailed || core.changingTUN)
                        if let device = status.tun?.device {
                            Text("设备 " + device).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    if let error = status.systemProxy?.error {
                        Label("系统代理 · " + error, systemImage: "exclamationmark.circle")
                            .font(.callout).foregroundStyle(.orange)
                    }
                    if let error = status.tun?.error {
                        Label("TUN · " + error, systemImage: "exclamationmark.circle")
                            .font(.callout).foregroundStyle(.orange)
                    }
                } else if core.statusReadFailed {
                    Text("暂时无法读取接入状态。").font(.callout).foregroundStyle(.orange)
                } else {
                    ProgressView("正在读取接入状态…").controlSize(.small)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .hopPanel()
    }

    private var coreSettings: some View {
        let profile = core.configuredProfile
        let backend = [profile?.backend, profile?.backendVersion].compactMap { $0 }.joined(separator: " ")
        return VStack(alignment: .leading, spacing: 9) {
            Label("监听与内核", systemImage: "cpu").font(.headline)
            if let profile {
                HStack(spacing: 18) {
                    LabeledContent("SOCKS5", value: portLabel(profile.socksPort, running: core.endpoint?.socks, applied: core.appliedPorts?.socks))
                    LabeledContent("HTTP", value: portLabel(profile.httpPort, running: core.endpoint?.http, applied: core.appliedPorts?.http))
                }
                .monospacedDigit()
                if !backend.isEmpty { LabeledContent("内核后端", value: backend) }
                if let applied = core.status?.reloaded {
                    LabeledContent("配置应用时间", value: Date(timeIntervalSince1970: applied / 1000)
                        .formatted(date: .abbreviated, time: .shortened))
                }
                if let notice = core.configurationNotice, core.phase == .running {
                    Label(notice, systemImage: "clock").foregroundStyle(.orange)
                }
            } else if !core.profileReadFailed {
                Text("正在读取已保存的配置。").foregroundStyle(.secondary)
            }
            if core.profileReadFailed {
                Label("读取已保存的配置失败", systemImage: "exclamationmark.circle")
                    .foregroundStyle(.orange)
            }
        }
        .font(.callout)
        .frame(maxWidth: .infinity, alignment: .leading)
        .hopPanel()
    }

    private func portLabel(_ configured: Int?, running: String?, applied: Int?) -> String {
        if let running {
            if let configured, let applied, configured != applied {
                let saved = configured == 0 ? "自动分配" : "\(configured)"
                return "\(running) · 已保存 \(saved)"
            }
            return running
        }
        guard let configured else { return "未读取" }
        return configured == 0 ? "启动时分配" : "\(configured)（已配置）"
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
                Button("还原草稿") { core.draft = core.saved }.disabled(core.saving || !core.changed)
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
            Text(core.message ?? "保存后尝试热加载。修改监听端口需重启代理。关闭会保留草稿。")
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .padding(20)
        .frame(width: 650, height: 395)
    }
}
