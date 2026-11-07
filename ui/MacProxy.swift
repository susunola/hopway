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
        Text("内核 · " + core.phase.rawValue)
        if core.phase == .running {
            Text("接入 · " + core.accessLabel)
            Text("出口 · " + core.reachabilityLabel)
        }
        Divider()
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
    @State private var showsRouteTester = false
    @State private var showsAutoRouting = false
    @State private var showsPolicyDetails = false
    @State private var page: DashboardPage = .overview
    @State private var showsLinkImport = false
    @State private var importLink = ""
    @State private var preview: CoreModel.ImportPreview?
    @State private var previewRequest = UUID()
    @State private var importError: String?
    @State private var previewing = false
    @State private var showsConfigurationEditor = false
    @State private var confirmsDiskVersion = false
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
                            showPolicies: { page = .policies },
                            showUsage: { page = .usage },
                            showSubscriptions: { page = .subscriptions },
                            importLink: { showsLinkImport = true }
                        )
                    case .nodes:
                        NodeDashboard(core: core) { showsLinkImport = true }
                    case .policies:
                        ScrollView {
                            VStack(alignment: .leading, spacing: HopAppearance.pageSpacing) {
                                HStack {
                                    HopPageHeading(title: "策略", detail: "选择出站方式，检查规则和策略组")
                                    Spacer()
                                    Button("检查路由…") { showsRouteTester = true }
                                        .fixedSize()
                                        .disabled(core.phase != .running || core.statusReadFailed)
                                }
                                routingPresets
                                policySummary
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
                    HStack(spacing: 12) {
                        Label(message, systemImage: "info.circle")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        if core.refreshing {
                            Button("取消刷新", action: core.cancelRefresh)
                        } else if core.tunProgress == nil && !core.statusReadFailed {
                            Button(action: core.dismissMessage) {
                                Image(systemName: "xmark")
                            }
                            .buttonStyle(.borderless)
                            .accessibilityLabel("关闭提示")
                        }
                    }
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
        .sheet(isPresented: $showsLinkImport, onDismiss: {
            importLink = ""
            preview = nil
            previewRequest = UUID()
            importError = nil
        }) {
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
                        .font(.callout).foregroundStyle(HopAppearance.warning)
                }
                HStack {
                    Spacer()
                    Button("取消") { showsLinkImport = false }.keyboardShortcut(.cancelAction)
                    Button(previewing ? "正在预览…" : preview == nil ? "预览" : "确认导入") {
                        if let preview {
                            if core.confirmImport(preview) {
                                showsLinkImport = false
                            } else {
                                self.preview = nil
                                importError = core.message
                            }
                        } else {
                            let link = importLink
                            let request = UUID()
                            previewRequest = request
                            previewing = true
                            importError = nil
                            Task {
                                defer { previewing = false }
                                do {
                                    let result = try await core.previewImport(link)
                                    if previewRequest == request && showsLinkImport { preview = result }
                                } catch {
                                    if previewRequest == request && showsLinkImport { importError = error.localizedDescription }
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
            .onChange(of: importLink) { _, _ in
                preview = nil
                previewRequest = UUID()
                importError = nil
            }
        }
        .sheet(isPresented: $showsConfigurationEditor) {
            configurationEditor
        }
        .sheet(isPresented: $showsRouteTester) { routeTester }
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
                .accessibilityLabel(destination.title)
                .accessibilityAddTraits(page == destination ? .isSelected : [])
            }

            Spacer()
            Divider().padding(.bottom, 8)
            HStack(spacing: 7) {
                Circle()
                    .fill(core.statusReadFailed ? HopAppearance.warning :
                          core.phase == .running ? HopAppearance.accent : Color.secondary)
                    .frame(width: 7, height: 7)
                Text(core.statusReadFailed ? "状态更新失败" : core.phase.rawValue)
                    .font(.caption)
                    .foregroundStyle(core.statusReadFailed ? HopAppearance.warning : .secondary)
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
                Label("检查路由", systemImage: "arrow.triangle.branch").font(.headline)
                Spacer()
                Button("关闭") { showsRouteTester = false }.keyboardShortcut(.cancelAction)
            }
            HStack {
                TextField("域名或 IP", text: $routeHost)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel("待测试地址")
                Button(testingRoute ? "正在检查…" : "检查") {
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
                .buttonStyle(HopPrimaryButton())
                .keyboardShortcut(.defaultAction)
                .disabled(core.phase != .running || routeHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || testingRoute)
            }
            if let routeResult { Text(routeResult).textSelection(.enabled) }
        }
        .padding(22)
        .frame(width: 460)
        .onChange(of: routeHost) { _, _ in routeResult = nil }
        .onChange(of: core.status?.policy) { _, _ in routeResult = nil }
        .onChange(of: core.status?.reloaded) { _, _ in routeResult = nil }
        .onChange(of: core.phase) { _, _ in routeResult = nil }
    }

    private enum RoutingPreset: String, CaseIterable, Identifiable {
        case fastest, rule, auto, direct
        var id: Self { self }

        var icon: String {
            switch self {
            case .fastest: "bolt"
            case .rule: "arrow.triangle.branch"
            case .auto: "globe"
            case .direct: "arrow.right"
            }
        }

        var detail: String {
            switch self {
            case .fastest: "从已验证的可用节点中选延迟最低的。"
            case .rule: "按已有规则分流，未命中时直连。"
            case .auto: "固定地区，在节点和服务商之间自动切换。"
            case .direct: "新连接直接访问目标。"
            }
        }
    }

    private var routingPresets: some View {
        let mode = core.status?.policy.mode ?? core.configuredProfile?.mode
        let ready = core.phase == .stopped ? !core.profileReadFailed && core.configuredProfile != nil :
            core.phase == .running && !core.statusReadFailed && core.status != nil
        return VStack(alignment: .leading, spacing: 10) {
            Text("策略模板").font(.headline)
            LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible())], spacing: 10) {
                ForEach(RoutingPreset.allCases) { preset in
                    presetCard(preset, selected: preset.rawValue == mode, ready: ready)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .hopPanel()
    }

    private func presetCard(_ preset: RoutingPreset, selected: Bool, ready: Bool) -> some View {
        let title = Policy.label(preset.rawValue)
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Label(title, systemImage: preset.icon).font(.callout.weight(.semibold))
                Spacer(minLength: 8)
                if preset == .auto {
                    Button(selected ? "调整…" : "配置…") { showsAutoRouting = true }
                        .accessibilityLabel("配置按地区自动")
                        .disabled(core.phase != .running || !ready)
                        .help(core.phase == .stopped ? "启动代理后可配置地区与服务商。" : "设置地区与首选服务商")
                        .sheet(isPresented: $showsAutoRouting) { AutoRoutingSheet(core: core) }
                } else if !selected {
                    Button("使用") { core.selectRoutingPreset(preset.rawValue) }
                        .accessibilityLabel("使用" + title)
                        .disabled(!ready || core.saving || core.updatingPolicy)
                }
                if selected {
                    Label(core.phase == .stopped ? "启动时使用" : "已启用", systemImage: "checkmark.circle.fill")
                        .font(.caption)
                        .foregroundStyle(HopAppearance.accent)
                        .fixedSize()
                }
            }
            .frame(minHeight: 25)
            Text(preset.detail).font(.caption).foregroundStyle(.secondary).lineLimit(2)
        }
        .frame(maxWidth: .infinity, minHeight: 49, alignment: .topLeading)
        .padding(10)
        .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(selected ? HopAppearance.accent.opacity(0.45) : .clear))
    }

    private var policySummary: some View {
        let profile = core.configuredProfile
        let status = core.status
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Label(status == nil ? "启动出站" : "当前出站", systemImage: "point.3.connected.trianglepath.dotted")
                    .font(.headline)
                    .fixedSize()
                if let mode = status?.policy.mode ?? profile?.mode {
                    let outbound: String? = if mode == "auto" || mode == "fastest" {
                        status.map { $0.auto?.node ?? "等待可用节点" }
                    } else if mode == "global" {
                        status?.policy.selected ?? profile?.selected
                    } else {
                        nil
                    }
                    Text([Policy.label(mode), outbound].compactMap { $0 }.joined(separator: " · "))
                        .font(.callout.weight(.medium))
                        .lineLimit(1)
                        .help(outbound ?? Policy.label(mode))
                }
                Spacer(minLength: 10)
                if let profile {
                    Text("\(profile.ruleCount ?? 0) 条规则 · \(profile.groups?.count ?? 0) 个策略组 · \(profile.ruleSets?.count ?? 0) 个规则集")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .fixedSize()
                    if !(profile.groups ?? []).isEmpty || !(profile.ruleSets ?? []).isEmpty {
                        Button("策略详情…") { showsPolicyDetails = true }
                            .fixedSize()
                            .sheet(isPresented: $showsPolicyDetails) { policyDetails }
                    }
                }
            }
            if let defaults = status?.ruleDefaults, status?.policy.mode == "rule" {
                HopDisclosure("规则命中统计") {
                    Text("兜底规则 \(defaults.explicitMatch.formatted()) 次 · 未命中直连 \(defaults.implicit.formatted()) 次")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
                .font(.callout)
            }
            if core.profileReadFailed {
                Label("配置读取失败，请在设置中检查已保存的配置。", systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(HopAppearance.warning)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .hopPanel()
    }

    private var policyDetails: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                HopPageHeading(title: "策略详情", detail: "手动组可以换成员，自动组由内核选路。")
                Spacer(minLength: 10)
                Button("完成") { showsPolicyDetails = false }
                    .keyboardShortcut(.cancelAction)
            }
            Divider()
            ScrollView { policies }
        }
        .padding(22)
        .frame(width: 560, height: 430)
    }

    private var policies: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let groups = core.status?.groups, !groups.isEmpty {
                let manual = groups.filter { $0.type == "select" }
                let automatic = groups.filter { $0.type != "select" }
                if !manual.isEmpty {
                    Text("手动切换").font(.headline)
                    ForEach(manual) { group in
                        if group.id != manual.first?.id { Divider() }
                        manualGroup(group)
                    }
                }
                if !automatic.isEmpty {
                    if !manual.isEmpty { Divider() }
                    HopDisclosure("自动与备用分组（\(automatic.count)）") {
                        ForEach(automatic) { group in
                            inspectGroup(group.name, current: group.now, members: group.members)
                        }
                    }
                    .font(.callout)
                }
            } else if let groups = core.configuredProfile?.groups, !groups.isEmpty {
                Text("启动代理后可在此切换手动组成员。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                HopDisclosure("已保存的分组（\(groups.count)）") {
                    ForEach(groups) { group in
                        inspectGroup(group.name, current: group.selected, members: group.members)
                    }
                }
                .font(.callout)
            } else {
                Text(core.configuredProfile == nil ? "正在读取已保存的策略。" : "当前配置没有策略组。")
                    .foregroundStyle(.secondary)
                    .font(.callout)
            }

            if let sets = core.status?.ruleSets, !sets.isEmpty {
                Divider()
                HopDisclosure("规则集（\(sets.count)）") {
                    VStack(alignment: .leading, spacing: 7) {
                        Button("更新规则集") { core.trigger("rulesets/refresh", done: "正在更新规则集…") }
                            .disabled(core.phase != .running || core.statusReadFailed || core.refreshing)
                        ForEach(sets) { item in
                            sourceRow(item.name, detail: "\(item.entries) 条", updated: item.updated, error: item.error)
                        }
                    }
                }
            } else if let names = core.configuredProfile?.ruleSets, !names.isEmpty {
                Divider()
                HopDisclosure("规则集（\(names.count)）") {
                    ForEach(names, id: \.self) { name in
                        Text(name).font(.callout)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func manualGroup(_ group: ProxyStatus.PolicyGroup) -> some View {
        let selected = group.selected ?? group.now
        return HStack(spacing: 12) {
            Text(group.name).font(.callout.weight(.medium)).lineLimit(1).help(group.name)
                .frame(maxWidth: .infinity, alignment: .leading)
            HopSelectionMenu(title: "切换 \(group.name)", value: core.memberLabel(selected), labelWidth: 153,
                             selection: Binding(get: { selected }, set: { core.selectInGroup(group.name, member: $0) })) {
                ForEach(group.members, id: \.self) { Text(core.memberLabel($0)).tag($0) }
            }
            .disabled(core.phase != .running || core.statusReadFailed)
        }
    }

    private func inspectGroup(_ name: String, current: String?, members: [String]) -> some View {
        HopDisclosure(name) {
            if let current, !current.isEmpty {
                Text((core.phase == .running ? "组内当前 · " : "默认成员 · ") + core.memberLabel(current))
            }
            Text("\(members.count) 个成员")
            Text(members.map { core.memberLabel($0) }.joined(separator: "，"))
                .textSelection(.enabled)
        }
        .font(.callout)
    }

    private func sourceRow(_ name: String, detail: String, updated: Double?, error: String?) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(name)
            Text(detail).foregroundStyle(.secondary).monospacedDigit()
            Spacer()
            if let error {
                Text(error).foregroundStyle(HopAppearance.warning).lineLimit(1).help(error)
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
            VStack(alignment: .leading, spacing: HopAppearance.pageSpacing) {
                HStack {
                    HopPageHeading(title: "设置", detail: "启动偏好、接入端口和高级配置")
                    Spacer()
                    Button(action: core.exportDiagnostics) {
                        Label(core.exportingDiagnostics ? "正在生成…" : "导出诊断…", systemImage: "doc.text.magnifyingglass")
                    }
                    .fixedSize()
                    .disabled(core.exportingDiagnostics)
                }
                AdvancedSettingsPanel(core: core, draft: $advancedDraft) { showsConfigurationEditor = true }
                configurationFeedback
            }
            .padding(.bottom, 12)
        }
    }

    @ViewBuilder
    private var configurationFeedback: some View {
        if let notice = core.configurationNotice, core.phase == .running {
            Label(notice, systemImage: "clock")
                .font(.callout)
                .foregroundStyle(HopAppearance.warning)
        }
        if core.profileReadFailed || core.configurationConflict {
            HStack {
                Label(core.configurationConflict ? "磁盘配置已有新版本" : "无法读取已保存的配置",
                      systemImage: "exclamationmark.circle")
                    .foregroundStyle(HopAppearance.warning)
                Spacer()
                Button("重新读取配置") {
                    if core.changed { showsConfigurationEditor = true }
                    else { core.readDiskConfiguration() }
                }
                .fixedSize()
                .disabled(core.saving)
            }
            .font(.callout)
            .hopPanel()
        }
    }

    private func requestDiskVersion() {
        if core.changed {
            confirmsDiskVersion = true
        } else {
            core.readDiskConfiguration()
        }
    }

    private var configurationEditor: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("高级配置").font(.headline)
                if core.changed { Text("未保存").font(.caption).foregroundStyle(HopAppearance.warning) }
                Spacer()
                Button("关闭") { showsConfigurationEditor = false }.keyboardShortcut(.cancelAction)
            }
            HStack {
                Button("打开 JSON", action: core.importDraft).disabled(core.saving)
                if core.configurationConflict || core.changed {
                    Button("读取磁盘版本", action: requestDiskVersion).disabled(core.saving)
                }
                Menu("插入节点模板") {
                    ForEach(["socks5", "http", "https", "trojan", "shadowsocks", "anytls", "vless", "vmess"], id: \.self) { type in
                        Button(type) { core.insertTemplate(type) }
                    }
                }.disabled(core.saving)
                Spacer()
                Button("还原草稿") { core.draft = core.saved }.disabled(core.saving || !core.changed)
                Button(core.saving ? "正在校验…" : "校验并保存", action: core.save)
                    .buttonStyle(HopPrimaryButton())
                    .disabled(core.saving || !core.changed || core.configurationConflict)
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
        .confirmationDialog("读取磁盘配置", isPresented: $confirmsDiskVersion, titleVisibility: .visible) {
            Button("复制草稿并读取") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(core.draft, forType: .string)
                core.readDiskConfiguration()
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("可以先复制当前草稿，再读取并比较磁盘版本。")
        }
    }
}
