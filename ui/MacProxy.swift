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
    @AppStorage(HopLanguage.key) private var language = HopLanguage.chinese

    var body: some Scene {
        Window("HopWay", id: "dashboard") {
            Dashboard(core: core, language: $language)
                .environment(\.locale, Locale(identifier: language.rawValue))
        }
        .defaultSize(width: 1040, height: 690)

        MenuBarExtra("HopWay", systemImage: core.phase == .running ? "point.3.connected.trianglepath.dotted" : "point.3.filled.connected.trianglepath.dotted") {
            StatusMenu(core: core)
                .environment(\.locale, Locale(identifier: language.rawValue))
        }
    }
}

private struct StatusMenu: View {
    @Environment(\.locale) private var interfaceLocale
    @Environment(\.openWindow) private var openWindow
    @ObservedObject var core: CoreModel

    var body: some View {
        let _ = interfaceLocale
        Text(L("内核 · ") + L(core.phase.rawValue))
        if core.phase == .running {
            Text(L("接入 · ") + core.accessLabel)
            Text(L("出口 · ") + core.reachabilityLabel)
        }
        Divider()
        Button(core.phase == .running ? L("停止代理") : L("启动代理"), action: core.toggle)
            .disabled(core.phase == .starting || core.phase == .stopping || core.saving)
        Button(L("打开控制台")) {
            openWindow(id: "dashboard")
            NSApp.activate(ignoringOtherApps: true)
        }
        Divider()
        Button(L("退出 HopWay")) { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}

private enum DashboardPage: String, CaseIterable {
    case overview, nodes, policies, subscriptions, usage, connections, settings

    var title: String {
        switch self {
        case .overview: L("概览")
        case .nodes: L("节点")
        case .subscriptions: L("订阅")
        case .usage: L("用量")
        case .policies: L("策略")
        case .connections: L("连接")
        case .settings: L("设置")
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
    @Environment(\.locale) private var interfaceLocale
    @ObservedObject var core: CoreModel
    @Binding var language: HopLanguage
    @State private var routeHost = ""
    @State private var routeResult: String?
    @State private var testingRoute = false
    @State private var showsRouteTester = false
    @State private var showsAutoRouting = false
    @State private var showsFallbackRouting = false
    @State private var editsCustomRules = false
    @State private var showsPolicyDetails = false
    @State private var editingGroup: ProfileInspection.Group?
    @State private var showsNewPolicyGroup = false
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
    @State private var hoveredPreset: RoutingPreset?
    @State private var hoveredPage: DashboardPage?

    var body: some View {
        let _ = interfaceLocale
        HStack(spacing: 0) {
            sidebar
            Divider()
            VStack(spacing: 0) {
                Group {
                    switch page {
                    case .overview:
                        OverviewDashboard(
                            core: core,
                            hasAdvancedEdits: advancedDraft?.changed == true,
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
                                    HopPageHeading(title: L("策略"), detail: L("选择出站方式，检查规则和策略组"))
                                    Spacer()
                                    Button(L("检查路由…")) { showsRouteTester = true }
                                        .fixedSize()
                                        .disabled(core.phase != .running || core.statusReadFailed)
                                }
                                routingPresets
                                policySummary
                                policyGroups
                            }
                            .padding(.bottom, 12)
                        }
                        .scrollBounceBehavior(.basedOnSize)
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
                .padding(.top, page == .settings ? 20 : 26)
                .padding(.bottom, page == .overview ? 0 : page == .settings ? 18 : 26)
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
                            Button(L("取消刷新"), action: core.cancelRefresh)
                        } else if core.tunProgress == nil && !core.statusReadFailed {
                            Button(action: core.dismissMessage) {
                                Image(systemName: "xmark")
                            }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(L("关闭提示"))
                        }
                    }
                    .padding(.horizontal, 26)
                    .padding(.vertical, 11)
                }
            }
            .background(HopAppearance.pageSurface)
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
                Text(L("导入链接")).font(.headline)
                Text(L("粘贴 Shadowrocket 或 Clash 的一键导入链接，也可直接填订阅地址。"))
                    .foregroundStyle(.secondary)
                TextField(L("订阅或节点链接"), text: $importLink)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                if let preview {
                    Text(L("识别到 <1> 个节点 · 跳过 <2> 条", preview.added, preview.skipped))
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
                    Button(L("取消")) { showsLinkImport = false }.keyboardShortcut(.cancelAction)
                    Button(previewing ? L("正在预览…") : preview == nil ? L("预览") : L("确认导入")) {
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
        .sheet(isPresented: $showsConfigurationEditor, onDismiss: { editsCustomRules = false }) {
            configurationEditor
        }
        .sheet(isPresented: $showsFallbackRouting) {
            fallbackRouting
        }
        .sheet(isPresented: $showsRouteTester) { routeTester }
        .sheet(isPresented: $showsNewPolicyGroup) { NewPolicyGroupSheet(core: core) }
        .sheet(item: $editingGroup) { group in
            if let ids = core.configuredProfile?.outboundIds {
                PolicyGroupEditor(core: core, group: group, ids: ids)
            }
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
                        Text(destination.title).lineLimit(1).minimumScaleFactor(0.82)
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
                    .background {
                        if page == destination {
                            RoundedRectangle(cornerRadius: 9).fill(HopAppearance.accent.opacity(0.11))
                        } else if hoveredPage == destination {
                            RoundedRectangle(cornerRadius: 9).fill(HopAppearance.accent.opacity(0.06))
                        }
                    }
                    .overlay(alignment: .leading) {
                        if page == destination {
                            Capsule().fill(HopAppearance.accent).frame(width: 2, height: 16)
                                .padding(.leading, 3)
                                .accessibilityHidden(true)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .onHover { hovered in
                    if hovered { hoveredPage = destination }
                    else if hoveredPage == destination { hoveredPage = nil }
                }
                .accessibilityLabel(destination.title)
                .accessibilityAddTraits(page == destination ? .isSelected : [])
            }

            Spacer()
            HStack(spacing: 7) {
                Circle()
                    .fill(core.statusReadFailed ? HopAppearance.warning :
                          core.phase == .running ? HopAppearance.accent : Color.secondary)
                    .frame(width: 7, height: 7)
                Text(core.statusReadFailed ? L("状态更新失败") : L(core.phase.rawValue))
                    .font(.caption)
                    .foregroundStyle(core.statusReadFailed ? HopAppearance.warning : .secondary)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(HopAppearance.insetSurface, in: RoundedRectangle(cornerRadius: 9))
        }
        .padding(14)
        .frame(width: 172)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var routeTester: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label(L("检查路由"), systemImage: "arrow.triangle.branch").font(.headline)
                Spacer()
                Button(L("关闭")) { showsRouteTester = false }.keyboardShortcut(.cancelAction)
            }
            HStack {
                TextField(L("域名或 IP"), text: $routeHost)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel(L("待测试地址"))
                Button(testingRoute ? L("正在检查…") : L("检查")) {
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
                            routeResult = result.rule + " · " + ((result.path ?? []) + [result.outbound]).map(core.groupLabel).joined(separator: " → ")
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
        case fastest, rule, auto, direct, custom, fallback
        var id: Self { self }

        var title: String {
            switch self {
            case .custom: L("自定义")
            case .fallback: L("按顺序备用")
            default: Policy.label(rawValue)
            }
        }

        var icon: String {
            switch self {
            case .fastest: "bolt"
            case .rule: "arrow.triangle.branch"
            case .auto: "globe"
            case .direct: "arrow.right"
            case .custom: "slider.horizontal.3"
            case .fallback: "arrow.triangle.2.circlepath"
            }
        }

        var detail: String {
            switch self {
            case .fastest: L("从已验证的可用节点中选延迟最低的。")
            case .rule: L("按已有规则分流，未命中时直连。")
            case .auto: L("固定地区，在节点和服务商之间自动切换。")
            case .direct: L("新连接直接访问目标。")
            case .custom: L("按域名、IP 或应用编写分流规则。")
            case .fallback: L("优先走组内主线路，故障时按顺序切换。")
            }
        }
    }

    private var routingPresets: some View {
        let mode = core.status?.policy.mode ?? core.configuredProfile?.mode
        let outbound = core.status?.policy.selected ?? core.configuredProfile?.selected
        let usingFallback = mode == "global" && fallbackGroups.contains { $0.name == outbound }
        let ready = core.phase == .stopped ? !core.profileReadFailed && core.configuredProfile != nil :
            core.phase == .running && !core.statusReadFailed && core.status != nil
        return VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Label(L("策略模板"), systemImage: "square.grid.2x2").labelStyle(HopSectionLabelStyle())
                Text(L("双击使用或配置")).font(.caption).foregroundStyle(.secondary)
            }
            LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible())], spacing: 10) {
                ForEach(RoutingPreset.allCases) { preset in
                    presetCard(preset, selected: preset == .fallback ? usingFallback : preset.rawValue == mode, ready: ready)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .hopPanel()
    }

    private func presetCard(_ preset: RoutingPreset, selected: Bool, ready: Bool) -> some View {
        let title = preset.title
        let available = switch preset {
        case .custom: true
        case .auto: ready && core.phase == .running
        case .fallback: ready
        default: ready && !selected
        }
        let canActivate = available && !core.saving && !core.updatingPolicy
        let activate = {
            guard canActivate else { return }
            switch preset {
            case .auto: showsAutoRouting = true
            case .custom:
                editsCustomRules = true
                showsConfigurationEditor = true
            case .fallback: showsFallbackRouting = true
            default: core.selectRoutingPreset(preset.rawValue)
            }
        }
        return HStack(alignment: .center, spacing: 11) {
            Image(systemName: preset.icon)
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(selected ? HopAppearance.accent : .secondary)
                .frame(width: 31, height: 31)
                .background(selected ? HopAppearance.accent.opacity(0.13) : HopAppearance.insetSurface,
                            in: RoundedRectangle(cornerRadius: 8))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.callout.weight(.semibold))
                Text(preset.detail).font(.caption).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer(minLength: 6)
            if selected {
                Label(core.phase == .stopped ? L("启动时使用") : L("已启用"), systemImage: "checkmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(HopAppearance.accent)
                    .fixedSize()
            }
            if preset == .auto {
                Button(selected ? L("调整…") : L("配置…"), action: activate)
                    .accessibilityLabel(L("配置按地区自动"))
                    .disabled(!canActivate)
                    .help(core.phase == .stopped ? L("启动代理后可配置地区与服务商。") : L("设置地区与首选服务商"))
                    .sheet(isPresented: $showsAutoRouting) { AutoRoutingSheet(core: core) }
            } else if preset == .custom || preset == .fallback {
                Button(preset == .custom ? L("编辑…") : selected ? L("调整…") : L("配置…"), action: activate)
                    .accessibilityLabel(preset == .custom ? L("编辑自定义规则") : L("配置按顺序备用"))
                    .disabled(!canActivate)
            } else if !selected {
                Button(L("使用"), action: activate)
                    .accessibilityLabel(L("使用") + title)
                    .disabled(!canActivate)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 46, alignment: .leading)
        .padding(11)
        .background(
            selected ? HopAppearance.accent.opacity(0.09) : Color.primary.opacity(hoveredPreset == preset ? 0.055 : 0.02),
            in: RoundedRectangle(cornerRadius: 10)
        )
        .overlay(RoundedRectangle(cornerRadius: 10)
            .strokeBorder(selected ? HopAppearance.accent.opacity(0.44) : HopAppearance.panelBorder)
            .allowsHitTesting(false))
        .contentShape(Rectangle())
        .onHover { hovered in
            if hovered { hoveredPreset = preset }
            else if hoveredPreset == preset { hoveredPreset = nil }
        }
        .onTapGesture(count: 2, perform: activate)
    }

    private var fallbackGroups: [ProfileInspection.Group] {
        let groups = (core.configuredProfile?.groups ?? []).filter { $0.type == "fallback" }
        if core.phase == .running {
            let active = Set((core.status?.groups ?? []).filter { $0.type == "fallback" }.map(\.name))
            return groups.filter { active.contains($0.name) }
        }
        return groups
    }

    private var fallbackRouting: some View {
        FallbackRoutingSheet(
            groups: fallbackGroups,
            aliases: core.configuredProfile?.groupAliases ?? [:],
            selected: core.status?.policy.selected ?? core.configuredProfile?.selected,
            running: core.phase == .running,
            canApply: !core.saving && !core.updatingPolicy && !core.statusReadFailed
        ) { group in
            core.selectRoutingPreset("global", fallbackGroup: group)
        }
    }

    private var policySummary: some View {
        let profile = core.configuredProfile
        let status = core.status
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Label(status == nil ? L("启动出站") : L("当前出站"), systemImage: "point.3.connected.trianglepath.dotted")
                    .font(.headline)
                    .fixedSize()
                if let mode = status?.policy.mode ?? profile?.mode {
                    let outbound: String? = if mode == "auto" || mode == "fastest" {
                        status.map { $0.auto?.node ?? L("等待可用节点") }
                    } else if mode == "global" {
                        status?.policy.selected ?? profile?.selected
                    } else {
                        nil
                    }
                    let label = mode == "global" && fallbackGroups.contains { $0.name == outbound }
                        ? RoutingPreset.fallback.title : Policy.label(mode)
                    Text([label, outbound.map(core.groupLabel)].compactMap { $0 }.joined(separator: " · "))
                        .font(.callout.weight(.medium))
                        .lineLimit(1)
                        .help(outbound ?? Policy.label(mode))
                }
                Spacer(minLength: 10)
                if let profile {
                    Text(L("<1> 条规则 · <2> 个策略组 · <3> 个规则集", profile.ruleCount ?? 0, profile.groups?.count ?? 0, profile.ruleSets?.count ?? 0))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .fixedSize()
                    if !(profile.ruleSets ?? []).isEmpty {
                        Button(L("规则集…")) { showsPolicyDetails = true }
                            .fixedSize()
                            .sheet(isPresented: $showsPolicyDetails) { policyDetails }
                    }
                }
            }
            if let defaults = status?.ruleDefaults, status?.policy.mode == "rule" {
                HopDisclosure(L("规则命中统计")) {
                    Text(L("兜底规则 <1> 次 · 未命中直连 <2> 次", defaults.explicitMatch.formatted(), defaults.implicit.formatted()))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
                .font(.callout)
            }
            if core.profileReadFailed {
                Label(L("配置读取失败，请在设置中检查已保存的配置。"), systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(HopAppearance.warning)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .hopPanel()
    }

    private var policyGroups: some View {
        let groups = core.configuredProfile?.groups ?? []
        let liveGroups = core.status?.groups ?? []
        return VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 8) {
                Label(L("策略组"), systemImage: "point.3.connected.trianglepath.dotted").labelStyle(HopSectionLabelStyle())
                Text(L("线路归属与顺序")).font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button { showsNewPolicyGroup = true } label: {
                    Label(L("新增策略组…"), systemImage: "plus")
                }
                .disabled(!core.canEditPolicyGroups)
            }
            if groups.isEmpty {
                Text(core.configuredProfile == nil ? L("正在读取策略组…") : L("暂无策略组。可以新增一个，也可以从订阅导入。"))
                    .font(.callout).foregroundStyle(.secondary)
            }
            ForEach(groups) { group in
                Divider()
                policyGroupRow(group, live: liveGroups.first { $0.name == group.name })
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .hopPanel(verticalPadding: 12)
    }

    private func policyGroupRow(_ group: ProfileInspection.Group, live: ProxyStatus.PolicyGroup?) -> some View {
        let type = switch group.type {
        case "select": L("手动")
        case "url-test": L("自动测速")
        case "fallback": L("故障转移")
        default: group.type
        }
        let title = core.groupLabel(group.name)
        return HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.callout.weight(.medium)).lineLimit(1).help(group.name)
                Text(L("<1> · <2> 条线路", type, group.members.count))
                    .font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if let live, live.type == "select" {
                let selected = live.selected ?? live.now
                HopSelectionMenu(title: L("切换 ") + title, value: core.memberLabel(selected), labelWidth: 130,
                                 selection: Binding(get: { selected }, set: { core.selectInGroup(group.name, member: $0) })) {
                    ForEach(live.members, id: \.self) { Text(core.memberLabel($0)).tag($0) }
                }
                .disabled(core.statusReadFailed || core.saving)
            } else if let current = live?.now, !current.isEmpty {
                Text(core.memberLabel(current)).font(.caption).foregroundStyle(.secondary)
                    .lineLimit(1).frame(maxWidth: 160, alignment: .trailing)
                    .help(current)
            }
            Button(L("编辑…")) { editingGroup = group }
                .accessibilityLabel(L("编辑策略组 ") + title)
                .fixedSize()
                .disabled(core.saving || core.changed || core.configurationConflict ||
                          core.configuredProfile?.outboundIds?[group.name] == nil)
                .help(core.changed || core.configurationConflict ? L("请先处理高级配置中的草稿或冲突。") : L("修改名称、成员与线路顺序"))
        }
    }

    private var policyDetails: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                HopPageHeading(title: L("规则集"))
                Spacer(minLength: 10)
                Button(L("完成")) { showsPolicyDetails = false }
                    .keyboardShortcut(.cancelAction)
            }
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 9) {
                    if let sets = core.status?.ruleSets, !sets.isEmpty {
                        Button(L("更新规则集")) { core.trigger("rulesets/refresh", done: L("正在更新规则集…")) }
                            .disabled(core.phase != .running || core.statusReadFailed || core.refreshing)
                        ForEach(sets) { item in
                            sourceRow(item.name, detail: L("<1> 条", item.entries), updated: item.updated, error: item.error)
                        }
                    } else {
                        ForEach(core.configuredProfile?.ruleSets ?? [], id: \.self) { name in Text(name) }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(22)
        .frame(width: 560, height: 360)
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
                Text(L("尚未下载")).foregroundStyle(.secondary)
            }
        }
        .font(.callout)
    }

    private var configuration: some View {
        AdvancedSettingsPanel(core: core, draft: $advancedDraft, editJSON: { showsConfigurationEditor = true }) {
            HStack {
                HopPageHeading(title: L("设置"), detail: L("本机端口和高级配置"))
                Spacer()
                Button(action: core.exportDiagnostics) {
                    Label(core.exportingDiagnostics ? L("正在生成…") : L("导出诊断…"), systemImage: "doc.text.magnifyingglass")
                }
                .fixedSize()
                .disabled(core.exportingDiagnostics)
            }
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Label(L("界面语言"), systemImage: "globe").labelStyle(HopSectionLabelStyle())
                    Text(L("选择 HopWay 的显示语言。")).font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                Picker(L("界面语言"), selection: $language) {
                    ForEach(HopLanguage.allCases, id: \.self) { option in
                        Text(option.title).tag(option)
                    }
                }
                .labelsHidden()
                .pickerStyle(.segmented)
                .fixedSize()
            }
            .hopPanel(verticalPadding: 12)
        } feedback: {
            configurationFeedback
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
                Label(core.configurationConflict ? L("磁盘配置已有新版本") : L("无法读取已保存的配置"),
                      systemImage: "exclamationmark.circle")
                    .foregroundStyle(HopAppearance.warning)
                Spacer()
                Button(L("重新读取配置")) {
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
                Text(editsCustomRules ? L("自定义规则") : L("高级配置")).font(.headline)
                if core.changed { Text(L("未保存")).font(.caption).foregroundStyle(HopAppearance.warning) }
                Spacer()
                Button(L("关闭")) { showsConfigurationEditor = false }.keyboardShortcut(.cancelAction)
            }
            HStack {
                Button(L("打开 JSON"), action: core.importDraft).disabled(core.saving)
                if core.configurationConflict || core.changed {
                    Button(L("读取磁盘版本"), action: requestDiskVersion).disabled(core.saving)
                }
                Menu(L("插入节点模板")) {
                    ForEach(["socks5", "http", "https", "trojan", "shadowsocks", "anytls", "vless", "vmess"], id: \.self) { type in
                        Button(type) { core.insertTemplate(type) }
                    }
                }.disabled(core.saving)
                Spacer()
                Button(L("还原草稿")) { core.draft = core.saved }.disabled(core.saving || !core.changed)
                Button(core.saving ? L("正在校验…") : L("校验并保存"), action: core.save)
                    .buttonStyle(HopPrimaryButton())
                    .disabled(core.saving || !core.changed || core.configurationConflict)
            }
            if editsCustomRules {
                Text(L("编辑 rules 数组，按顺序匹配。保存后选用「按规则」即可应用分流。"))
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            TextEditor(text: $core.draft)
                .disabled(core.saving)
                .font(.system(.body, design: .monospaced))
                .autocorrectionDisabled()
                .padding(6)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(.quaternary))
                .accessibilityLabel(L("JSON 配置编辑器"))
            Text(core.message ?? L("保存后尝试热加载。修改监听端口需重启代理。关闭会保留草稿。"))
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .padding(20)
        .frame(width: 650, height: 395)
        .confirmationDialog(L("读取磁盘配置"), isPresented: $confirmsDiskVersion, titleVisibility: .visible) {
            Button(L("复制草稿并读取")) {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(core.draft, forType: .string)
                core.readDiskConfiguration()
            }
            Button(L("取消"), role: .cancel) {}
        } message: {
            Text(L("可以先复制当前草稿，再读取并比较磁盘版本。"))
        }
    }
}


private struct FallbackRoutingSheet: View {
    @Environment(\.locale) private var interfaceLocale
    @Environment(\.dismiss) private var dismiss
    let groups: [ProfileInspection.Group]
    let aliases: [String: String]
    let running: Bool
    let canApply: Bool
    let apply: (String) -> Void
    @State private var selection: String

    init(groups: [ProfileInspection.Group], aliases: [String: String], selected: String?, running: Bool, canApply: Bool,
         apply: @escaping (String) -> Void) {
        self.groups = groups
        self.aliases = aliases
        self.running = running
        self.canApply = canApply
        self.apply = apply
        _selection = State(initialValue: groups.first { $0.name == selected }?.name ?? groups.first?.name ?? "")
    }

    var body: some View {
        let _ = interfaceLocale
        let group = groups.first { $0.name == selection }
        VStack(alignment: .leading, spacing: 14) {
            HopPageHeading(title: L("按顺序备用"), detail: L("优先使用组内排在最前的可用线路。"))
            if groups.isEmpty {
                Text(L("当前没有故障转移组。可导入带 fallback 组的 Clash 配置，或在高级配置的 groups 数组中添加。"))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                HopLabeledControl(title: L("故障转移组")) {
                    HopSelectionMenu(title: L("故障转移组"), value: group.map { aliases[$0.name] ?? $0.name } ?? L("请选择"),
                                     labelWidth: 270, selection: $selection) {
                        ForEach(groups) { item in Text(aliases[item.name] ?? item.name).tag(item.name) }
                    }
                }
                if let group {
                    Text(L("<1> 条线路 · 首选 <2>", group.members.count, group.members.first.map { aliases[$0] ?? $0 } ?? "—"))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .help(group.members.joined(separator: " → "))
                }
            }
            HStack {
                Spacer()
                Button(groups.isEmpty ? L("完成") : L("取消")) { dismiss() }.keyboardShortcut(.cancelAction)
                if !groups.isEmpty {
                    Button(running ? L("启用备用") : L("下次启动使用")) {
                        guard let group, canApply else { return }
                        apply(group.name)
                        dismiss()
                    }
                    .buttonStyle(HopPrimaryButton())
                    .keyboardShortcut(.defaultAction)
                    .disabled(group == nil || !canApply)
                }
            }
        }
        .padding(24)
        .frame(width: 470)
    }
}
