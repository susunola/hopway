import SwiftUI

struct PolicyGroupEditor: View {
    @Environment(\.locale) private var interfaceLocale
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var core: CoreModel
    let group: ProfileInspection.Group
    let ids: [String: String]
    @State private var source: String
    @State private var members: [String]
    @State private var alias: String
    @State private var query = ""
    @State private var error: String?
    @State private var confirmsDeletion = false

    init(core: CoreModel, group: ProfileInspection.Group, ids: [String: String]) {
        self.core = core
        self.group = group
        self.ids = ids
        _source = State(initialValue: core.saved)
        _members = State(initialValue: group.members)
        _alias = State(initialValue: core.configuredProfile?.groupAliases?[group.name] ?? "")
    }

    private var document: [String: Any]? {
        (try? JSONSerialization.jsonObject(with: Data(source.utf8))) as? [String: Any]
    }

    private var customized: Bool {
        guard let id = ids[group.name] else { return false }
        return (document?["groupMembers"] as? [String: [String]])?[id] != nil
    }

    private var displayAlias: String {
        let text = alias.trimmingCharacters(in: .whitespacesAndNewlines)
        return text == group.name ? "" : text
    }

    private var aliasChanged: Bool {
        guard let id = ids[group.name] else { return false }
        let previous = (document?["groupAliases"] as? [String: String])?[id] ?? ""
        return previous != displayAlias
    }

    private var aliasError: String? {
        guard aliasChanged, !displayAlias.isEmpty else { return nil }
        if displayAlias.count > 80 { return L("显示名称最多 80 个字符。") }
        let groups = core.configuredProfile?.groups ?? []
        let otherNames = groups.filter { $0.name != group.name }.flatMap { [$0.name, core.groupLabel($0.name)] }
        let reserved = core.configuredNodes.map(\.name) + ["DIRECT", "REJECT", "SELECT", "AUTO"]
        if (otherNames + reserved).contains(where: { $0.caseInsensitiveCompare(displayAlias) == .orderedSame }) {
            return L("这个名称已在使用，请换一个。")
        }
        return nil
    }

    private var eligible: [String] {
        let included = Set(members)
        let candidates = core.configuredNodes.map(\.name) + group.members
        var seen = Set<String>()
        let filter = query.trimmingCharacters(in: .whitespacesAndNewlines)
        return candidates.filter {
            !included.contains($0) && ids[$0] != nil && seen.insert($0).inserted &&
            (filter.isEmpty || $0.localizedCaseInsensitiveContains(filter))
        }
    }

    private var canSave: Bool {
        !core.saving && !core.changed && !core.configurationConflict && core.saved == source &&
        core.configuredProfile?.outboundIds?[group.name] == ids[group.name]
    }

    private var listHeight: CGFloat {
        min(270, max(120, CGFloat(max(group.members.count, core.configuredNodes.count)) * 31 + 37))
    }

    var body: some View {
        let _ = interfaceLocale
        let local = core.configuredProfile?.localGroups?.contains(group.name) == true
        let deletionBlock = core.policyGroupDeletionBlock(group.name)
        VStack(alignment: .leading, spacing: 13) {
            HopPageHeading(title: L("编辑策略组"))
            HopLabeledControl(title: L("显示名称")) {
                TextField(L("显示名称"), text: $alias, prompt: Text(group.name))
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel(L("显示名称"))
                    .help(L("留空恢复原名。显示名称用于界面，已有规则继续引用原策略组。"))
            }
            Text(group.type == "fallback" ? L("按列表顺序选用线路，第一条为首选。") : L("添加或移除该策略组可用的线路。"))
                .font(.callout).foregroundStyle(.secondary)
            HStack(alignment: .top, spacing: 14) {
                memberList
                candidateList
            }
            if !canSave || error != nil || aliasError != nil {
                Text(error ?? aliasError ?? L("配置已更新，请关闭后重新打开此策略组。"))
                    .font(.callout).foregroundStyle(HopAppearance.warning)
            }
            HStack {
                if local {
                    Button(L("删除组…"), role: .destructive) { confirmsDeletion = true }
                        .disabled(!canSave || !core.canEditPolicyGroups || core.updatingPolicy ||
                                  deletionBlock != nil)
                }
                if let deletionBlock {
                    Text(deletionBlock).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }
                if customized {
                    Button(L("恢复原成员")) { save(restore: true) }.disabled(!canSave || aliasChanged)
                }
                Spacer()
                Button(L("取消")) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(L("保存更改")) { save(restore: false) }
                    .buttonStyle(HopPrimaryButton())
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSave || members.isEmpty || aliasError != nil || (!aliasChanged && members == group.members))
            }
        }
        .padding(22)
        .frame(width: 710)
        .alert(L("删除「<1>」？", core.groupLabel(group.name)), isPresented: $confirmsDeletion) {
            Button(L("删除策略组"), role: .destructive) {
                core.deletePolicyGroup(group.name, basedOn: source)
                dismiss()
            }
            Button(L("取消"), role: .cancel) {}
        }
    }

    private var memberList: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L("组内线路 · <1>", members.count)).font(.headline)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(members, id: \.self) { name in
                        HStack(spacing: 8) {
                            if let index = members.firstIndex(of: name) {
                                Text((index + 1).formatted()).font(.caption.monospacedDigit())
                                    .foregroundStyle(.secondary).frame(width: 20)
                                lineName(name)
                                iconButton("chevron.up", label: L("上移 ") + name) { members.swapAt(index, index - 1) }
                                    .disabled(index == 0)
                                iconButton("chevron.down", label: L("下移 ") + name) { members.swapAt(index, index + 1) }
                                    .disabled(index + 1 == members.count)
                                iconButton("minus.circle", label: L("移除 ") + name) { members.remove(at: index) }
                            }
                        }
                        .padding(.horizontal, 5).frame(minHeight: 29)
                    }
                }
            }
            .frame(height: listHeight)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var candidateList: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L("可添加线路")).font(.headline)
            HopSearchField(placeholder: L("搜索节点"), text: $query)
                .accessibilityLabel(L("搜索可添加线路"))
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(eligible, id: \.self) { name in
                        HStack(spacing: 8) {
                            lineName(name)
                            iconButton("plus.circle", label: L("添加 ") + name) { members.append(name) }
                        }
                        .padding(.horizontal, 5).frame(minHeight: 29)
                    }
                    if eligible.isEmpty {
                        Text(L("没有可添加的匹配线路")).font(.callout).foregroundStyle(.secondary)
                    }
                }
            }
            .frame(height: listHeight - 37)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func lineName(_ name: String) -> some View {
        Text(core.memberLabel(name)).font(.callout).lineLimit(1).help(name)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func iconButton(_ icon: String, label: String, action: @escaping () -> Void) -> some View {
        Button(action: action) { Image(systemName: icon).frame(width: 16, height: 18) }
            .buttonStyle(.borderless)
            .accessibilityLabel(label)
            .help(label)
    }

    private func save(restore: Bool) {
        guard canSave, var config = document, let id = ids[group.name] else { return }
        var overrides = config["groupMembers"] as? [String: [String]] ?? [:]
        if restore {
            overrides.removeValue(forKey: id)
        } else if members != group.members {
            let currentIDs = core.configuredProfile?.outboundIds
            let ordered = members.compactMap { name in
                ids[name] == currentIDs?[name] ? ids[name] : nil
            }
            guard !ordered.isEmpty, ordered.count == members.count else {
                error = L("线路列表已更新，请重新打开后再编辑。")
                return
            }
            overrides[id] = ordered
        }
        config["groupMembers"] = overrides.isEmpty ? nil : overrides
        if !restore, aliasChanged {
            guard aliasError == nil else { return }
            var aliases = config["groupAliases"] as? [String: String] ?? [:]
            aliases[id] = displayAlias.isEmpty ? nil : displayAlias
            config["groupAliases"] = aliases.isEmpty ? nil : aliases
        }
        do {
            let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
            core.saveAdvanced(String(decoding: data, as: UTF8.self), basedOn: source, activation: nil)
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}


struct NewPolicyGroupSheet: View {
    @Environment(\.locale) private var interfaceLocale
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var core: CoreModel
    @State private var name = ""
    @State private var type = "select"
    @State private var members: [String] = []
    @State private var query = ""
    @State private var source = ""

    var body: some View {
        let _ = interfaceLocale
        let title = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let error = core.policyGroupNameError(title)
        let filter = query.trimmingCharacters(in: .whitespacesAndNewlines)
        let canSave = core.canEditPolicyGroups && core.saved == source && error == nil && !members.isEmpty
        VStack(alignment: .leading, spacing: 12) {
            HopPageHeading(title: L("新增策略组"))
            HStack(alignment: .top, spacing: 12) {
                HopLabeledControl(title: L("名称")) {
                    TextField(L("策略组名称"), text: $name, prompt: Text(L("例如 香港备用")))
                        .textFieldStyle(.roundedBorder)
                        .accessibilityLabel(L("策略组名称"))
                }
                Picker(L("类型"), selection: $type) {
                    Text(L("手动")).tag("select")
                    Text(L("自动测速")).tag("url-test")
                    Text(L("故障转移")).tag("fallback")
                }
                .fixedSize()
            }
            HopSearchField(placeholder: L("搜索线路"), text: $query)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 6) {
                    let names = core.configuredNodes.map(\.name)
                    ForEach(names.filter { filter.isEmpty || $0.localizedCaseInsensitiveContains(filter) }, id: \.self) { node in
                        Toggle(core.memberLabel(node), isOn: Binding(
                            get: { members.contains(node) },
                            set: { checked in
                                if checked { members.append(node) }
                                else { members.removeAll { $0 == node } }
                            }
                        ))
                        .lineLimit(1)
                    }
                    if names.isEmpty {
                        Text(L("导入节点后即可选择线路。")).foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(height: min(210, max(48, CGFloat(core.configuredNodes.count) * 25)))
            HStack {
                Text(title.isEmpty ? L("已选 <1> 条线路", members.count) :
                        error ?? (type == "fallback" ? L("按勾选顺序使用线路 · 已选 <1> 条", members.count) : L("已选 <1> 条线路", members.count)))
                    .font(.caption)
                    .foregroundStyle(!title.isEmpty && error != nil ? HopAppearance.warning : .secondary)
                Spacer()
                Button(L("取消")) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(L("创建策略组")) {
                    core.createPolicyGroup(name: title, type: type, members: members, basedOn: source)
                    dismiss()
                }
                .buttonStyle(HopPrimaryButton())
                .keyboardShortcut(.defaultAction)
                .disabled(!canSave)
            }
        }
        .padding(22)
        .frame(width: 490)
        .onAppear { source = core.saved }
    }
}
