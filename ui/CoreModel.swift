import AppKit
import Foundation
import SwiftUI
import UniformTypeIdentifiers

struct Endpoint: Decodable {
    let control: URL
    let token: String
    let socks: String
    let http: String
}

struct Policy: Codable, Equatable {
    var mode: String
    var selected: String
    var auto: AutoRoutingConfig? = nil

    static func label(_ mode: String) -> String {
        switch mode {
        case "rule": "按规则"
        case "global": "全局"
        case "direct": "直连"
        case "auto": "自动"
        default: mode
        }
    }
}

enum DialDiagnostic {
    static func stage(_ key: String?) -> String? {
        guard let key else { return nil }
        let labels = ["route": "路由策略", "dns": "DNS 解析", "connect": "连接服务器",
                      "handshake": "TLS / 协议握手", "upstream": "目标服务",
                      "client-read": "读取客户端", "client-write": "写入客户端",
                      "upstream-read": "读取出站", "upstream-write": "写入出站",
                      "client-transfer": "上传转发", "upstream-transfer": "下载转发"]
        return labels[key] ?? key
    }

    static func message(_ code: String?, fallback: String?) -> String? {
        guard let code else { return fallback }
        let labels = [
            "dns-timeout": "DNS 查询超时", "dns-not-found": "DNS 未返回地址",
            "dns-unavailable": "DNS 上游无法应答", "tls-expired": "TLS 证书已过期",
            "tls-not-yet-valid": "TLS 证书尚未生效", "tls-hostname": "TLS 证书与服务器名称不匹配",
            "tls-untrusted": "TLS 证书不受信任", "tls-certificate": "TLS 证书校验失败",
            "proxy-auth": "上游代理认证失败", "endpoint-cooldown": "出站端点冷却中",
            "endpoint-busy": "出站拨号槽已满", "connection-refused": "服务器拒绝连接",
            "target-refused": "目标服务拒绝连接", "timeout": "连接超时",
            "connection-reset": "连接被对端重置", "broken-pipe": "连接已断开",
            "unreachable": "网络或主机不可达", "canceled": "已取消"
        ]
        return labels[code] ?? fallback
    }
}

struct ProxyStatus: Decodable {
    struct Node: Decodable, Identifiable {
        let name: String
        let type: String
        let latencyMs: Int?
        let alive: Bool?
        let error: String?
        let healthAt: Double?
        let failureStage: String?
        let failureCode: String?
        let probeTarget: String?
        var id: String { name }

        var label: String {
            var parts = [name, type == "group" ? "策略组" : type]
            if alive == false {
                parts.append("不可用")
            } else if let latencyMs {
                parts.append("\(latencyMs) ms")
            }
            return parts.joined(separator: " · ")
        }
    }

    struct Connection: Decodable, Identifiable {
        struct AttemptFailure: Decodable {
            let via: String?
            let stage: String
            let code: String
            let message: String

            var label: String {
                [via, DialDiagnostic.stage(stage), DialDiagnostic.message(code, fallback: message)]
                    .compactMap { $0 }.joined(separator: " · ")
            }
        }

        let id: UInt64
        let start: Double?
        let inbound: String
        let target: String
        let via: String
        let rule: String
        let state: String
        let sent: Int64
        let received: Int64
        let error: String?
        let stage: String?
        let failureCode: String?
        let failures: [AttemptFailure]?
        let route: [String]?
        let server: String?
        let dnsMs: Int?
        let connectMs: Int?
        let handshakeMs: Int?
        let firstByteMs: Int?
        let process: String?
        let processPath: String?
        let network: String?

        var inboundLabel: String { network == "udp" ? inbound + " · UDP" : inbound }

        var routeLabel: String { ((route ?? []) + [via]).joined(separator: " → ") }

        var failureStage: String? { DialDiagnostic.stage(stage) }
        var failureMessage: String? { DialDiagnostic.message(failureCode, fallback: error) }

        var timingLabel: String {
            [("DNS", dnsMs), ("连接", connectMs), ("握手", handshakeMs), ("首字节", firstByteMs)]
                .compactMap { name, value in value.map { "\(name) \($0) ms" } }
                .joined(separator: " · ")
        }

        var diagnosis: String {
            let lines = [failureMessage, failureStage.map { "失败阶段 · " + $0 },
                         processPath.map { "应用 · " + $0 }, "路径 · " + routeLabel,
                         server.map { "服务器 · " + $0 }, timingLabel.isEmpty ? nil : timingLabel]
            return (lines.compactMap { $0 } + (failures ?? []).map(\.label)).joined(separator: "\n")
        }

        var stateLabel: String {
            switch state {
            case "active": "传输中"
            case "closed": "已结束"
            case "blocked": "已拦截"
            case "canceled": "已取消"
            default: "失败"
            }
        }
    }

    struct SystemProxy: Decodable {
        let supported: Bool
        let enabled: Bool
        let error: String?
        let recovered: Bool?
    }

    struct FakeIPPool: Decodable {
        let capacity: Int
        let mapped: Int
        let pinned: Int
        let reclaimed: UInt64
        let refused: UInt64
    }

    struct FakeIP: Decodable {
        let ipv4: FakeIPPool
        let ipv6: FakeIPPool?
    }

    struct TUN: Decodable {
        let supported: Bool
        let enabled: Bool
        let service: Bool?
        let device: String?
        let error: String?
        let operation: String?
        let fakeIP: FakeIP?
    }

    struct PolicyGroup: Decodable, Identifiable {
        let name: String
        let type: String
        let members: [String]
        let now: String
        let selected: String?
        var id: String { name }

        var typeLabel: String {
            switch type {
            case "select": "手动选择"
            case "url-test": "自动选最快"
            case "fallback": "故障转移"
            default: type
            }
        }
    }

    struct Subscription: Decodable, Identifiable {
        let name: String
        let id: String
        let nodes: Int
        let updated: Double?
        let checked: Double?
        let usage: SubscriptionSummary.Meter?
        let error: String?
    }

    struct RuleSet: Decodable, Identifiable {
        let name: String
        let entries: Int
        let updated: Double?
        let error: String?
        var id: String { name }
    }

    struct UDPDropCounts: Decodable {
        let invalid: UInt64
        let fragmented: UInt64
        let queueFull: UInt64
        let upstream: UInt64
        let policy: UInt64

        var total: UInt64 { invalid + fragmented + queueFull + upstream + policy }
        var detail: String {
            "队列满 \(queueFull) · 出站错误 \(upstream) · 规则拒绝 \(policy) · 分片 \(fragmented) · 无效包 \(invalid)"
        }
    }

    let policy: Policy
    let auto: AutoRoutingStatus?
    let warnings: [String]?
    let groups: [PolicyGroup]?
    let subscriptions: [Subscription]?
    let ruleSets: [RuleSet]?
    let systemProxy: SystemProxy?
    let tun: TUN?
    let nodes: [Node]
    let connections: [Connection]
    let active: Int
    let sessionTraffic: TrafficHistory.Count?
    let udpDrops: [String: UDPDropCounts]?
    let reloaded: Double?
}

struct ProfileInspection: Decodable {
    struct Group: Decodable, Identifiable {
        let name: String
        let type: String
        let members: [String]
        let selected: String?
        var id: String { name }
    }

    let nodes: [ProxyStatus.Node]?
    let subscriptions: [SubscriptionSummary]?
    let groups: [Group]?
    let ruleSets: [String]?
    let ruleCount: Int?
    let mode: String?
    let selected: String?
    let backend: String?
    let backendVersion: String?
    let socksPort: Int?
    let httpPort: Int?
    let systemProxy: Bool?
    let tunEnabled: Bool?
    let snapshotAt: [String: Double]?
}

struct CoreError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

@MainActor
final class CoreModel: ObservableObject {
    enum Phase: String {
        case stopped = "已停止"
        case starting = "正在启动"
        case running = "运行中"
        case stopping = "正在停止"
    }

    @Published private(set) var phase = Phase.stopped
    @Published private(set) var endpoint: Endpoint?
    @Published private(set) var status: ProxyStatus?
    @Published private(set) var statusReadFailed = false
    @Published private(set) var configuredProfile: ProfileInspection?
    @Published private(set) var profileReadFailed = false
    private(set) var statusReadAt: Date?
    @Published private(set) var message: String?
    @Published private(set) var configurationNotice: String?
    @Published private(set) var appliedPorts: (socks: Int?, http: Int?)?
    @Published private(set) var verifying = false
    @Published private(set) var verification: String?
    @Published private(set) var saving = false
    @Published private(set) var updatingPolicy = false
    @Published private var requestedTUNOperation: String?
    @Published private(set) var trafficHistory: TrafficHistory?
    @Published private(set) var liveTraffic: TrafficRate?
    @Published private(set) var subscriptions: [SubscriptionSummary] = []
    @Published private(set) var configuredNodes: [ProxyStatus.Node] = []
    @Published private(set) var importCount = 0
    @Published private(set) var hiddenNodes: Set<String> = []
    @Published private(set) var probeResults: [String: NodeProbeResult] = [:]
    @Published private(set) var probePending: Set<String> = []
    @Published private(set) var probeTotal = 0
    @Published var draft = ""
    private var announcedRecovery = false
    @Published private(set) var saved = ""

    private var inspectionID: UUID?
    private var statusFailureMessage: String?
    private var trafficModifiedAt: Date?
    private var lastTrafficSample: (totals: TrafficHistory.Count, time: ContinuousClock.Instant)?
    private var quotaRefreshTask: Task<Void, Never>?
    private var probeFailures: [String: Int] = [:]
    private var lastRecoveryAttempt: Date?
    private var probeProcess: Process?
    private var probeTask: Task<Void, Never>?
    private var probeID: UUID?
    private var process: Process?
    private var input: FileHandle?
    private var polling: Task<Void, Never>?
    private var session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [
            "HTTPEnable": 0, "HTTPSEnable": 0, "SOCKSEnable": 0, "ProxyAutoConfigEnable": 0
        ]
        configuration.timeoutIntervalForRequest = 8
        return URLSession(configuration: configuration)
    }()

    private let configURL: URL
    private var trafficURL: URL {
        configURL.deletingLastPathComponent().appendingPathComponent("traffic-history.json")
    }
    private let executable = Bundle.main.url(forResource: "mac-proxy-core", withExtension: nil)

    init() {
        let files = FileManager.default
        if let override = ProcessInfo.processInfo.environment["MAC_PROXY_CONFIG_DIR"], !override.isEmpty {
            configURL = URL(fileURLWithPath: override).appendingPathComponent("config.json")
        } else {
            configURL = files.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("Mac Proxy").appendingPathComponent("config.json")
        }
        do {
            saved = try String(contentsOf: configURL, encoding: .utf8)
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
            saved = Self.defaultConfiguration
        } catch {
            message = error.localizedDescription
        }
        draft = saved
        reloadConfiguredNodes()
        reloadTraffic()
        quotaRefreshTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(60))
                if Task.isCancelled { return }
                self?.reloadTraffic()
                self?.retryUnavailableNodes()
            }
        }
    }

    deinit { quotaRefreshTask?.cancel() }

    var changed: Bool { draft != saved }

    static let defaultConfiguration = """
    {
      "socksPort": 1080,
      "httpPort": 8080,
      "mode": "rule",
      "selected": "DIRECT",
      "nodes": [],
      "rules": [
        { "type": "match", "via": "DIRECT" }
      ]
    }
    """

    func toggle() {
        switch phase {
        case .running: stop()
        case .stopped: start()
        default: break
        }
    }

    var canConnectToNode: Bool {
        !saving && !updatingPolicy && (phase == .stopped || phase == .running)
    }

    func connectToNode(_ name: String) {
        guard canConnectToNode, configuredNodes.contains(where: { $0.name == name }) else { return }
        let policy = Policy(mode: "global", selected: name)
        if phase == .stopped {
            start(policy: policy)
        } else {
            updatePolicy(policy)
        }
    }

    private func start(policy: Policy? = nil) {
        guard !saving, let executable else {
            if self.executable == nil { message = "App 内缺少代理内核。" }
            return
        }
        cancelProbe()
        message = nil
        phase = .starting
        let launchedConfiguration = saved
        let child = Process()
        child.executableURL = executable
        child.arguments = ["-managed", "-config", configURL.path]
        let inputPipe = Pipe()
        let output = Pipe()
        child.standardInput = inputPipe
        child.standardOutput = output
        child.standardError = FileHandle.nullDevice
        child.terminationHandler = { [weak self] _ in
            Task { @MainActor in self?.terminated(child) }
        }
        do {
            try child.run()
            process = child
            input = inputPipe.fileHandleForWriting
        } catch {
            message = error.localizedDescription
            phase = .stopped
            return
        }
        Task {
            do {
                let reader = output.fileHandleForReading
                let data = try await Task.detached { try Self.readLine(reader) }.value
                if let error = try? JSONDecoder().decode([String: String].self, from: data)["error"] {
                    throw CoreError(message: error)
                }
                let info = try JSONDecoder().decode(Endpoint.self, from: data)
                guard process === child, phase == .starting else { return }
                if let policy {
                    try await applyPolicy(policy, to: info)
                    guard process === child, phase == .starting else { return }
                }
                endpoint = info
                appliedPorts = configuredPorts(in: launchedConfiguration)
                phase = .running
                configurationNotice = nil
                polling = Task {
                    while !Task.isCancelled {
                        await refresh(info)
                        try? await Task.sleep(for: .seconds(1))
                    }
                }
            } catch {
                if process === child || (process == nil && phase == .stopped) {
                    message = "启动失败 · " + error.localizedDescription
                    if process === child { stop() }
                }
            }
        }
    }

    nonisolated private static func readLine(_ reader: FileHandle) throws -> Data {
        var result = Data()
        while result.count < 8192, let byte = try reader.read(upToCount: 1), !byte.isEmpty {
            if byte == Data([10]) { return result }
            result.append(byte)
        }
        throw CoreError(message: "内核退出或未返回启动信息。")
    }

    private func stop() {
        cancelProbe()
        phase = .stopping
        requestedTUNOperation = nil
        polling?.cancel()
        polling = nil
        try? input?.close()
        input = nil
    }

    private func terminated(_ child: Process) {
        guard process === child else { return }
        if phase == .running { message = "内核已退出（退出码 \(child.terminationStatus)）。" }
        polling?.cancel()
        polling = nil
        try? input?.close()
        input = nil
        process = nil
        endpoint = nil
        appliedPorts = nil
        verification = nil
        verifying = false
        status = nil
        clearStatusFailure()
        statusReadAt = nil
        updateTrafficRate(nil)
        updatingPolicy = false
        requestedTUNOperation = nil
        phase = .stopped
    }

    private func call(_ info: Endpoint, path: String, method: String = "GET", body: Data? = nil) async throws -> Data {
        var request = URLRequest(url: info.control.appendingPathComponent(path))
        if path == "verify" { request.timeoutInterval = 8 }
        request.httpMethod = method
        request.httpBody = body
        request.setValue("Bearer " + info.token, forHTTPHeaderField: "Authorization")
        if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw CoreError(message: String(decoding: data.prefix(1024), as: UTF8.self))
        }
        return data
    }

    /// Applies the saved configuration to the running core without a restart.
    private func applyRunning() async -> String {
        guard let info = endpoint else { return "重启内核后生效。" }
        let reloadedConfiguration = saved
        do {
            _ = try await call(info, path: "reload", method: "POST")
            if endpoint?.token == info.token {
                appliedPorts = configuredPorts(in: reloadedConfiguration)
            }
            configurationNotice = nil
            await refresh(info)
            return "已生效，无需重启。"
        } catch {
            configurationNotice = "当前内核仍在使用上次成功应用的配置。"
            let reason = error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
            return "未能热加载（" + reason + "），重启内核后生效。"
        }
    }

    private func configuredPorts(in source: String) -> (socks: Int?, http: Int?)? {
        guard let config = AdvancedSettingsDraft(source: source) else { return nil }
        return (Int(config.original.socksPort), Int(config.original.httpPort))
    }

    func verifyConnection() {
        guard let info = endpoint, !verifying else { return }
        verifying = true
        verification = nil
        Task {
            let result: String
            do {
                _ = try await call(info, path: "verify", method: "POST")
                result = "当前路由已通过 HTTPS 联网验证"
            } catch {
                result = "联网验证失败 · " + error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            guard endpoint?.token == info.token else { return }
            verifying = false
            verification = result
            await refresh(info)
        }
    }

    struct RouteDecision: Decodable {
        let rule: String
        let path: [String]?
        let outbound: String
    }

    func explainRoute(_ host: String) async throws -> RouteDecision {
        guard let info = endpoint else { throw CoreError(message: "请先启动内核。") }
        var address = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if address.hasPrefix("[") && address.hasSuffix("]") {
            address += ":443"
        } else if !address.contains(":") {
            address += ":443"
        } else if address.filter({ $0 == ":" }).count > 1 && !address.hasPrefix("[") {
            address = "[\(address)]:443"
        }
        var url = URLComponents(url: info.control.appendingPathComponent("route"), resolvingAgainstBaseURL: false)
        url?.queryItems = [URLQueryItem(name: "target", value: address)]
        guard let target = url?.url else { throw CoreError(message: "地址无效。") }
        var request = URLRequest(url: target)
        request.setValue("Bearer " + info.token, forHTTPHeaderField: "Authorization")
        let (data, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw CoreError(message: "请输入域名、IP 或主机与端口。")
        }
        return try JSONDecoder().decode(RouteDecision.self, from: data)
    }

    private func refresh(_ info: Endpoint) async {
        do {
            let data = try await call(info, path: "status")
            guard endpoint?.token == info.token else { return }
            let snapshot = try JSONDecoder().decode(ProxyStatus.self, from: data)
            let before = status?.subscriptions?.map { [$0.updated, $0.usage.map { Double($0.updatedAt) }] }
            if let previous = status,
               previous.policy != snapshot.policy || previous.auto?.node != snapshot.auto?.node {
                verification = nil
            }
            statusReadAt = .now
            clearStatusFailure()
            status = snapshot
            updateTrafficRate(snapshot.sessionTraffic)
            if before != snapshot.subscriptions?.map({ [$0.updated, $0.usage.map { Double($0.updatedAt) }] }) {
                reloadConfiguredNodes()
            }
            reloadTraffic()
            if message == nil, let warnings = status?.warnings, !warnings.isEmpty {
                message = warnings.joined(separator: "；")
            }
            if message == nil, status?.systemProxy?.recovered == true, !announcedRecovery {
                announcedRecovery = true
                message = "上次异常退出时留下的系统代理设置已自动还原。"
            }
        } catch {
            guard !Task.isCancelled, endpoint?.token == info.token else { return }
            if !statusReadFailed { statusReadFailed = true }
            updateTrafficRate(nil)
            let failure = "读取内核状态失败 · " + error.localizedDescription
            if message == nil || message == statusFailureMessage { message = failure }
            statusFailureMessage = failure
        }
    }

    private func clearStatusFailure() {
        guard statusReadFailed else { return }
        if message == statusFailureMessage { message = nil }
        statusFailureMessage = nil
        statusReadFailed = false
    }

    func updatePolicy(_ policy: Policy) {
        guard let info = endpoint, !updatingPolicy else { return }
        updatingPolicy = true
        message = nil
        Task {
            defer { if endpoint?.token == info.token { updatingPolicy = false } }
            do {
                try await applyPolicy(policy, to: info)
                await refresh(info)
            } catch {
                if endpoint?.token == info.token { message = error.localizedDescription }
            }
        }
    }

    private func applyPolicy(_ policy: Policy, to info: Endpoint) async throws {
        _ = try await call(info, path: "policy", method: "PUT", body: JSONEncoder().encode(policy))
    }

    /// Points macOS's proxy settings at HopWay, or restores the user's own.
    func setSystemProxy(_ enabled: Bool) {
        guard let info = endpoint else { return }
        message = nil
        Task {
            do {
                struct Body: Encodable { let enabled: Bool }
                _ = try await call(info, path: "system-proxy", method: "PUT", body: JSONEncoder().encode(Body(enabled: enabled)))
                await refresh(info)
            } catch {
                if endpoint?.token == info.token { message = "系统代理设置失败 · " + error.localizedDescription }
            }
        }
    }

    private var tunOperation: String? {
        guard phase == .running else { return nil }
        return requestedTUNOperation ?? (statusReadFailed ? nil : status?.tun?.operation)
    }

    var changingTUN: Bool { tunOperation != nil }

    var tunProgress: String? {
        switch tunOperation {
        case "enable": status?.tun?.service == true ? "正在开启增强模式…" : "正在开启增强模式，如有系统弹窗请完成授权。"
        case "disable": "正在关闭增强模式…"
        case "install-helper": "正在安装 TUN 助手，请在系统弹窗中完成授权。"
        case "remove-helper": "正在移除 TUN 助手，请在系统弹窗中完成授权。"
        default: nil
        }
    }

    /// Turns on TUN mode (macOS asks for the administrator password) or off.
    func setTUN(_ enabled: Bool) {
        requestTUN(enabled ? "enable" : "disable", path: "tun", body: ["enabled": enabled])
    }

    /// Installs or removes the service that lets TUN start without a password.
    func setTUNService(_ installed: Bool) {
        requestTUN(installed ? "install-helper" : "remove-helper", path: "tun-service", body: ["installed": installed])
    }

    private func requestTUN(_ operation: String, path: String, body: [String: Bool]) {
        guard phase == .running, let info = endpoint, !changingTUN else { return }
        requestedTUNOperation = operation
        Task {
            defer {
                if endpoint?.token == info.token { requestedTUNOperation = nil }
            }
            do {
                _ = try await call(info, path: path, method: "PUT", body: JSONEncoder().encode(body))
                guard phase == .running, endpoint?.token == info.token else { return }
                await refresh(info)
            } catch {
                if phase == .running, endpoint?.token == info.token {
                    message = "增强模式操作失败 · " + error.localizedDescription
                }
            }
        }
    }

    /// Picks the member a select group uses.
    func selectInGroup(_ group: String, member: String) {
        guard let info = endpoint else { return }
        Task {
            do {
                struct Body: Encodable { let selected: String }
                _ = try await call(info, path: "groups/" + group, method: "PUT", body: JSONEncoder().encode(Body(selected: member)))
                await refresh(info)
            } catch {
                if endpoint?.token == info.token { message = "切换失败 · " + error.localizedDescription }
            }
        }
    }

    /// Starts a background request (probe, refresh) and re-reads status shortly after.
    func trigger(_ path: String, done text: String) {
        guard let info = endpoint else { return }
        message = text
        Task {
            do {
                _ = try await call(info, path: path, method: "POST")
                try? await Task.sleep(for: .seconds(4))
                await refresh(info)
                if message == text { message = nil }
            } catch {
                if endpoint?.token == info.token { message = error.localizedDescription }
            }
        }
    }

    /// "HK 01 · 83 ms" for a member of a group.
    func memberLabel(_ name: String) -> String {
        status?.nodes.first(where: { $0.name == name })?.label ?? name
    }

    func renameSubscription(_ id: String, to name: String) {
        let alias = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard alias.count <= 80 else {
            message = "订阅名称最多 80 个字符。"
            return
        }
        updateSubscription(id, success: alias.isEmpty ? "已恢复默认订阅名称。" : "订阅名称已更新。") { records, index, _ in
            records[index]["alias"] = alias.isEmpty ? nil : alias
        }
    }

    func pauseSubscription(_ id: String, paused: Bool) {
        updateSubscription(id, success: paused ? "订阅已暂停。" : "订阅已恢复。") { records, index, _ in
            records[index]["paused"] = paused ? true : nil
        }
    }

    func removeSubscription(_ id: String) {
        updateSubscription(id, success: "订阅已移除。") { records, index, config in
            let removed = Set(records.remove(at: index)["nodes"] as? [String] ?? [])
            let shared = Set(records.flatMap { $0["nodes"] as? [String] ?? [] })
            let orphaned = removed.subtracting(shared)
            if let nodes = config["nodes"] as? [[String: Any]] {
                config["nodes"] = nodes.filter { !orphaned.contains($0["name"] as? String ?? "") }
            }
            if let managed = config["subscriptionNodes"] as? [String] {
                config["subscriptionNodes"] = managed.filter { !orphaned.contains($0) }
            }
        }
    }

    private func updateSubscription(
        _ id: String, success: String,
        edit: (inout [[String: Any]], Int, inout [String: Any]) -> Void
    ) {
        guard !saving, let executable else { return }
        guard !changed else {
            message = "请先保存配置草稿，再修改订阅。"
            return
        }
        let originalName = subscriptions.first(where: { $0.id == id })?.originalName
        guard var config = (try? JSONSerialization.jsonObject(with: Data(saved.utf8))) as? [String: Any],
              var records = config["subscriptions"] as? [[String: Any]],
              let index = records.firstIndex(where: {
                  ($0["id"] as? String) == id ||
                  ($0["id"] == nil && $0["name"] as? String == originalName)
              }) else {
            message = "找不到这份订阅，请刷新列表后重试。"
            return
        }
        edit(&records, index, &config)
        config["subscriptions"] = records
        guard let json = try? JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]) else {
            message = "无法保存订阅。"
            return
        }
        let text = String(decoding: json, as: UTF8.self)
        let destination = configURL
        saving = true
        Task {
            defer { saving = false }
            do {
                try await Task.detached {
                    try Self.validateAndSave(text, to: destination, with: executable)
                }.value
                draft = text
                saved = text
                reloadConfiguredNodes()
                let applied = phase == .running ? " " + (await applyRunning()) : ""
                message = success + applied
            } catch {
                message = "无法保存订阅 · " + error.localizedDescription
            }
        }
    }

    private func updateTrafficRate(_ totals: TrafficHistory.Count?) {
        guard let totals else {
            lastTrafficSample = nil
            if liveTraffic != nil { liveTraffic = nil }
            return
        }
        let now = ContinuousClock.now
        guard let last = lastTrafficSample else {
            lastTrafficSample = (totals, now)
            return
        }
        let duration = last.time.duration(to: now)
        // Status refreshes also happen after user actions. Use a long enough
        // interval to avoid spikes when two responses arrive back to back.
        guard duration >= .milliseconds(500),
              totals.upload >= last.totals.upload,
              totals.download >= last.totals.download else { return }
        let elapsed = duration.components
        let seconds = Double(elapsed.seconds) + Double(elapsed.attoseconds) / 1e18
        liveTraffic = TrafficRate(
            upload: Double(totals.upload - last.totals.upload) / seconds,
            download: Double(totals.download - last.totals.download) / seconds
        )
        lastTrafficSample = (totals, now)
    }

    private func reloadTraffic() {
        guard let modified = try? trafficURL.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate,
              modified != trafficModifiedAt,
              let data = try? Data(contentsOf: trafficURL),
              let history = try? JSONDecoder().decode(TrafficHistory.self, from: data) else { return }
        trafficModifiedAt = modified
        trafficHistory = history
    }

    private func retryUnavailableNodes() {
        let now = Date()
        guard probeTask == nil, !saving,
              lastRecoveryAttempt.map({ now.timeIntervalSince($0) >= 120 }) ?? true else { return }
        let names = configuredNodes.map(\.name).filter { (probeFailures[$0] ?? 0) > 0 }
        guard !names.isEmpty else { return }
        lastRecoveryAttempt = now
        runProbe(names, all: false, showSummary: false)
    }

    func testNodes(_ name: String? = nil) {
        let names = configuredNodes.map(\.name).filter { name == nil || $0 == name }
        runProbe(names, all: name == nil, showSummary: true)
    }

    private func runProbe(_ names: [String], all: Bool, showSummary: Bool) {
        guard probeTask == nil, !saving, !names.isEmpty else { return }
        let live = phase == .running ? endpoint : nil
        guard phase == .stopped || live != nil else { return }
        var offline: (Process, FileHandle)?
        if live == nil {
            guard let executable else { return }
            let child = Process()
            child.executableURL = executable
            child.arguments = ["-probe", "-config", configURL.path]
            if !all {
                for name in names { child.arguments?.append(contentsOf: ["-probe-node", name]) }
            }
            let output = Pipe()
            child.standardOutput = output
            child.standardError = FileHandle.nullDevice
            do {
                try child.run()
            } catch {
                message = "无法启动测速 · " + error.localizedDescription
                return
            }
            probeProcess = child
            offline = (child, output.fileHandleForReading)
        }
        let id = UUID()
        probeID = id
        probePending = Set(names)
        probeTotal = probePending.count
        if showSummary { message = nil }
        probeTask = Task {
            var available = 0
            var inconclusive = 0
            var interrupted = false
            @MainActor func receive(_ sample: NodeProbeResult) {
                var result = sample
                guard probePending.remove(result.name) != nil else { return }
                if !result.isAvailable, let previous = probeResults[result.name] {
                    result.lastKnownLatency = previous.isAvailable ? previous.milliseconds : previous.lastKnownLatency
                }
                probeResults[result.name] = result
                if result.isAvailable {
                    available += 1
                    probeFailures.removeValue(forKey: result.name)
                    hiddenNodes.remove(result.name)
                } else if result.isFailure {
                    let failures = min(2, (probeFailures[result.name] ?? 0) + 1)
                    probeFailures[result.name] = failures
                    if failures == 2 { hiddenNodes.insert(result.name) }
                } else {
                    inconclusive += 1
                }
            }
            do {
                if let live {
                    var request = URLRequest(url: live.control.appendingPathComponent("probe/stream"))
                    request.httpMethod = "POST"
                    request.timeoutInterval = 20
                    request.setValue("Bearer " + live.token, forHTTPHeaderField: "Authorization")
                    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
                    request.httpBody = try JSONEncoder().encode(["names": names])
                    let (bytes, response) = try await session.bytes(for: request)
                    guard (response as? HTTPURLResponse)?.statusCode == 200 else {
                        throw CoreError(message: "运行中的内核未接受测速请求。")
                    }
                    let decoder = JSONDecoder()
                    for try await line in bytes.lines {
                        guard probeID == id, endpoint?.token == live.token else { break }
                        if line.isEmpty { continue }
                        receive(try decoder.decode(NodeProbeResult.self, from: Data(line.utf8)))
                    }
                } else if let (child, reader) = offline {
                    for try await result in Self.probeOutput(child, reader: reader) {
                        guard probeID == id else { break }
                        receive(result)
                    }
                }
            } catch {
                interrupted = true
            }
            guard probeID == id else { return }
            let remaining = probePending.count
            let completed = probeTotal - remaining
            if showSummary {
                if interrupted || remaining > 0 {
                    message = "测速未完整结束 · 已完成 \(completed)/\(probeTotal)，剩余 \(remaining) 个。"
                } else {
                    let failed = completed - available - inconclusive
                    let uncertain = inconclusive == 0 ? "" : "，\(inconclusive) 个待复测"
                    message = "测速完成 · \(completed) 个节点，\(available) 个可用，\(failed) 个失败或超时\(uncertain)。"
                }
            }
            probeTask = nil
            probeProcess = nil
            probeID = nil
            probePending = []
            probeTotal = 0
        }
    }

    func cancelProbe() {
        probeID = nil
        probeTask?.cancel()
        probeTask = nil
        if let child = probeProcess, child.isRunning { child.terminate() }
        probeProcess = nil
        probePending = []
        probeTotal = 0
    }

    nonisolated private static func probeOutput(_ child: Process, reader: FileHandle) -> AsyncThrowingStream<NodeProbeResult, Error> {
        AsyncThrowingStream { continuation in
            Task.detached {
                do {
                    var pending = Data()
                    let decoder = JSONDecoder()
                    while let chunk = try reader.read(upToCount: 4096), !chunk.isEmpty {
                        pending.append(chunk)
                        while let newline = pending.firstIndex(of: 10) {
                            continuation.yield(try decoder.decode(NodeProbeResult.self, from: pending[..<newline]))
                            pending.removeSubrange(...newline)
                        }
                    }
                    child.waitUntilExit()
                    guard child.terminationStatus == 0, pending.isEmpty else {
                        throw CoreError(message: "测速进程退出。")
                    }
                    continuation.finish()
                } catch {
                    if child.isRunning { child.terminate() }
                    continuation.finish(throwing: error)
                }
            }
        }
    }

    private func reloadConfiguredNodes() {
        guard let executable else { return }
        let destination = configURL
        let id = UUID()
        inspectionID = id
        Task {
            do {
                let data = try await Task.detached {
                    try Self.runProfileCommand("-inspect", at: destination, executable: executable)
                }.value
                guard inspectionID == id else { return }
                let profile = try JSONDecoder().decode(ProfileInspection.self, from: data)
                profileReadFailed = false
                configuredProfile = profile
                configuredNodes = profile.nodes ?? []
                subscriptions = profile.subscriptions ?? []
                let names = Set(configuredNodes.map(\.name))
                hiddenNodes.formIntersection(names)
                probeResults = probeResults.filter { names.contains($0.key) }
                probeFailures = probeFailures.filter { names.contains($0.key) }
            } catch {
                if inspectionID == id { profileReadFailed = true }
            }
        }
    }

    func refreshAllSubscriptions() { refreshSubscriptions(checkNodes: false) }
    func refreshNodes() { refreshSubscriptions(checkNodes: true) }

    func refreshSubscription(_ id: String) { refreshSubscriptions(checkNodes: false, id: id) }

    private func refreshSubscriptions(checkNodes: Bool, id: String? = nil) {
        guard !saving, let executable else { return }
        if !subscriptions.contains(where: { !$0.isPaused && (id == nil || $0.id == id) }) {
            if checkNodes { testNodes() }
            return
        }
        if endpoint != nil {
            let path = id.map { "subscriptions/" + $0 + "/refresh" } ?? "subscriptions/refresh"
            trigger(path, done: "正在刷新订阅…")
            return
        }
        saving = true
        let destination = configURL
        Task {
            defer { saving = false }
            do {
                let data = try await Task.detached {
                    try Self.runProfileCommand("-refresh-subscriptions", at: destination, executable: executable, subscriptionID: id)
                }.value
                let result = try JSONDecoder().decode([String: Int].self, from: data)
                message = "已刷新 \(result["updated"] ?? 0) 份订阅 · \(result["failed"] ?? 0) 份失败"
                reloadConfiguredNodes()
            } catch {
                message = "刷新失败 · " + error.localizedDescription
            }
        }
    }

    nonisolated private static func runProfileCommand(_ flag: String, at destination: URL, executable: URL, subscriptionID: String? = nil) throws -> Data {
        let child = Process()
        let output = Pipe()
        child.executableURL = executable
        child.arguments = [flag, "-config", destination.path]
        if let subscriptionID { child.arguments?.append(contentsOf: ["-subscription-id", subscriptionID]) }
        child.standardOutput = output
        child.standardError = FileHandle.nullDevice
        try child.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        child.waitUntilExit()
        guard child.terminationStatus == 0 else { throw CoreError(message: "内核命令失败。") }
        return data
    }

    func importClipboard() {
        importContent(NSPasteboard.general.string(forType: .string) ?? "")
    }

    func importContent(_ raw: String) {
        guard !saving, let executable else { return }
        guard !changed else {
            message = "请先保存配置草稿，再导入节点。"
            return
        }
        guard !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            message = "请先复制订阅地址、节点链接或 Clash 配置。"
            return
        }
        saving = true
        message = "正在识别并导入…"
        let destination = configURL
        Task {
            defer { saving = false }
            do {
                let (text, summary) = try await Task.detached {
                    try Self.convertAndSave(raw, to: destination, with: executable)
                }.value
                draft = text
                saved = text
                reloadConfiguredNodes()
                importCount += 1
                var next = "启动后可在概览切换出站。"
                if phase == .running {
                    next = await applyRunning()
                }
                message = summary + " " + next
            } catch {
                message = "导入失败 · " + error.localizedDescription
            }
        }
    }

    struct ImportPreview: Decodable {
        let added: Int
        let skipped: Int
        let notes: [String]
    }

    func previewImport(_ raw: String) async throws -> ImportPreview {
        guard let executable, !changed else {
            throw CoreError(message: "请先保存配置草稿，再预览导入。")
        }
        let destination = configURL
        let data = try await Task.detached {
            try Self.convert(raw, from: destination, with: executable, preview: true)
        }.value
        return try JSONDecoder().decode(ImportPreview.self, from: data)
    }

    nonisolated private static func convertAndSave(_ raw: String, to destination: URL, with executable: URL) throws -> (String, String) {
        let data = try convert(raw, from: destination, with: executable, preview: false)
        guard let result = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let config = result["config"] as? [String: Any],
              let added = result["added"] as? Int,
              let skipped = result["skipped"] as? Int,
              let notes = result["notes"] as? [String] else {
            throw CoreError(message: "内核返回的导入结果无效。")
        }
        let json = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        let text = String(decoding: json, as: UTF8.self)
        try validateAndSave(text, to: destination, with: executable)
        let summary = ["已导入 \(added) 个节点，跳过 \(skipped) 个。"] + notes
        return (text, summary.joined(separator: " "))
    }

    nonisolated private static func convert(_ raw: String, from destination: URL, with executable: URL, preview: Bool) throws -> Data {
        guard raw.utf8.count <= 1_048_576 else { throw CoreError(message: "导入内容上限为 1 MB。") }
        let files = FileManager.default
        let directory = files.temporaryDirectory.appendingPathComponent("hopway-" + UUID().uuidString)
        try files.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? files.removeItem(at: directory) }
        let source = directory.appendingPathComponent("input")
        guard files.createFile(atPath: source.path, contents: Data(raw.utf8), attributes: [.posixPermissions: 0o600]) else {
            throw CoreError(message: "无法暂存导入内容。")
        }
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        let output = Pipe()
        let child = Process()
        child.executableURL = executable
        // Always name the config path, even before the file exists: the core
        // keeps subscription caches next to it.
        child.arguments = [preview ? "-preview-import" : "-import", "-config", destination.path]
        child.standardInput = input
        child.standardOutput = output
        child.standardError = output
        try child.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        child.waitUntilExit()
        guard child.terminationStatus == 0 else {
            let explanation = String(decoding: data.prefix(2048), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            throw CoreError(message: explanation.isEmpty ? "内核无法完成导入。" : explanation)
        }
        return data
    }

    func importDraft() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            guard let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= 1_048_576 else {
                throw CoreError(message: "配置文件上限为 1 MB。")
            }
            draft = try String(contentsOf: url, encoding: .utf8)
            message = nil
        } catch {
            message = error.localizedDescription
        }
    }

    func insertTemplate(_ type: String) {
        do {
            guard var object = try JSONSerialization.jsonObject(with: Data(draft.utf8)) as? [String: Any],
                  object["nodes"] == nil || object["nodes"] is NSNull || object["nodes"] is [[String: Any]] else {
                throw CoreError(message: "请先将草稿修正为 JSON 对象，nodes 应为数组。")
            }
            var nodes = object["nodes"] as? [[String: Any]] ?? []
            var name = type
            var index = 1
            while nodes.contains(where: { $0["name"] as? String == name }) {
                index += 1
                name = "\(type)-\(index)"
            }
            var node = ["name": name, "type": type, "server": "proxy.example.com:443"]
            if type == "trojan" || type == "shadowsocks" { node["password"] = "替换为节点密码" }
            if type == "shadowsocks" { node["cipher"] = "aes-128-gcm" }
            if type == "vless" || type == "vmess" { node["uuid"] = "替换为节点 UUID" }
            nodes.append(node)
            object["nodes"] = nodes
            let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
            draft = String(decoding: data, as: UTF8.self)
            message = nil
        } catch {
            message = error.localizedDescription
        }
    }

    func save() {
        saveConfiguration(draft)
    }

    func saveAdvanced(_ candidate: String, basedOn source: String, needsRestart: Bool, activation: String?) {
        guard !changed, saved == source else {
            message = "配置已有更新，请重新打开高级配置后再保存。"
            return
        }
        saveConfiguration(candidate, needsRestart: needsRestart, activation: activation)
    }

    private func saveConfiguration(_ candidate: String, needsRestart: Bool = false, activation: String? = nil) {
        guard !saving, let executable else { return }
        saving = true
        message = nil
        let destination = configURL
        Task {
            defer { saving = false }
            do {
                try await Task.detached { try Self.validateAndSave(candidate, to: destination, with: executable) }.value
                saved = candidate
                draft = candidate
                reloadConfiguredNodes()
                if phase == .running {
                    if needsRestart {
                        message = "配置已保存。重启代理后应用新的监听端口和本次改动。"
                        configurationNotice = "已保存的端口将在重启后使用。"
                    } else if let activation {
                        let applied = await applyRunning()
                        message = applied == "已生效，无需重启。" ? "配置已保存。\(activation)" : "配置已保存，\(applied)"
                        if configurationNotice == nil { configurationNotice = activation }
                    } else {
                        message = "配置已保存，" + (await applyRunning())
                    }
                } else {
                    message = "配置已保存。"
                }
            } catch {
                message = error.localizedDescription
            }
        }
    }

    nonisolated private static func validateAndSave(_ text: String, to destination: URL, with executable: URL) throws {
        let files = FileManager.default
        let directory = destination.deletingLastPathComponent()
        try files.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let stage = directory.appendingPathComponent(".draft-" + UUID().uuidString)
        defer { try? files.removeItem(at: stage) }
        guard text.utf8.count <= 1_048_576 else { throw CoreError(message: "配置文件上限为 1 MB。") }
        guard files.createFile(atPath: stage.path, contents: Data(text.utf8), attributes: [.posixPermissions: 0o600]) else {
            throw CoreError(message: "无法创建配置草稿。")
        }
        let child = Process()
        child.executableURL = executable
        child.arguments = ["-check", "-config", stage.path]
        let output = Pipe()
        child.standardError = output
        try child.run()
        let diagnostics = output.fileHandleForReading.readDataToEndOfFile()
        child.waitUntilExit()
        guard child.terminationStatus == 0 else {
            throw CoreError(message: "配置校验失败 · " + String(decoding: diagnostics.prefix(1024), as: UTF8.self))
        }
        if rename(stage.path, destination.path) != 0 {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }
}
