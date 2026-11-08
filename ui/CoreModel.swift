import AppKit
import CryptoKit
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
    var expectedProbeKey: String? = nil

    static func label(_ mode: String) -> String {
        switch mode {
        case "rule": L("按规则")
        case "global": L("手动")
        case "direct": L("直连")
        case "auto": L("按地区自动")
        case "fastest": L("自动最快")
        default: mode
        }
    }
}

enum DialDiagnostic {
    static func stage(_ key: String?) -> String? {
        guard let key else { return nil }
        let labels = ["route": L("路由策略"), "dns": L("DNS 解析"), "connect": L("连接服务器"),
                      "handshake": L("TLS / 协议握手"), "upstream": L("目标服务"),
                      "client-read": L("读取客户端"), "client-write": L("写入客户端"),
                      "upstream-read": L("读取出站"), "upstream-write": L("写入出站"),
                      "client-transfer": L("上传转发"), "upstream-transfer": L("下载转发"), "idle": L("空闲回收")]
        return labels[key] ?? key
    }

    static func message(_ code: String?, fallback: String?) -> String? {
        guard let code else { return fallback }
        let labels = [
            "dns-timeout": L("DNS 查询超时"), "dns-not-found": L("DNS 未返回地址"),
            "dns-unavailable": L("DNS 上游无法应答"), "tls-expired": L("TLS 证书已过期"),
            "tls-not-yet-valid": L("TLS 证书尚未生效"), "tls-hostname": L("TLS 证书与服务器名称不匹配"),
            "tls-untrusted": L("TLS 证书不受信任"), "tls-certificate": L("TLS 证书校验失败"),
            "proxy-auth": L("上游代理认证失败"), "endpoint-cooldown": L("出站端点冷却中"),
            "endpoint-busy": L("出站拨号槽已满"), "connection-refused": L("服务器拒绝连接"),
            "fd-exhausted": L("本机文件描述符额度用尽"),
            "tcp-idle-timeout": L("隧道达到空闲回收时限"),
            "target-refused": L("目标服务拒绝连接"), "timeout": L("连接超时"),
            "connection-reset": L("连接被对端重置"), "broken-pipe": L("连接已断开"),
            "unreachable": L("网络或主机不可达"), "canceled": L("已取消")
        ]
        return labels[code] ?? fallback
    }
}

struct ProxyStatus: Decodable, Equatable {
    struct Node: Decodable, Equatable, Identifiable {
        let name: String
        let type: String
        let probeKey: String?
        let latencyMs: Int?
        let alive: Bool?
        let error: String?
        let healthAt: Double?
        let failureStage: String?
        let failureCode: String?
        let probeTarget: String?
        var id: String { name }
        var probeIdentity: String { probeKey ?? "legacy:" + name }

        var label: String {
            var parts = [name, type == "group" ? L("策略组") : type]
            if alive == false {
                parts.append(L("不可用"))
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
        let targetSource: String?
        let via: String
        let rule: String
        let state: String
        var sent: Int64
        var received: Int64
        let error: String?
        let stage: String?
        let failureCode: String?
        let failures: [AttemptFailure]?
        let route: [String]?
        let server: String?
        let dnsMs: Int?
        let connectMs: Int?
        let handshakeMs: Int?
        var firstByteMs: Int?
        let process: String?
        let processPath: String?
        let processBundleId: String?
        let network: String?

        var inboundLabel: String { network == "udp" ? inbound + " · UDP" : inbound }

        var routeLabel: String { ((route ?? []) + [via]).joined(separator: " → ") }

        var targetSourceLabel: String? {
            switch targetSource {
            case "fake-ip": L("DNS 映射（Fake IP）")
            case "tls-sni": "TLS SNI"
            case "http-host": "HTTP Host"
            case "ip": L("原始 IP")
            default: nil
            }
        }

        var failureStage: String? { DialDiagnostic.stage(stage) }
        var failureMessage: String? { DialDiagnostic.message(failureCode, fallback: error) }

        var timingLabel: String {
            [("DNS", dnsMs), (L("连接"), connectMs), (L("握手"), handshakeMs), (L("首字节"), firstByteMs)]
                .compactMap { name, value in value.map { "\(name) \($0) ms" } }
                .joined(separator: " · ")
        }

        var diagnosis: String {
            let lines = [failureMessage, failureStage.map { L("失败阶段 · ") + $0 },
                         processPath.map { L("应用 · ") + $0 }, processBundleId.map { L("应用标识 · ") + $0 }, L("路径 · ") + routeLabel,
                         targetSourceLabel.map { L("目标来源 · ") + $0 },
                         server.map { L("服务器 · ") + $0 }, timingLabel.isEmpty ? nil : timingLabel]
            return (lines.compactMap { $0 } + (failures ?? []).map(\.label)).joined(separator: "\n")
        }

        var stateLabel: String {
            switch state {
            case "active": L("传输中")
            case "closed": L("已结束")
            case "blocked": L("已拦截")
            case "canceled": L("已取消")
            default: L("失败")
            }
        }
    }

    struct SystemProxy: Decodable, Equatable {
        let supported: Bool
        let enabled: Bool
        let error: String?
        let recovered: Bool?
    }

    struct FakeIPPool: Decodable, Equatable {
        let capacity: Int
        let mapped: Int
        let pinned: Int
        let reclaimed: UInt64
        let refused: UInt64
    }

    struct FakeIP: Decodable, Equatable {
        let ipv4: FakeIPPool
        let ipv6: FakeIPPool?
    }

    struct TUN: Decodable, Equatable {
        struct DNS: Decodable, Equatable {
            let timeoutMs: Int
            let exceptionCount: Int
            let sniffingEnabled: Bool
        }

        let supported: Bool
        let enabled: Bool
        let service: Bool?
        let device: String?
        let error: String?
        let operation: String?
        let fakeIP: FakeIP?
        let dns: DNS?
    }

    struct PolicyGroup: Decodable, Equatable, Identifiable {
        let name: String
        let type: String
        let members: [String]
        let now: String
        let selected: String?
        var id: String { name }

        var typeLabel: String {
            switch type {
            case "select": L("手动选择")
            case "url-test": L("自动选最快")
            case "fallback": L("故障转移")
            default: type
            }
        }
    }

    struct Subscription: Decodable, Equatable, Identifiable {
        let name: String
        let id: String
        let nodes: Int
        let updated: Double?
        let checked: Double?
        let usage: SubscriptionSummary.Meter?
        let error: String?
    }

    struct RuleSet: Decodable, Equatable, Identifiable {
        let name: String
        let entries: Int
        let updated: Double?
        let error: String?
        var id: String { name }
    }

    struct RuleDefaults: Decodable, Equatable {
        let explicitMatch: UInt64
        let implicit: UInt64
    }

    struct UDPDropCounts: Decodable, Equatable {
        let invalid: UInt64
        let fragmented: UInt64
        let queueFull: UInt64
        let upstream: UInt64
        let policy: UInt64

        var total: UInt64 { invalid + fragmented + queueFull + upstream + policy }
        var detail: String {
            L("队列满 <1> · 出站错误 <2> · 规则拒绝 <3> · 分片 <4> · 无效包 <5>", queueFull, upstream, policy, fragmented, invalid)
        }
    }

    struct NetworkEvent: Decodable, Equatable {
        let at: String
    }

    let network: [NetworkEvent]?
    let policy: Policy
    let auto: AutoRoutingStatus?
    let warnings: [String]?
    let groups: [PolicyGroup]?
    let subscriptions: [Subscription]?
    let ruleSets: [RuleSet]?
    let ruleDefaults: RuleDefaults?
    let systemProxy: SystemProxy?
    let tun: TUN?
    let nodes: [Node]
    let active: Int
    let generation: UInt64
    let canUndoRoute: Bool?
    let sessionTraffic: TrafficHistory.Count?
    let udpDrops: [String: UDPDropCounts]?
    struct Resources: Decodable, Equatable {
        let connections: Int?
        let connectionLimit: Int?
        let connectionsRefused: UInt64?
        let udpSessions: Int
        let udpSessionLimit: Int
        let udpOpening: Int
        let udpOpenLimit: Int
        let endpointDialLimit: Int
        let udpIdleTimeoutSec: Int?
        let udpQueuedBytes: Int64?
        let udpQueueLimitBytes: Int64?
    }
    let resources: Resources?
    let reloaded: Double?
    let revision: String?
    let profileFallback: Bool?

    var currentOutbound: String? {
        switch policy.mode {
        case "auto", "fastest": auto?.node
        case "global": groups?.first(where: { $0.name == policy.selected })?.now ?? policy.selected
        case "direct": "DIRECT"
        default: nil
        }
    }
    struct Retirement: Decodable, Equatable {
        let pending: UInt64
        let forced: UInt64
        let slow: UInt64
    }
    let retirement: Retirement?
}

private struct ConnectionUpdate: Decodable {
    struct Counters: Decodable {
        let id: UInt64
        let sent: UInt64
        let received: UInt64
        let firstByteMs: Int?
    }

    let generation: UInt64
    let cursor: UInt64
    let full: Bool?
    let records: [ProxyStatus.Connection]?
    let counters: [Counters]?
    let removed: [UInt64]?
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
    let outboundIds: [String: String]?
    let groupAliases: [String: String]?
    let groupRuleRefs: [String: Int]?
    let localGroups: [String]?
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
    let revision: String?
}

struct CoreError: LocalizedError {
    let message: String
    var requiresRestart = false
    var errorDescription: String? { message }
}

private struct ProfileWriteConflict: LocalizedError {
    var errorDescription: String? { L("磁盘配置已有新版本，请核对后再保存。") }
}

@MainActor
final class CoreModel: ObservableObject {
    enum RouteVerification {
        case reachable
        case failed(String)

        var title: String {
            switch self {
            case .reachable: L("联网正常")
            case .failed: L("联网失败")
            }
        }

        var detail: String {
            switch self {
            case .reachable: L("当前出站已通过 HTTPS 联网验证")
            case .failed(let reason): reason
            }
        }

        var failed: Bool {
            if case .failed = self { return true }
            return false
        }
    }

    enum Phase: String {
        case stopped = "已停止"
        case starting = "正在启动"
        case running = "运行中"
        case stopping = "正在停止"
    }

    private struct VerificationRoute: Equatable {
        let generation: UInt64
        let policy: Policy
        let outbound: String?
        let groupExits: [String]
        let networkChangedAt: String?

        init(_ status: ProxyStatus) {
            generation = status.generation
            policy = status.policy
            outbound = status.currentOutbound
            groupExits = policy.mode == "rule" ? status.groups?.map(\.now) ?? [] : []
            networkChangedAt = status.network?.last?.at
        }

        var canVerify: Bool {
            outbound != "REJECT" && (outbound != nil || policy.mode == "rule")
        }
    }

    private var verificationRoute: VerificationRoute?
    private var verificationTask: Task<Void, Never>?
    private var nextVerificationAt: ContinuousClock.Instant?

    @Published private(set) var phase = Phase.stopped
    @Published private(set) var endpoint: Endpoint?
    @Published private(set) var status: ProxyStatus?
    @Published private(set) var statusReadFailed = false
    @Published private(set) var connectionReadFailed = false
    @Published private(set) var configuredProfile: ProfileInspection?
    @Published private(set) var profileReadFailed = false
    private(set) var statusReadAt: Date?
    private(set) var connectionReadAt: Date?
    @Published private(set) var message: String?
    @Published private(set) var configurationNotice: String?
    @Published private(set) var configurationConflict = false
    @Published private(set) var verifying = false
    @Published private(set) var verification: RouteVerification?
    @Published private(set) var saving = false
    @Published private(set) var refreshing = false
    @Published private(set) var exportingDiagnostics = false
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
    private var presentedWarnings: [String] = []
    @Published private(set) var saved = ""
    @Published private(set) var savedRevision = "missing"

    private var inspectionID: UUID?
    private var statusFailureMessage: String?
    private var trafficStamp: TrafficHistory.DiskStamp?
    private var trafficReadTask: Task<Void, Never>?
    private var lastTrafficSample: (totals: TrafficHistory.Count, time: ContinuousClock.Instant)?
    private var quotaRefreshTask: Task<Void, Never>?
    private var probeFailures: [String: Int] = [:]
    private var lastRecoveryAttempt: Date?
    private var probeProcess: Process?
    private var probeInput: FileHandle?
    private var probeTask: Task<Void, Never>?
    private var probeID: UUID?
    private var process: Process?
    private var input: FileHandle?
    private var polling: Task<Void, Never>?
    private var statusRequest: Task<Void, Never>?
    private var statusRequestedAgain = false
    private var refreshTask: Task<Void, Never>?
    private var refreshID: UUID?
    private var terminationObserver: NSObjectProtocol?
    private var watchingConnections = false
    private var connectionRequest: Task<Void, Never>?
    private var connectionCursor: UInt64?
    private var connectionRecords: [UInt64: ProxyStatus.Connection] = [:]

    var connections: Dictionary<UInt64, ProxyStatus.Connection>.Values { connectionRecords.values }
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
            let document = try Self.readDiskConfiguration(configURL)
            saved = document.text
            savedRevision = document.revision
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
        terminationObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.willTerminateNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.shutDown() }
        }
    }

    deinit {
        quotaRefreshTask?.cancel()
        if let terminationObserver { NotificationCenter.default.removeObserver(terminationObserver) }
    }

    private func shutDown() {
        quotaRefreshTask?.cancel()
        if process != nil { stop() }
        else { cancelProbe(); cancelControlRefresh() }
        session.invalidateAndCancel()
    }

    var changed: Bool { draft != saved }

    nonisolated static let defaultConfiguration = """
    {
      "socksPort": 1080,
      "httpPort": 8080,
      "mode": "fastest",
      "selected": "DIRECT",
      "nodes": [],
      "rules": [
        { "type": "match", "via": "DIRECT" }
      ]
    }
    """

    private func acceptSavedConfiguration(_ text: String, revision: String) {
        savedRevision = revision
        saved = text
        draft = text
        configurationConflict = false
        reloadConfiguredNodes()
    }

    func readDiskConfiguration() {
        guard !saving else { return }
        do {
            let document = try Self.readDiskConfiguration(configURL)
            acceptSavedConfiguration(document.text, revision: document.revision)
            message = L("已读取磁盘配置。")
        } catch {
            message = error.localizedDescription
        }
    }

    nonisolated private static func readDiskConfiguration(_ path: URL) throws -> (text: String, revision: String) {
        do {
            let data = try Data(contentsOf: path)
            guard let text = String(data: data, encoding: .utf8) else {
                throw CoreError(message: L("配置文件须使用 UTF-8 编码。"))
            }
            let revision = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            return (text, revision)
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
            return (defaultConfiguration, "missing")
        }
    }

    private func writeFailed(_ error: Error, prefix: String = "") {
        if error is ProfileWriteConflict {
            configurationConflict = true
            reloadConfiguredNodes()
        }
        message = prefix + error.localizedDescription
    }

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
        guard canConnectToNode, let node = configuredNodes.first(where: { $0.name == name }) else { return }
        if phase == .stopped {
            start(policy: Policy(mode: "global", selected: name, expectedProbeKey: node.probeKey))
        } else {
            selectNode(node, mode: "global")
        }
    }

    func selectNode(_ node: ProxyStatus.Node, mode: String) {
        guard let current = status?.nodes.first(where: { $0.probeIdentity == node.probeIdentity }) else {
            message = L("节点配置已变化，请刷新后重试。")
            return
        }
        updatePolicy(Policy(mode: mode, selected: current.name, expectedProbeKey: current.probeKey))
    }

    private func start(policy: Policy? = nil) {
        guard !saving, let executable else {
            if self.executable == nil { message = L("App 内缺少代理内核。") }
            return
        }
        cancelProbe()
        message = nil
        presentedWarnings = []
        phase = .starting
        let child = Process()
        child.executableURL = executable
        var arguments = ["-managed", "-desktop-routing", "-config", configURL.path]
        if let policy {
            arguments += ["-startup-node", policy.selected]
            if let key = policy.expectedProbeKey {
                arguments += ["-startup-probe-key", key]
            }
        }
        child.arguments = arguments
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
                endpoint = info
                if policy != nil { reloadConfiguredNodes() }
                phase = .running
                configurationNotice = nil
                polling = Task {
                    while !Task.isCancelled {
                        await refresh(info, followUp: false)
                        try? await Task.sleep(for: .seconds(1))
                    }
                }
            } catch {
                if process === child || (process == nil && phase == .stopped) {
                    message = L("启动失败 · ") + error.localizedDescription
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
        throw CoreError(message: L("内核退出或未返回启动信息。"))
    }

    private func stop() {
        cancelProbe()
        cancelControlRefresh()
        phase = .stopping
        resetVerification()
        requestedTUNOperation = nil
        polling?.cancel()
        polling = nil
        cancelStatusRequest()
        try? input?.close()
        input = nil
    }

    private func terminated(_ child: Process) {
        guard process === child else { return }
        if phase == .running { message = L("内核已退出（退出码 <1>）。", child.terminationStatus) }
        polling?.cancel()
        polling = nil
        cancelStatusRequest()
        cancelControlRefresh()
        try? input?.close()
        input = nil
        process = nil
        endpoint = nil
        resetVerification()
        status = nil
        connectionRecords.removeAll()
        connectionCursor = nil
        connectionReadAt = nil
        connectionReadFailed = false
        clearStatusFailure()
        statusReadAt = nil
        updateTrafficRate(nil)
        updatingPolicy = false
        requestedTUNOperation = nil
        phase = .stopped
    }

    private func call(_ info: Endpoint, path: String, method: String = "GET", body: Data? = nil,
                      revision: String? = nil, query: [URLQueryItem] = []) async throws -> Data {
        let url = info.control.appendingPathComponent(path)
        var request = URLRequest(url: url)
        if !query.isEmpty {
            var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            components?.queryItems = query
            guard let target = components?.url else { throw CoreError(message: L("控制请求地址无效。")) }
            request.url = target
        }
        if path == "verify" { request.timeoutInterval = 8 }
        request.httpMethod = method
        request.httpBody = body
        request.setValue("Bearer " + info.token, forHTTPHeaderField: "Authorization")
        if let revision { request.setValue(revision, forHTTPHeaderField: "X-HopWay-Revision") }
        if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        let (data, response) = try await session.data(for: request)
        let http = response as? HTTPURLResponse
        guard let http, (200..<300).contains(http.statusCode) else {
            throw CoreError(message: String(decoding: data.prefix(1024), as: UTF8.self),
                            requiresRestart: http?.value(forHTTPHeaderField: "X-HopWay-Restart-Required") == "1")
        }
        return data
    }

    /// Applies the saved configuration to the running core without a restart.
    private func applyRunning() async -> String {
        guard let info = endpoint else { return L("重启内核后生效。") }
        do {
            _ = try await call(info, path: "reload", method: "POST", revision: savedRevision)
            configurationNotice = nil
            await refresh(info)
            return L("已生效，无需重启。")
        } catch let error as CoreError where error.requiresRestart {
            configurationNotice = L("本次配置将在重启代理后生效。")
            return L("重启代理后生效。")
        } catch {
            configurationNotice = L("当前内核仍在使用上次成功应用的配置。")
            let reason = error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
            return L("未能热加载（") + reason + L("），重启内核后生效。")
        }
    }

    private func resetVerification() {
        verificationTask?.cancel()
        verificationTask = nil
        verificationRoute = nil
        nextVerificationAt = nil
        if verifying { verifying = false }
        if verification != nil { verification = nil }
    }

    private func scheduleVerification(_ info: Endpoint, status: ProxyStatus) {
        let route = VerificationRoute(status)
        if verificationRoute != route {
            resetVerification()
            verificationRoute = route
        }
        guard route.canVerify, verificationTask == nil,
              nextVerificationAt.map({ $0 <= .now }) ?? true else { return }

        if verification == nil { verifying = true }
        verificationTask = Task { [weak self] in
            guard let self, isRunning(info) else { return }
            let result: RouteVerification
            do {
                _ = try await call(info, path: "verify", method: "POST")
                result = .reachable
            } catch {
                result = .failed(error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines))
            }
            guard isRunning(info), verificationRoute == route, !statusReadFailed else { return }
            verification = result
            verifying = false
            nextVerificationAt = ContinuousClock.now.advanced(by: .seconds(result.failed ? 30 : 300))
            verificationTask = nil
        }
    }

    var accessLabel: String {
        guard phase == .running else { return L("未接管") }
        guard let status, !statusReadFailed else { return L("读取中") }
        return switch (status.tun?.enabled == true, status.systemProxy?.enabled == true) {
        case (true, true): L("TUN + 系统代理")
        case (true, false): "TUN"
        case (false, true): L("系统代理")
        case (false, false): L("手动接入")
        }
    }

    var reachabilityLabel: String {
        if phase != .running { return L("启动后自动验证") }
        if statusReadFailed { return L("状态待确认") }
        if verifying { return L("正在验证…") }
        if status?.currentOutbound == "REJECT" { return L("已阻断") }
        if verificationRoute?.canVerify == false { return L("等待可用出站") }
        return verification?.title ?? L("等待验证")
    }

    func dismissMessage() {
        message = nil
    }

    func exportDiagnostics() {
        guard !exportingDiagnostics else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.zip]
        panel.nameFieldStringValue = L("HopWay-诊断.zip")
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        exportingDiagnostics = true
        Task {
            defer { exportingDiagnostics = false }
            do {
                try await writeDiagnostics(to: destination)
                message = L("已导出诊断文件。")
            } catch {
                message = L("导出诊断失败 · ") + error.localizedDescription
            }
        }
    }

    func writeDiagnostics(to destination: URL) async throws {
        var report = diagnosticSummary()
        var files: [String: Data] = [:]
        if let info = endpoint, isRunning(info) {
            for kind in ["cpu", "heap"] {
                let label = kind == "cpu" ? L("CPU 样本") : L("堆快照")
                do {
                    var query = [URLQueryItem(name: "kind", value: kind)]
                    if kind == "cpu" { query.append(URLQueryItem(name: "seconds", value: "3")) }
                    guard isRunning(info) else { throw CancellationError() }
                    files[kind + ".pprof"] = try await call(info, path: "diagnostics/profile", method: "POST", query: query)
                    report += L("\n<1> · 已采集", label)
                } catch {
                    report += L("\n<1> · 采集失败", label)
                }
            }
        } else {
            report += L("\n性能样本 · 内核停止")
        }
        files["report.txt"] = Data((report + "\n").utf8)
        let archive = files
        try await Task.detached {
            let manager = FileManager.default
            let temporary = manager.temporaryDirectory.appendingPathComponent("hopway-diagnostics-" + UUID().uuidString)
            let contents = temporary.appendingPathComponent("HopWay-Diagnostics")
            try manager.createDirectory(at: temporary, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            defer { try? manager.removeItem(at: temporary) }
            try manager.createDirectory(at: contents, withIntermediateDirectories: false)
            for (name, data) in archive { try data.write(to: contents.appendingPathComponent(name)) }
            let zipped = temporary.appendingPathComponent("diagnostics.zip")
            let child = Process()
            child.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
            child.arguments = ["-c", "-k", "--norsrc", "--noextattr", "--noacl", "--keepParent", contents.path, zipped.path]
            child.standardError = FileHandle.nullDevice
            try child.run()
            child.waitUntilExit()
            guard child.terminationStatus == 0 else { throw CoreError(message: L("无法打包诊断文件。")) }
            try Data(contentsOf: zipped).write(to: destination, options: .atomic)
        }.value
    }

    private func diagnosticSummary() -> String {
        let profile = configuredProfile
        let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? L("未知")
        let backend = [profile?.backend, profile?.backendVersion].compactMap { $0 }.joined(separator: " ")
        let mode = status?.policy.mode ?? profile?.mode
        let diskVersion = profile?.revision ?? savedRevision
        var lines = [
            L("HopWay 诊断"),
            L("采集时间 · ") + Date.now.ISO8601Format(),
            "App · " + appVersion,
            L("系统 · ") + ProcessInfo.processInfo.operatingSystemVersionString,
            L("内核后端 · ") + (backend.isEmpty ? L("未知") : backend),
            L("内核 · ") + L(phase.rawValue),
            L("接入 · ") + accessLabel,
            L("出口可达 · ") + reachabilityLabel,
            L("路由模式 · ") + (mode.map(Policy.label) ?? L("未知")),
            L("磁盘配置版本 · ") + String(diskVersion.prefix(12)),
            L("节点 · <1> 个", configuredNodes.count),
            L("订阅 · <1> 份", subscriptions.count),
        ]
        if let status {
            lines.append(L("运行配置版本 · ") + (status.revision.map { String($0.prefix(12)) } ?? L("未知")))
            lines.append(L("内核代次 · <1>", status.generation))
            lines.append(L("活动连接 · <1>", status.active))
            lines.append(L("配置告警 · <1> 条", status.warnings?.count ?? 0))
            if let applied = status.reloaded {
                lines.append(L("配置应用时间 · ") + Date(timeIntervalSince1970: applied / 1000).ISO8601Format())
            }
            if let resources = status.resources {
                if let used = resources.connections, let limit = resources.connectionLimit {
                    lines.append(L("连接额度 · <1> / <2> · 拒绝 <3>", used, limit, resources.connectionsRefused ?? 0))
                }
                lines.append(L("UDP 会话 · <1> / <2>", resources.udpSessions, resources.udpSessionLimit))
                lines.append(L("UDP 建连 · <1> / <2>", resources.udpOpening, resources.udpOpenLimit))
                lines.append(L("端点拨号并发 · <1>", resources.endpointDialLimit))
                if let idle = resources.udpIdleTimeoutSec { lines.append(L("UDP 空闲回收 · <1> 秒", idle)) }
                if let used = resources.udpQueuedBytes, let limit = resources.udpQueueLimitBytes {
                    lines.append(L("UDP 暂存 · <1> / <2> B", used, limit))
                }
            }
            if let retirement = status.retirement {
                lines.append(L("旧内核回收 · 处理中 <1> · 强制关闭 <2> · 清理超时 <3>", retirement.pending, retirement.forced, retirement.slow))
            }
            if let tun = status.tun {
                lines.append(L("TUN 助手 · ") + (tun.service == true ? L("已安装") : L("未安装")))
                if let pools = tun.fakeIP {
                    lines.append(L("Fake IP IPv4 · <1> / <2> · 暂缓 <3>", pools.ipv4.mapped, pools.ipv4.capacity, pools.ipv4.refused))
                    if let ipv6 = pools.ipv6 {
                        lines.append(L("Fake IP IPv6 · <1> / <2> · 暂缓 <3>", ipv6.mapped, ipv6.capacity, ipv6.refused))
                    }
                }
                if let dns = tun.dns {
                    lines.append(L("TUN DNS · 转发时限 <1> 毫秒 · 例外 <2> 条 · 嗅探 <3>", dns.timeoutMs, dns.exceptionCount, dns.sniffingEnabled ? L("开启") : L("关闭")))
                }
            }
            for (name, drops) in (status.udpDrops ?? [:]).sorted(by: { $0.key < $1.key }) {
                lines.append("UDP \(name) · \(drops.detail)")
            }
        }
        return lines.joined(separator: "\n")
    }

    struct RouteDecision: Decodable {
        let rule: String
        let path: [String]?
        let outbound: String
    }

    func explainRoute(_ host: String) async throws -> RouteDecision {
        guard let info = endpoint else { throw CoreError(message: L("请先启动内核。")) }
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
        guard let target = url?.url else { throw CoreError(message: L("地址无效。")) }
        var request = URLRequest(url: target)
        request.setValue("Bearer " + info.token, forHTTPHeaderField: "Authorization")
        let (data, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw CoreError(message: L("请输入域名、IP 或主机与端口。"))
        }
        return try JSONDecoder().decode(RouteDecision.self, from: data)
    }

    private func cancelStatusRequest() {
        statusRequest?.cancel()
        statusRequest = nil
        statusRequestedAgain = false
        cancelConnectionRequest()
    }

    func watchConnections(_ enabled: Bool) {
        watchingConnections = enabled
        if enabled {
            if let info = endpoint { Task { await refresh(info) } }
        } else {
            cancelConnectionRequest()
        }
    }

    private func cancelConnectionRequest() {
        connectionRequest?.cancel()
        connectionRequest = nil
    }

    private func isRunning(_ info: Endpoint) -> Bool {
        !Task.isCancelled && phase == .running && endpoint?.token == info.token
    }

    private func refresh(_ info: Endpoint, followUp: Bool = true) async {
        guard isRunning(info) else { return }
        if let statusRequest {
            statusRequestedAgain = statusRequestedAgain || followUp
            await statusRequest.value
            return
        }
        let request = Task { [weak self] in
            guard let self, isRunning(info) else { return }
            repeat {
                statusRequestedAgain = false
                await readStatus(info)
            } while statusRequestedAgain && isRunning(info)
            if isRunning(info) { statusRequest = nil }
        }
        statusRequest = request
        await request.value
    }

    private func readStatus(_ info: Endpoint) async {
        do {
            let data = try await call(info, path: "status", query: [URLQueryItem(name: "view", value: "compact")])
            guard isRunning(info) else { return }
            let snapshot = try JSONDecoder().decode(ProxyStatus.self, from: data)
            let before = status?.subscriptions?.map { [$0.updated, $0.usage.map { Double($0.updatedAt) }] }
            statusReadAt = .now
            clearStatusFailure()
            let generationChanged = status?.generation != snapshot.generation
            if generationChanged {
                cancelConnectionRequest()
                connectionRecords.removeAll()
                connectionCursor = nil
                connectionReadAt = nil
                connectionReadFailed = false
            }
            if status != snapshot { status = snapshot }
            scheduleVerification(info, status: snapshot)
            updateTrafficRate(snapshot.sessionTraffic)
            if generationChanged || before != snapshot.subscriptions?.map({ [$0.updated, $0.usage.map { Double($0.updatedAt) }] }) {
                reloadConfiguredNodes()
            }
            reloadTraffic()
            let warnings = snapshot.warnings ?? []
            if warnings.isEmpty {
                presentedWarnings = []
            } else if message == nil && warnings != presentedWarnings {
                presentedWarnings = warnings
                message = warnings.joined(separator: "；")
            }
            if message == nil, status?.systemProxy?.recovered == true, !announcedRecovery {
                announcedRecovery = true
                message = L("上次异常退出时留下的系统代理设置已自动还原。")
            }
            requestConnectionFeed(info, generation: snapshot.generation)
        } catch {
            guard isRunning(info) else { return }
            if !statusReadFailed {
                statusReadFailed = true
                resetVerification()
            }
            updateTrafficRate(nil)
            let failure = L("读取内核状态失败 · ") + error.localizedDescription
            if message == nil || message == statusFailureMessage { message = failure }
            statusFailureMessage = failure
        }
    }

    private func requestConnectionFeed(_ info: Endpoint, generation: UInt64) {
        guard watchingConnections, connectionRequest == nil else { return }
        connectionRequest = Task { [weak self] in
            await self?.readConnectionFeed(info, generation: generation)
            if !Task.isCancelled { self?.connectionRequest = nil }
        }
    }

    private func readConnectionFeed(_ info: Endpoint, generation: UInt64) async {
        guard isRunning(info), watchingConnections else { return }
        let query: [URLQueryItem] = connectionCursor.map { cursor in
            [URLQueryItem(name: "generation", value: String(generation)),
             URLQueryItem(name: "cursor", value: String(cursor))]
        } ?? []
        do {
            let data = try await call(info, path: "connections", query: query)
            guard isRunning(info), watchingConnections else { return }
            let update = try JSONDecoder().decode(ConnectionUpdate.self, from: data)
            guard update.generation == generation else { return }
            connectionReadAt = .now
            if connectionReadFailed { connectionReadFailed = false }
            connectionCursor = update.cursor
            if update.full == true || update.records != nil || update.counters != nil || update.removed != nil {
                objectWillChange.send()
                if update.full == true { connectionRecords.removeAll(keepingCapacity: true) }
                for id in update.removed ?? [] { connectionRecords.removeValue(forKey: id) }
                for row in update.records ?? [] { connectionRecords[row.id] = row }
                for counters in update.counters ?? [] {
                    if var row = connectionRecords[counters.id] {
                        row.sent = Int64(clamping: counters.sent)
                        row.received = Int64(clamping: counters.received)
                        row.firstByteMs = counters.firstByteMs
                        connectionRecords[row.id] = row
                    }
                }
            }
        } catch {
            if isRunning(info), watchingConnections, !connectionReadFailed { connectionReadFailed = true }
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
                reloadConfiguredNodes()
                await refresh(info)
            } catch {
                if endpoint?.token == info.token { message = error.localizedDescription }
            }
        }
    }

    /// Goes back one manual outbound change. The engine keeps only the latest
    /// snapshot, so a second undo has nothing to restore.
    func undoRoute() {
        guard let info = endpoint, !updatingPolicy else { return }
        updatingPolicy = true
        message = nil
        Task {
            defer { if endpoint?.token == info.token { updatingPolicy = false } }
            do {
                _ = try await call(info, path: "undo", method: "POST")
                await refresh(info)
                message = L("已撤销上一次出站切换。")
            } catch {
                if endpoint?.token == info.token { message = error.localizedDescription }
            }
        }
    }

    func selectRoutingPreset(_ mode: String, fallbackGroup: String? = nil) {
        guard !saving, !updatingPolicy else { return }
        if phase == .running, let status, !statusReadFailed {
            let selected = fallbackGroup ?? (mode == "direct" ? "DIRECT" : status.policy.selected)
            updatePolicy(Policy(mode: mode, selected: selected))
        } else if phase == .stopped, let executable {
            saving = true
            message = nil
            let destination = configURL
            Task {
                defer { saving = false }
                do {
                    _ = try await Task.detached {
                        try Self.runProfileCommand("-save-desktop-mode=" + mode, at: destination,
                                                   executable: executable, desktopSelected: fallbackGroup)
                    }.value
                    message = L("下次启动使用「<1>」。", fallbackGroup.map(groupLabel) ?? Policy.label(mode))
                    reloadConfiguredNodes()
                } catch {
                    message = L("保存策略预设失败 · ") + error.localizedDescription
                }
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
                if endpoint?.token == info.token { message = L("系统代理设置失败 · ") + error.localizedDescription }
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
        case "enable": status?.tun?.service == true ? L("正在开启增强模式…") : L("正在开启增强模式，如有系统弹窗请完成授权。")
        case "disable": L("正在关闭增强模式…")
        case "install-helper": L("正在安装 TUN 助手，请在系统弹窗中完成授权。")
        case "remove-helper": L("正在移除 TUN 助手，请在系统弹窗中完成授权。")
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
                    message = L("增强模式操作失败 · ") + error.localizedDescription
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
                if endpoint?.token == info.token { message = L("切换失败 · ") + error.localizedDescription }
            }
        }
    }

    /// Starts a background request (probe, refresh) and re-reads status shortly after.
    func trigger(_ path: String, done text: String) {
        guard let info = endpoint else { return }
        if path.hasSuffix("/refresh") {
            runControlRefresh(path, info: info, text: text)
            return
        }
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

    private struct RefreshReceipt: Decodable {
        let succeeded: Int
        let failed: Int
        let canceled: Bool
    }

    private func runControlRefresh(_ path: String, info: Endpoint, text: String) {
        guard refreshTask == nil, phase == .running,
              var url = URLComponents(url: info.control.appendingPathComponent(path), resolvingAgainstBaseURL: false) else { return }
        url.queryItems = [URLQueryItem(name: "wait", value: "1")]
        guard let target = url.url else { return }
        let id = UUID()
        refreshID = id
        refreshing = true
        message = text
        refreshTask = Task {
            defer {
                if refreshID == id { cancelControlRefresh() }
            }
            do {
                var request = URLRequest(url: target)
                request.httpMethod = "POST"
                request.timeoutInterval = 20
                request.setValue("Bearer " + info.token, forHTTPHeaderField: "Authorization")
                let (bytes, response) = try await session.bytes(for: request)
                guard (response as? HTTPURLResponse)?.statusCode == 200 else {
                    throw CoreError(message: L("内核未接受刷新请求。"))
                }
                for try await line in bytes.lines where !line.isEmpty {
                    let receipt = try JSONDecoder().decode(RefreshReceipt.self, from: Data(line.utf8))
                    guard refreshID == id, isRunning(info) else { return }
                    await refresh(info)
                    guard refreshID == id, isRunning(info) else { return }
                    message = receipt.canceled ? L("刷新已中止。") : L("已刷新 <1> 项 · <2> 项失败", receipt.succeeded, receipt.failed)
                    return
                }
                throw CoreError(message: L("刷新连接在返回结果前断开。"))
            } catch {
                if refreshID == id, isRunning(info) { message = L("刷新失败 · ") + error.localizedDescription }
            }
        }
    }

    func cancelRefresh() {
        cancelControlRefresh()
        message = L("刷新已取消。")
    }

    private func cancelControlRefresh() {
        refreshID = nil
        refreshTask?.cancel()
        refreshTask = nil
        if refreshing { refreshing = false }
    }

    func groupLabel(_ name: String) -> String {
        configuredProfile?.groupAliases?[name] ?? name
    }

    /// "HK 01 · 83 ms" for a node, or the display name of a nested group.
    func memberLabel(_ name: String) -> String {
        if let alias = configuredProfile?.groupAliases?[name] { return alias }
        return status?.nodes.first(where: { $0.name == name })?.label ?? name
    }

    var canEditPolicyGroups: Bool {
        !saving && !changed && !configurationConflict && !profileReadFailed && configuredProfile != nil &&
        (phase == .stopped || (phase == .running && !statusReadFailed && status != nil))
    }

    func policyGroupNameError(_ name: String) -> String? {
        if name.isEmpty { return L("请输入策略组名称。") }
        if name.count > 80 { return L("名称最多 80 个字符。") }
        let names = (configuredProfile?.outboundIds?.keys.map { $0 } ?? []) +
            (configuredProfile?.groupAliases?.values.map { $0 } ?? []) + ["SELECT", "AUTO"]
        if names.contains(where: { $0.caseInsensitiveCompare(name) == .orderedSame }) {
            return L("这个名称已在使用，请换一个。")
        }
        return nil
    }

    func createPolicyGroup(name: String, type: String, members: [String], basedOn source: String) {
        guard canEditPolicyGroups, source == saved, policyGroupNameError(name) == nil, !members.isEmpty,
              let ids = configuredProfile?.outboundIds, members.allSatisfy({ ids[$0] != nil }),
              var config = (try? JSONSerialization.jsonObject(with: Data(source.utf8))) as? [String: Any] else {
            message = L("策略配置已有更新，请重新打开后再试。")
            return
        }
        var groups = config["groups"] as? [[String: Any]] ?? []
        groups.append(["name": name, "type": type, "members": members])
        config["groups"] = groups
        savePolicyGroups(config, basedOn: source)
    }

    func policyGroupDeletionBlock(_ name: String) -> String? {
        guard let profile = configuredProfile, profile.localGroups?.contains(name) == true else {
            return L("此组由订阅管理，可编辑显示名称与线路。")
        }
        if profile.selected == name || status?.policy.selected == name {
            return L("该组是当前或启动出站，请先切换出站。")
        }
        if let count = profile.groupRuleRefs?[name], count > 0 {
            return L("还有 <1> 条规则指向此组，请先修改规则。", count)
        }
        if profile.groups?.contains(where: { $0.name != name && $0.members.contains(name) }) == true ||
            status?.groups?.contains(where: { $0.name != name && $0.members.contains(name) }) == true {
            return L("其他策略组仍使用此组，请先移除引用。")
        }
        return nil
    }

    func deletePolicyGroup(_ name: String, basedOn source: String) {
        guard canEditPolicyGroups, !updatingPolicy, source == saved, policyGroupDeletionBlock(name) == nil,
              var config = (try? JSONSerialization.jsonObject(with: Data(source.utf8))) as? [String: Any],
              var groups = config["groups"] as? [[String: Any]],
              let index = groups.firstIndex(where: { $0["name"] as? String == name }),
              let id = configuredProfile?.outboundIds?[name] else {
            message = L("无法删除策略组，请检查配置和引用后再试。")
            return
        }
        guard config["selected"] as? String != name else {
            message = L("高级配置的默认出站仍引用此组，请先修改 selected。")
            return
        }
        groups.remove(at: index)
        config["groups"] = groups.isEmpty ? nil : groups
        var aliases = config["groupAliases"] as? [String: String] ?? [:]
        aliases.removeValue(forKey: id)
        config["groupAliases"] = aliases.isEmpty ? nil : aliases
        var members = config["groupMembers"] as? [String: [String]] ?? [:]
        members.removeValue(forKey: id)
        config["groupMembers"] = members.isEmpty ? nil : members
        savePolicyGroups(config, basedOn: source)
    }

    private func savePolicyGroups(_ config: [String: Any], basedOn source: String) {
        do {
            let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
            saveAdvanced(String(decoding: data, as: UTF8.self), basedOn: source, activation: nil)
        } catch {
            message = error.localizedDescription
        }
    }

    func renameSubscription(_ id: String, to name: String) {
        let alias = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard alias.count <= 80 else {
            message = L("订阅名称最多 80 个字符。")
            return
        }
        updateSubscription(id, success: alias.isEmpty ? L("已恢复默认订阅名称。") : L("订阅名称已更新。")) { records, index, _ in
            records[index]["alias"] = alias.isEmpty ? nil : alias
        }
    }

    func pauseSubscription(_ id: String, paused: Bool) {
        updateSubscription(id, success: paused ? L("订阅已暂停。") : L("订阅已恢复。")) { records, index, _ in
            records[index]["paused"] = paused ? true : nil
        }
    }

    func removeSubscription(_ id: String) {
        updateSubscription(id, success: L("订阅已移除。")) { records, index, config in
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
            message = L("请先保存配置草稿，再修改订阅。")
            return
        }
        let originalName = subscriptions.first(where: { $0.id == id })?.originalName
        guard var config = (try? JSONSerialization.jsonObject(with: Data(saved.utf8))) as? [String: Any],
              var records = config["subscriptions"] as? [[String: Any]],
              let index = records.firstIndex(where: {
                  ($0["id"] as? String) == id ||
                  ($0["id"] == nil && $0["name"] as? String == originalName)
              }) else {
            message = L("找不到这份订阅，请刷新列表后重试。")
            return
        }
        edit(&records, index, &config)
        config["subscriptions"] = records
        guard let json = try? JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]) else {
            message = L("无法保存订阅。")
            return
        }
        let text = String(decoding: json, as: UTF8.self)
        let destination = configURL
        let expected = savedRevision
        saving = true
        Task {
            defer { saving = false }
            do {
                let revision = try await Task.detached {
                    try Self.validateAndSave(text, to: destination, expected: expected, with: executable)
                }.value
                acceptSavedConfiguration(text, revision: revision)
                let applied = phase == .running ? " " + (await applyRunning()) : ""
                message = success + applied
            } catch {
                writeFailed(error, prefix: L("无法保存订阅 · "))
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
        let rate = TrafficRate(
            upload: Double(totals.upload - last.totals.upload) / seconds,
            download: Double(totals.download - last.totals.download) / seconds
        )
        if liveTraffic != rate { liveTraffic = rate }
        lastTrafficSample = (totals, now)
    }

    private func reloadTraffic() {
        guard trafficReadTask == nil else { return }
        let url = trafficURL
        let previous = trafficStamp
        trafficReadTask = Task { [weak self] in
            let result = await Task.detached { () -> (TrafficHistory.DiskStamp, TrafficHistory)? in
                let stamp = TrafficHistory.stamp(at: url)
                guard stamp != previous, let history = TrafficHistory.load(at: url) else { return nil }
                return (stamp, history)
            }.value
            guard let self else { return }
            trafficReadTask = nil
            if let (stamp, history) = result {
                trafficStamp = stamp
                trafficHistory = history
            }
        }
    }

    private func retryUnavailableNodes() {
        let now = Date()
        guard probeTask == nil, !saving,
              lastRecoveryAttempt.map({ now.timeIntervalSince($0) >= 120 }) ?? true else { return }
        let names = configuredNodes.filter { (probeFailures[$0.probeIdentity] ?? 0) > 0 }.map(\.name)
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
            child.arguments = ["-probe", "-watch-stdin", "-config", configURL.path]
            if !all {
                for name in names { child.arguments?.append(contentsOf: ["-probe-node", name]) }
            }
            let output = Pipe()
            let lifetime = Pipe()
            child.standardInput = lifetime
            child.standardOutput = output
            child.standardError = FileHandle.nullDevice
            do {
                try child.run()
            } catch {
                message = L("无法启动测速 · ") + error.localizedDescription
                return
            }
            probeProcess = child
            probeInput = lifetime.fileHandleForWriting
            offline = (child, output.fileHandleForReading)
        }
        let requested = Set(names)
        let keys = Dictionary(uniqueKeysWithValues: configuredNodes.filter { requested.contains($0.name) }
            .map { ($0.name, $0.probeIdentity) })
        let id = UUID()
        probeID = id
        probePending = Set(keys.values)
        probeTotal = probePending.count
        if showSummary { message = nil }
        probeTask = Task {
            var available = 0
            var inconclusive = 0
            var interrupted = false
            @MainActor func receive(_ sample: NodeProbeResult) {
                var result = sample
                let key = result.probeKey ?? "legacy:" + result.name
                guard keys[result.name] == key, probePending.remove(key) != nil else { return }
                if !result.isAvailable, let previous = probeResults[key] {
                    result.lastKnownLatency = previous.isAvailable ? previous.milliseconds : previous.lastKnownLatency
                }
                probeResults[key] = result
                if result.isAvailable {
                    available += 1
                    probeFailures.removeValue(forKey: key)
                    hiddenNodes.remove(key)
                } else if result.isFailure {
                    let failures = min(2, (probeFailures[key] ?? 0) + 1)
                    probeFailures[key] = failures
                    if failures == 2 { hiddenNodes.insert(key) }
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
                        throw CoreError(message: L("运行中的内核未接受测速请求。"))
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
                    message = L("测速未完整结束 · 已完成 <1>/<2>，剩余 <3> 个。", completed, probeTotal, remaining)
                } else {
                    let failed = completed - available - inconclusive
                    let uncertain = inconclusive == 0 ? "" : L("，<1> 个待复测", inconclusive)
                    message = L("测速完成 · <1> 个节点，<2> 个可用，<3> 个失败或超时<4>。", completed, available, failed, uncertain)
                }
            }
            probeTask = nil
            probeProcess = nil
            try? probeInput?.close()
            probeInput = nil
            probeID = nil
            probePending = []
            probeTotal = 0
        }
    }

    func cancelProbe() {
        probeID = nil
        probeTask?.cancel()
        probeTask = nil
        try? probeInput?.close()
        probeInput = nil
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
                        throw CoreError(message: L("测速进程退出。"))
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
                let keys = Set(configuredNodes.map(\.probeIdentity))
                hiddenNodes.formIntersection(keys)
                probeResults = probeResults.filter { keys.contains($0.key) }
                probeFailures = probeFailures.filter { keys.contains($0.key) }
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
            trigger(path, done: L("正在刷新订阅…"))
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
                message = L("已刷新 <1> 份订阅 · <2> 份失败", result["updated"] ?? 0, result["failed"] ?? 0)
                reloadConfiguredNodes()
            } catch {
                message = L("刷新失败 · ") + error.localizedDescription
            }
        }
    }

    nonisolated private static func runProfileCommand(_ flag: String, at destination: URL, executable: URL, subscriptionID: String? = nil, desktopSelected: String? = nil) throws -> Data {
        let child = Process()
        let output = Pipe()
        child.executableURL = executable
        child.arguments = [flag, "-config", destination.path]
        if flag == "-inspect" { child.arguments?.append("-desktop-routing") }
        if let subscriptionID { child.arguments?.append(contentsOf: ["-subscription-id", subscriptionID]) }
        if let desktopSelected { child.arguments?.append(contentsOf: ["-desktop-selected", desktopSelected]) }
        let lifetime = flag == "-refresh-subscriptions" ? Pipe() : nil
        if let lifetime {
            child.arguments?.append("-watch-stdin")
            child.standardInput = lifetime
        }
        defer { try? lifetime?.fileHandleForWriting.close() }
        child.standardOutput = output
        child.standardError = FileHandle.nullDevice
        try child.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        child.waitUntilExit()
        guard child.terminationStatus == 0 else { throw CoreError(message: L("内核命令失败。")) }
        return data
    }

    func importClipboard() {
        importContent(NSPasteboard.general.string(forType: .string) ?? "")
    }

    func importContent(_ raw: String) {
        guard !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            message = L("请先复制订阅地址、节点链接或 Clash 配置。")
            return
        }
        _ = commitImport(Data(raw.utf8), prepared: false, basedOn: savedRevision)
    }

    func confirmImport(_ preview: ImportPreview) -> Bool {
        commitImport(preview.snapshot, prepared: true, basedOn: preview.revision)
    }

    private func commitImport(_ input: Data, prepared: Bool, basedOn expected: String) -> Bool {
        guard !saving, let executable else { return false }
        guard !changed else {
            message = L("请先保存配置草稿，再导入节点。")
            return false
        }
        guard savedRevision == expected else {
            message = L("配置已更新，请重新预览导入。")
            return false
        }
        saving = true
        message = prepared ? L("正在保存已预览的配置…") : L("正在识别并导入…")
        let destination = configURL
        Task {
            defer { saving = false }
            do {
                let receipt = try await Task.detached {
                    let data = try Self.runProfileInput(input, mode: prepared ? "-commit-prepared-import" : "-commit-import",
                                                        at: destination, expected: prepared ? nil : expected, with: executable)
                    return try JSONDecoder().decode(ImportReceipt.self, from: data)
                }.value
                acceptSavedConfiguration(receipt.text, revision: receipt.revision)
                importCount += 1
                var next = L("启动后可在概览切换出站。")
                if phase == .running {
                    next = await applyRunning()
                }
                let summary = [L("已导入 <1> 个节点，跳过 <2> 个。", receipt.added, receipt.skipped)] + (receipt.notes ?? [])
                message = (summary + [next]).joined(separator: " ")
            } catch {
                writeFailed(error, prefix: L("导入失败 · "))
            }
        }
        return true
    }

    struct ImportPreview {
        let added: Int
        let skipped: Int
        let notes: [String]
        fileprivate let snapshot: Data
        fileprivate let revision: String
    }

    private struct ImportPreviewEnvelope: Decodable {
        struct Result: Decodable {
            let added: Int
            let skipped: Int
            let notes: [String]?
        }
        let result: Result
        let revision: String
    }

    private struct ImportReceipt: Decodable {
        let text: String
        let revision: String
        let added: Int
        let skipped: Int
        let notes: [String]?
    }

    func previewImport(_ raw: String) async throws -> ImportPreview {
        guard let executable, !changed else {
            throw CoreError(message: L("请先保存配置草稿，再预览导入。"))
        }
        let destination = configURL
        let expected = savedRevision
        let data = try await Task.detached {
            try Self.runProfileInput(Data(raw.utf8), mode: "-prepare-import", at: destination, expected: expected, with: executable)
        }.value
        let envelope = try JSONDecoder().decode(ImportPreviewEnvelope.self, from: data)
        guard !changed, savedRevision == expected, envelope.revision == expected else { throw ProfileWriteConflict() }
        return ImportPreview(added: envelope.result.added, skipped: envelope.result.skipped,
                             notes: envelope.result.notes ?? [], snapshot: data, revision: expected)
    }

    nonisolated private static func runProfileInput(_ input: Data, mode: String, at destination: URL,
                                                     expected: String? = nil, with executable: URL) throws -> Data {
        if mode == "-commit-prepared-import" {
            guard input.count <= 16 * 1_048_576 else { throw CoreError(message: L("预览后的导入数据超过 16 MB。")) }
        } else {
            guard input.count <= 1_048_576 else { throw CoreError(message: L("输入上限为 1 MB。")) }
        }
        let files = FileManager.default
        let directory = files.temporaryDirectory.appendingPathComponent("hopway-" + UUID().uuidString)
        try files.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? files.removeItem(at: directory) }
        let source = directory.appendingPathComponent("input")
        guard files.createFile(atPath: source.path, contents: input, attributes: [.posixPermissions: 0o600]) else {
            throw CoreError(message: L("无法暂存配置内容。"))
        }
        let output = Pipe()
        let lifetime = Pipe()
        defer { try? lifetime.fileHandleForWriting.close() }
        let child = Process()
        child.executableURL = executable
        // Always name the config path, even before the file exists: the core
        // keeps subscription caches next to it.
        child.arguments = [mode, "-config", destination.path, "-input-file", source.path, "-watch-stdin"]
        if let expected { child.arguments?.append(contentsOf: ["-expected-revision", expected]) }
        child.standardInput = lifetime
        child.standardOutput = output
        child.standardError = output
        try child.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        child.waitUntilExit()
        if child.terminationStatus == 3 { throw ProfileWriteConflict() }
        guard child.terminationStatus == 0 else {
            let explanation = String(decoding: data.prefix(2048), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            throw CoreError(message: explanation.isEmpty ? L("内核无法处理配置。") : explanation)
        }
        return data
    }

    func importDraft() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            guard let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= 1_048_576 else {
                throw CoreError(message: L("配置文件上限为 1 MB。"))
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
                throw CoreError(message: L("请先将草稿修正为 JSON 对象，nodes 应为数组。"))
            }
            var nodes = object["nodes"] as? [[String: Any]] ?? []
            var name = type
            var index = 1
            while nodes.contains(where: { $0["name"] as? String == name }) {
                index += 1
                name = "\(type)-\(index)"
            }
            var node = ["name": name, "type": type, "server": "proxy.example.com:443"]
            if type == "trojan" || type == "shadowsocks" { node["password"] = L("替换为节点密码") }
            if type == "shadowsocks" { node["cipher"] = "aes-128-gcm" }
            if type == "vless" || type == "vmess" { node["uuid"] = L("替换为节点 UUID") }
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

    func saveAdvanced(_ candidate: String, basedOn source: String, activation: String?) {
        guard !changed, saved == source else {
            message = L("配置已有更新，请重新打开高级配置后再保存。")
            return
        }
        saveConfiguration(candidate, activation: activation)
    }

    private func saveConfiguration(_ candidate: String, activation: String? = nil) {
        guard !saving, let executable else { return }
        saving = true
        message = nil
        let destination = configURL
        let expected = savedRevision
        Task {
            defer { saving = false }
            do {
                let revision = try await Task.detached {
                    try Self.validateAndSave(candidate, to: destination, expected: expected, with: executable)
                }.value
                acceptSavedConfiguration(candidate, revision: revision)
                if phase == .running {
                    if let activation {
                        let applied = await applyRunning()
                        message = applied == L("已生效，无需重启。") ? L("配置已保存。<1>", activation) : L("配置已保存，<1>", applied)
                        if configurationNotice == nil { configurationNotice = activation }
                    } else {
                        message = L("配置已保存，") + (await applyRunning())
                    }
                } else {
                    message = L("配置已保存。")
                }
            } catch {
                writeFailed(error)
            }
        }
    }

    nonisolated private static func validateAndSave(_ text: String, to destination: URL,
                                                    expected: String, with executable: URL) throws -> String {
        let data = try runProfileInput(Data(text.utf8), mode: "-save-config", at: destination, expected: expected, with: executable)
        let receipt = try JSONDecoder().decode([String: String].self, from: data)
        guard let revision = receipt["revision"] else { throw CoreError(message: L("无法读取保存后的配置版本。")) }
        return revision
    }
}
