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
}

struct ProxyStatus: Decodable {
    struct Node: Decodable, Identifiable {
        let name: String
        let type: String
        var id: String { name }
    }

    struct Connection: Decodable, Identifiable {
        let id: UInt64
        let inbound: String
        let target: String
        let via: String
        let rule: String
        let state: String
        let sent: Int64
        let received: Int64
        let error: String?

        var stateLabel: String {
            switch state {
            case "active": "传输中"
            case "closed": "已结束"
            case "blocked": "已拦截"
            default: "失败"
            }
        }
    }

    let policy: Policy
    let nodes: [Node]
    let connections: [Connection]
    let active: Int
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
    @Published private(set) var message: String?
    @Published private(set) var saving = false
    @Published private(set) var updatingPolicy = false
    @Published var draft = ""
    @Published private(set) var saved = ""

    private var process: Process?
    private var input: FileHandle?
    private var polling: Task<Void, Never>?
    private var session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [
            "HTTPEnable": 0, "HTTPSEnable": 0, "SOCKSEnable": 0, "ProxyAutoConfigEnable": 0
        ]
        configuration.timeoutIntervalForRequest = 3
        return URLSession(configuration: configuration)
    }()

    private let configURL: URL
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
    }

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

    private func start() {
        guard !saving, let executable else {
            if self.executable == nil { message = "App 内缺少代理内核。" }
            return
        }
        message = nil
        phase = .starting
        let child = Process()
        child.executableURL = executable
        child.arguments = ["-managed"]
        if FileManager.default.fileExists(atPath: configURL.path) {
            child.arguments?.append(contentsOf: ["-config", configURL.path])
        }
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
                phase = .running
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
        phase = .stopping
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
        status = nil
        updatingPolicy = false
        phase = .stopped
    }

    private func call(_ info: Endpoint, path: String, method: String = "GET", body: Data? = nil) async throws -> Data {
        var request = URLRequest(url: info.control.appendingPathComponent(path))
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

    private func refresh(_ info: Endpoint) async {
        do {
            let data = try await call(info, path: "status")
            guard endpoint?.token == info.token else { return }
            status = try JSONDecoder().decode(ProxyStatus.self, from: data)
        } catch {
            guard !Task.isCancelled, endpoint?.token == info.token else { return }
            message = "读取内核状态失败 · " + error.localizedDescription
        }
    }

    func updatePolicy(_ policy: Policy) {
        guard let info = endpoint, !updatingPolicy else { return }
        updatingPolicy = true
        message = nil
        Task {
            defer { if endpoint?.token == info.token { updatingPolicy = false } }
            do {
                _ = try await call(info, path: "policy", method: "PUT", body: JSONEncoder().encode(policy))
                await refresh(info)
            } catch {
                if endpoint?.token == info.token { message = error.localizedDescription }
            }
        }
    }

    func importClipboard() {
        guard !saving, let executable else { return }
        guard !changed else {
            message = "请先保存配置草稿，再导入节点。"
            return
        }
        guard let raw = NSPasteboard.general.string(forType: .string),
              !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
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
                let next = phase == .running ? "重启内核后生效。" : "启动后可在概览切换出站。"
                message = summary + " " + next
            } catch {
                message = "导入失败 · " + error.localizedDescription
            }
        }
    }

    nonisolated private static func convertAndSave(_ raw: String, to destination: URL, with executable: URL) throws -> (String, String) {
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
        child.arguments = ["-import"]
        if files.fileExists(atPath: destination.path) {
            child.arguments?.append(contentsOf: ["-config", destination.path])
        }
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
        guard !saving, let executable else { return }
        saving = true
        message = nil
        let candidate = draft
        let destination = configURL
        Task {
            defer { saving = false }
            do {
                try await Task.detached { try Self.validateAndSave(candidate, to: destination, with: executable) }.value
                saved = candidate
                message = phase == .running ? "配置已保存。重启内核后生效。" : "配置已保存。"
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
