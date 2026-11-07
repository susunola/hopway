import Foundation

struct NodeLocation {
    let title: String
    let flag: String?

    var isSubscriptionNotice: Bool {
        ["剩余流量", "剩餘流量", "套餐到期", "到期时间", "距离下次重置", "如果只显示当前节点", "请更新客户端", "轻语机场官网"]
            .contains { title.hasPrefix($0) }
    }

    var regionCode: String? {
        guard !isSubscriptionNotice else { return nil }
        return flag.map { value in
            String(String.UnicodeScalarView(value.unicodeScalars.compactMap {
                UnicodeScalar($0.value - 0x1F1E6 + 65)
            }))
        }
    }

    init(name: String) {
        if let embedded = name.first(where: Self.isFlag) {
            flag = String(embedded)
            if name.first == embedded {
                let remainder = name.dropFirst().trimmingCharacters(in: .whitespacesAndNewlines)
                title = remainder.isEmpty ? name : remainder
            } else {
                title = name
            }
            return
        }
        title = name
        let candidates = Self.regions.flatMap { region in
            region.aliases.compactMap { alias -> (start: String.Index, length: Int, code: String)? in
                guard let range = name.range(of: alias, options: .caseInsensitive) else { return nil }
                return (range.lowerBound, alias.count, region.code)
            }
        }
        if let code = candidates.min(by: {
            $0.start == $1.start ? $0.length > $1.length : $0.start < $1.start
        })?.code {
            flag = Self.flag(for: code)
        } else if let token = name.range(of: #"(?<![\p{L}0-9])(?:HK|TW|MO|JP|SG|US|KR|GB|UK|DE|FR|CA|AU|NL|IN|MY|TH|VN|PH|ID|RU|TR|AE|CN)(?![A-Za-z0-9])"#, options: .regularExpression) {
            let code = String(name[token])
            flag = Self.flag(for: code == "UK" ? "GB" : code)
        } else {
            flag = nil
        }
    }

    private static func isFlag(_ character: Character) -> Bool {
        character.unicodeScalars.count == 2 &&
            character.unicodeScalars.allSatisfy { (0x1F1E6...0x1F1FF).contains($0.value) }
    }

    private static func flag(for code: String) -> String {
        String(String.UnicodeScalarView(code.unicodeScalars.compactMap { UnicodeScalar($0.value - 65 + 0x1F1E6) }))
    }

    private static let regions: [(code: String, aliases: [String])] = [
        ("HK", ["香港", "Hong Kong"]), ("TW", ["台湾", "臺灣", "台灣", "Taiwan"]),
        ("MO", ["澳门", "澳門", "Macau"]), ("JP", ["日本", "东京", "東京", "大阪", "Japan", "Tokyo", "Osaka"]),
        ("SG", ["新加坡", "狮城", "獅城", "Singapore"]), ("US", ["美国", "美國", "洛杉矶", "纽约", "United States", "Los Angeles", "New York"]),
        ("KR", ["韩国", "韓國", "首尔", "首爾", "Korea", "Seoul"]), ("GB", ["英国", "英國", "伦敦", "倫敦", "United Kingdom", "London"]),
        ("DE", ["德国", "德國", "法兰克福", "Germany", "Frankfurt"]), ("FR", ["法国", "法國", "巴黎", "France", "Paris"]),
        ("CA", ["加拿大", "多伦多", "Canada", "Toronto"]), ("AU", ["澳大利亚", "澳大利亞", "澳洲", "悉尼", "Australia", "Sydney"]),
        ("NL", ["荷兰", "荷蘭", "Netherlands", "Amsterdam"]), ("IN", ["印度", "India", "Mumbai"]),
        ("MY", ["马来西亚", "馬來西亞", "Malaysia"]), ("TH", ["泰国", "泰國", "曼谷", "Thailand", "Bangkok"]),
        ("VN", ["越南", "Vietnam"]), ("PH", ["菲律宾", "菲律賓", "Philippines"]),
        ("ID", ["印度尼西亚", "印尼", "Indonesia"]), ("RU", ["俄罗斯", "俄羅斯", "Russia"]),
        ("TR", ["土耳其", "Türkiye", "Turkey"]), ("AE", ["阿联酋", "阿聯酋", "迪拜", "Dubai"]),
        ("CN", ["中国大陆", "中國大陸", "中国", "中國", "China"])
    ]
}
