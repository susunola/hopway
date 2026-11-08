import Foundation

enum HopLanguage: String, CaseIterable {
    case chinese = "zh-Hans"
    case english = "en"

    static let key = "HopWayInterfaceLanguage"

    var title: String {
        switch self {
        case .chinese: "简体中文"
        case .english: "English"
        }
    }

    static var current: Self {
        UserDefaults.standard.string(forKey: key).flatMap(Self.init(rawValue:)) ?? .chinese
    }
}

private let englishBundle = Bundle.main.path(forResource: "en", ofType: "lproj")
    .flatMap(Bundle.init(path:))
private let localizationToken = try! NSRegularExpression(pattern: "<([1-9][0-9]*)>")

func L(_ key: String, _ arguments: Any...) -> String {
    let template = HopLanguage.current == .english ? englishBundle?.localizedString(forKey: key, value: key, table: nil) ?? key : key
    guard !arguments.isEmpty else { return template }
    let source = template as NSString
    let matches = localizationToken.matches(in: template, range: NSRange(location: 0, length: source.length))
    let rendered = NSMutableString(string: template)
    for match in matches.reversed() {
        guard let index = Int(source.substring(with: match.range(at: 1))), arguments.indices.contains(index - 1) else { continue }
        rendered.replaceCharacters(in: match.range, with: String(describing: arguments[index - 1]))
    }
    return rendered as String
}
