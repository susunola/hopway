import AppKit
import SwiftUI

enum HopAppearance {
    static let accent = Color(nsColor: NSColor(name: nil) { appearance in
        if appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua {
            return NSColor(srgbRed: 0.36, green: 0.91, blue: 0.73, alpha: 1)
        }
        return NSColor(srgbRed: 0.02, green: 0.40, blue: 0.33, alpha: 1)
    })
    static let mint = Color(red: 0.49, green: 0.97, blue: 0.82)
    static let navy = Color(red: 0.04, green: 0.10, blue: 0.16)
}

struct HopPageHeading: View {
    let title: String
    let detail: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.system(size: 27, weight: .semibold))
                .accessibilityAddTraits(.isHeader)
            Text(detail).font(.callout).foregroundStyle(.secondary)
        }
    }
}

struct HopSearchField: View {
    let placeholder: String
    @Binding var text: String

    var body: some View {
        HStack(spacing: 7) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                .accessibilityHidden(true)
            TextField(placeholder, text: $text).textFieldStyle(.plain)
            if !text.isEmpty {
                Button { text = "" } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("清除筛选")
            }
        }
        .font(.callout)
        .padding(.horizontal, 9)
        .frame(height: 29)
        .background(Color.primary.opacity(0.045), in: RoundedRectangle(cornerRadius: 7))
        .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(.quaternary))
    }
}

extension View {
    func hopPanel() -> some View {
        padding(16)
            .background(Color(nsColor: .windowBackgroundColor).opacity(0.52), in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(.quaternary))
    }
}

struct HopPrimaryButton: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(HopAppearance.navy)
            .padding(.horizontal, 12)
            .frame(minHeight: 29)
            .background(
                HopAppearance.mint.opacity(isEnabled ? (configuration.isPressed ? 0.75 : 1) : 0.42),
                in: RoundedRectangle(cornerRadius: 7)
            )
            .contentShape(RoundedRectangle(cornerRadius: 7))
    }
}
