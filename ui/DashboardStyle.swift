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
    static let chartUpload = Color(nsColor: NSColor(name: nil) { appearance in
        let dark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
        return dark
            ? NSColor(srgbRed: 0.74, green: 0.86, blue: 1.0, alpha: 1)
            : NSColor(srgbRed: 0.61, green: 0.96, blue: 0.86, alpha: 1)
    })
    static let warning = Color(nsColor: NSColor(name: nil) { appearance in
        if appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua {
            return NSColor(srgbRed: 0.97, green: 0.71, blue: 0.35, alpha: 1)
        }
        return NSColor(srgbRed: 0.58, green: 0.32, blue: 0.06, alpha: 1)
    })
    static let panelSurface = Color(nsColor: NSColor(name: nil) { appearance in
        let dark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
        return dark ? NSColor(srgbRed: 0.108, green: 0.132, blue: 0.153, alpha: 1) : .white
    })
    static let insetSurface = Color.primary.opacity(0.035)
    static let pageSurface = Color(nsColor: NSColor(name: nil) { appearance in
        let dark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
        return dark
            ? NSColor(srgbRed: 0.071, green: 0.092, blue: 0.110, alpha: 1)
            : NSColor(srgbRed: 0.956, green: 0.969, blue: 0.973, alpha: 1)
    })
    static let panelBorder = Color.primary.opacity(0.10)
    static let panelRadius: CGFloat = 13
    static let pageSpacing: CGFloat = 14
}

struct HopPageHeading: View {
    let title: String
    var detail: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.system(size: 27, weight: .semibold)).tracking(-0.35)
                .accessibilityAddTraits(.isHeader)
            if let detail { Text(detail).font(.callout).foregroundStyle(.secondary) }
        }
    }
}

struct HopSectionLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 8) {
            configuration.icon
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(HopAppearance.accent)
                .frame(width: 16)
                .accessibilityHidden(true)
            configuration.title.font(.headline)
        }
    }
}

struct HopLabeledControl<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
                .accessibilityHidden(true)
            content
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct HopDisclosure<Content: View>: View {
    let title: String
    let content: Content

    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        DisclosureGroup {
            VStack(alignment: .leading, spacing: 6) { content }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.top, 5)
        } label: {
            Text(title).lineLimit(1).help(title)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct HopSelectionMenu<Value: Hashable, Options: View>: View {
    let title: String
    let value: String
    let labelWidth: CGFloat?
    @Binding var selection: Value
    @ViewBuilder var options: Options

    var body: some View {
        Group {
            if let labelWidth {
                Menu { picker } label: {
                    Text(value).lineLimit(1).frame(width: labelWidth, alignment: .leading)
                }
            } else {
                GeometryReader { geometry in
                    Menu { picker } label: {
                        // The native menu adds padding and its disclosure indicator.
                        Text(value).lineLimit(1)
                            .frame(width: max(0, geometry.size.width - 48), alignment: .leading)
                    }
                }
                .frame(height: 26)
            }
        }
        .accessibilityLabel(title)
        .accessibilityValue(value)
        .help(value)
    }

    private var picker: some View {
        Picker(title, selection: $selection) { options }
            .pickerStyle(.inline)
            .labelsHidden()
    }
}

struct HopSearchField: View {
    let placeholder: String
    @Binding var text: String
    @FocusState private var focused: Bool

    var body: some View {
        HStack(spacing: 7) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                .accessibilityHidden(true)
            TextField(placeholder, text: $text)
                .textFieldStyle(.plain)
                .focused($focused)
                .accessibilityLabel(placeholder)
            if !text.isEmpty {
                Button { text = "" } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(L("清除搜索"))
            }
        }
        .font(.callout)
        .padding(.horizontal, 9)
        .frame(height: 29)
        .hopGlass(radius: 8)
        .overlay {
            if focused {
                RoundedRectangle(cornerRadius: 8).strokeBorder(HopAppearance.accent)
                    .allowsHitTesting(false)
            }
        }
    }
}

private struct HopGlassSurface: ViewModifier {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    let radius: CGFloat
    let tint: Color?

    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: radius)
        if reduceTransparency {
            content.background(HopAppearance.panelSurface, in: shape)
                .overlay(shape.strokeBorder(HopAppearance.panelBorder))
        } else if #available(macOS 26.0, *) {
            content.background {
                Color.clear
                    .glassEffect(.regular.tint(tint), in: shape)
                    .accessibilityHidden(true)
                    .allowsHitTesting(false)
            }
        } else {
            content.background(.regularMaterial, in: shape)
                .background(tint ?? .clear, in: shape)
                .overlay(shape.strokeBorder(HopAppearance.panelBorder))
        }
    }
}

extension View {
    func hopGlass(radius: CGFloat = HopAppearance.panelRadius, tint: Color? = nil) -> some View {
        modifier(HopGlassSurface(radius: radius, tint: tint))
    }

    func hopPanel(verticalPadding: CGFloat = 16) -> some View {
        let shape = RoundedRectangle(cornerRadius: HopAppearance.panelRadius)
        return padding(.horizontal, 16)
            .padding(.vertical, verticalPadding)
            .background(HopAppearance.panelSurface, in: shape)
            .overlay(shape.strokeBorder(HopAppearance.panelBorder))
    }

    func hopTableSurface() -> some View {
        let shape = RoundedRectangle(cornerRadius: HopAppearance.panelRadius)
        return clipShape(shape)
            .overlay { shape.strokeBorder(HopAppearance.panelBorder).allowsHitTesting(false) }
    }
}

struct HopPrimaryButton: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.colorScheme) private var colorScheme
    var onDarkSurface = false

    func makeBody(configuration: Configuration) -> some View {
        let usesMint = onDarkSurface || colorScheme == .dark
        let fill = usesMint ? HopAppearance.mint : HopAppearance.accent
        return configuration.label
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(isEnabled ? (usesMint ? HopAppearance.navy : .white) : Color.secondary)
            .padding(.horizontal, 12)
            .frame(minHeight: 29)
            .background(
                fill.opacity(isEnabled ? (configuration.isPressed ? 0.78 : 1) : 0.13),
                in: RoundedRectangle(cornerRadius: 7)
            )
            .overlay {
                RoundedRectangle(cornerRadius: 7)
                    .strokeBorder(.white.opacity(isEnabled ? 0.25 : 0.08))
                    .allowsHitTesting(false)
            }
            .contentShape(RoundedRectangle(cornerRadius: 7))
    }
}
