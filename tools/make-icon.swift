import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let colorSpace = CGColorSpace(name: CGColorSpace.sRGB)!

func color(_ hex: UInt32, alpha: CGFloat = 1) -> CGColor {
    CGColor(
        colorSpace: colorSpace,
        components: [
            CGFloat((hex >> 16) & 255) / 255,
            CGFloat((hex >> 8) & 255) / 255,
            CGFloat(hex & 255) / 255,
            alpha
        ]
    )!
}

func render(size: Int, to destination: URL) throws {
    guard let context = CGContext(
        data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
        space: colorSpace, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
    ) else {
        throw CocoaError(.fileWriteUnknown)
    }
    let scale = CGFloat(size) / 1024
    context.translateBy(x: 0, y: CGFloat(size))
    context.scaleBy(x: scale, y: -scale)
    context.setAllowsAntialiasing(true)

    let tile = CGPath(
        roundedRect: CGRect(x: 100, y: 92, width: 824, height: 824),
        cornerWidth: 187, cornerHeight: 187, transform: nil
    )
    context.saveGState()
    context.setShadow(offset: CGSize(width: 0, height: -14 * scale), blur: 28 * scale, color: color(0x03121d, alpha: 0.28))
    context.addPath(tile)
    context.setFillColor(color(0x0d263c))
    context.fillPath()
    context.restoreGState()

    context.saveGState()
    context.addPath(tile)
    context.clip()
    let background = CGGradient(
        colorsSpace: colorSpace,
        colors: [color(0x234865), color(0x0d263c), color(0x091b2d)] as CFArray,
        locations: [0, 0.57, 1]
    )!
    context.drawLinearGradient(
        background, start: CGPoint(x: 200, y: 104), end: CGPoint(x: 812, y: 932),
        options: [.drawsBeforeStartLocation, .drawsAfterEndLocation]
    )
    context.restoreGState()

    context.addPath(tile)
    context.setLineWidth(3)
    context.setStrokeColor(color(0x9bc7e4, alpha: 0.25))
    context.strokePath()

    // The line climbs in two hops, with a visible origin and destination.
    let route = CGMutablePath()
    route.move(to: CGPoint(x: 277, y: 641))
    route.addLine(to: CGPoint(x: 340, y: 641))
    route.addCurve(
        to: CGPoint(x: 465, y: 515),
        control1: CGPoint(x: 403, y: 641), control2: CGPoint(x: 402, y: 515)
    )
    route.addLine(to: CGPoint(x: 542, y: 515))
    route.addCurve(
        to: CGPoint(x: 674, y: 383),
        control1: CGPoint(x: 608, y: 515), control2: CGPoint(x: 608, y: 383)
    )
    route.addLine(to: CGPoint(x: 747, y: 383))

    context.setLineWidth(60)
    context.setLineCap(.round)
    context.setStrokeColor(color(0x5cf0c5))
    context.addPath(route)
    context.strokePath()
    context.setFillColor(color(0x5cf0c5))
    context.fillEllipse(in: CGRect(x: 230, y: 594, width: 94, height: 94))
    context.setFillColor(color(0xc2ffea))
    context.fillEllipse(in: CGRect(x: 700, y: 336, width: 94, height: 94))

    guard let bitmap = context.makeImage(),
          let encoder = CGImageDestinationCreateWithURL(
              destination as CFURL, UTType.png.identifier as CFString, 1, nil
          ) else {
        throw CocoaError(.fileWriteUnknown)
    }
    CGImageDestinationAddImage(encoder, bitmap, nil)
    guard CGImageDestinationFinalize(encoder) else {
        throw CocoaError(.fileWriteUnknown)
    }
}

let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
for size in [16, 32, 128, 256, 512] {
    for density in [1, 2] {
        let suffix = density == 2 ? "@2x" : ""
        let destination = directory.appendingPathComponent("icon_\(size)x\(size)\(suffix).png")
        try render(size: size * density, to: destination)
    }
}
