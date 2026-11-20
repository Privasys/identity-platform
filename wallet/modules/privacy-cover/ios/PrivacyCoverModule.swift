// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import ExpoModulesCore
import UIKit

/// Covers the wallet the moment it goes to the background, before iOS takes
/// the snapshot it shows in the app switcher and while the app comes back.
///
/// The wallet's own cover (components/AppLock) is drawn from JavaScript, which
/// can land a frame or two after iOS has taken that snapshot: the snapshot then
/// showed the holder's data, and iOS fades from it into the live app on return.
/// This cover is added synchronously in the background notification, so it is
/// in the snapshot. It is the logo's closed halves, exactly as AppLock draws
/// them, so handing over between the two shows nothing.
///
/// Only while the app lock is on (setEnabled). The wallet lifts it (release)
/// once its own screen has caught up on return; failing that, it lifts itself.
public class PrivacyCoverModule: Module {
    private static var enabled = false
    private static var covers: [UIView] = []
    private static var fallback: DispatchWorkItem?
    private static var observing = false

    public func definition() -> ModuleDefinition {
        Name("PrivacyCover")

        OnCreate {
            DispatchQueue.main.async { Self.observe() }
        }

        Function("setEnabled") { (on: Bool) in
            Self.enabled = on
            DispatchQueue.main.async {
                Self.observe()
                if !on { Self.remove() }
            }
        }

        Function("release") {
            DispatchQueue.main.async { Self.remove() }
        }
    }

    private static func observe() {
        if observing { return }
        observing = true
        let centre = NotificationCenter.default
        for name in [UIApplication.didEnterBackgroundNotification, UIScene.didEnterBackgroundNotification] {
            centre.addObserver(forName: name, object: nil, queue: .main) { _ in show() }
        }
        for name in [UIApplication.didBecomeActiveNotification, UIScene.didActivateNotification] {
            centre.addObserver(forName: name, object: nil, queue: .main) { _ in liftLater() }
        }
    }

    private static func show() {
        guard enabled, covers.isEmpty else { return }
        fallback?.cancel()
        let windows = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
        for window in windows {
            let cover = HalvesView(frame: window.bounds)
            cover.autoresizingMask = [.flexibleWidth, .flexibleHeight]
            window.addSubview(cover)
            covers.append(cover)
        }
    }

    /// Should the wallet never lift the cover, it goes by itself.
    private static func liftLater() {
        guard !covers.isEmpty else { return }
        fallback?.cancel()
        let work = DispatchWorkItem { remove() }
        fallback = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5, execute: work)
    }

    private static func remove() {
        fallback?.cancel()
        fallback = nil
        covers.forEach { $0.removeFromSuperview() }
        covers.removeAll()
    }
}

/// The logo's two halves, closed, with the lock in the gap: components/AppLock
/// at rest. Same colours, same geometry.
private final class HalvesView: UIView {
    private static let green = UIColor(red: 0x34 / 255.0, green: 0xC1 / 255.0, blue: 0x7B / 255.0, alpha: 1)
    private static let blue = UIColor(red: 0x00 / 255.0, green: 0xAA / 255.0, blue: 0xEE / 255.0, alpha: 1)
    private static let ink = UIColor(red: 0x0F / 255.0, green: 0x17 / 255.0, blue: 0x2A / 255.0, alpha: 1)
    private static let gap: CGFloat = 20
    private static let badge: CGFloat = 44

    private let greenLayer = CALayer()
    private let blueLayer = CALayer()
    private let lockBadge = UIView()

    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .white
        greenLayer.backgroundColor = Self.green.cgColor
        blueLayer.backgroundColor = Self.blue.cgColor
        layer.addSublayer(greenLayer)
        layer.addSublayer(blueLayer)

        lockBadge.backgroundColor = .white
        lockBadge.layer.cornerRadius = Self.badge / 2
        let icon = UIImageView(image: UIImage(
            systemName: "lock.fill",
            withConfiguration: UIImage.SymbolConfiguration(pointSize: 16, weight: .semibold)
        ))
        icon.tintColor = Self.ink
        icon.translatesAutoresizingMaskIntoConstraints = false
        lockBadge.addSubview(icon)
        NSLayoutConstraint.activate([
            icon.centerXAnchor.constraint(equalTo: lockBadge.centerXAnchor),
            icon.centerYAnchor.constraint(equalTo: lockBadge.centerYAnchor),
        ])
        addSubview(lockBadge)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    override func layoutSubviews() {
        super.layoutSubviews()
        let w = bounds.width, h = bounds.height
        // Two squares turned 45°, much larger than the screen, each with an
        // edge gap/2 from the diagonal through the centre.
        let size = max(w, h) * 1.5
        let offset = (size + Self.gap) * CGFloat(2).squareRoot() / 4
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        for (layer, centre) in [
            (greenLayer, CGPoint(x: w / 2 - offset, y: h / 2 - offset)),
            (blueLayer, CGPoint(x: w / 2 + offset, y: h / 2 + offset)),
        ] {
            layer.setAffineTransform(.identity)
            layer.bounds = CGRect(x: 0, y: 0, width: size, height: size)
            layer.position = centre
            layer.setAffineTransform(CGAffineTransform(rotationAngle: -.pi / 4))
        }
        CATransaction.commit()
        lockBadge.frame = CGRect(x: w / 2 - Self.badge / 2, y: h / 2 - Self.badge / 2, width: Self.badge, height: Self.badge)
    }
}
