// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import ExpoModulesCore
import QuickLook
import UIKit

/// Shows a local file with Apple's Quick Look, presented over the wallet's own
/// screen: PDFs, images, Office documents, text. The file is the wallet's
/// temporary copy of something it fetched over an attested channel.
public class FilePreviewModule: Module {
    // Quick Look holds its data source and delegate weakly.
    private static var current: PreviewSession?

    public func definition() -> ModuleDefinition {
        Name("FilePreview")

        AsyncFunction("canPreview") { (path: String) -> Bool in
            QLPreviewController.canPreview(URL(fileURLWithPath: path) as NSURL)
        }.runOnQueue(.main)

        AsyncFunction("preview") { (path: String, title: String, promise: Promise) in
            guard let presenter = Self.topViewController() else {
                promise.reject("E_NO_VIEW", "there is no screen to show the file over")
                return
            }
            let session = PreviewSession(url: URL(fileURLWithPath: path), title: title)
            Self.current = session
            let controller = QLPreviewController()
            controller.dataSource = session
            controller.delegate = session
            presenter.present(controller, animated: true) {
                promise.resolve(nil)
            }
        }.runOnQueue(.main)
    }

    private static func topViewController() -> UIViewController? {
        let window = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first { $0.isKeyWindow }
        var top = window?.rootViewController
        while let presented = top?.presentedViewController {
            top = presented
        }
        return top
    }

    // The wallet deletes its copy when its own screen closes, so the holder
    // can open the file again meanwhile.
    fileprivate static func finished(_ session: PreviewSession) {
        if current === session {
            current = nil
        }
    }
}

private final class PreviewItem: NSObject, QLPreviewItem {
    let previewItemURL: URL?
    let previewItemTitle: String?

    init(url: URL, title: String) {
        previewItemURL = url
        previewItemTitle = title
    }
}

private final class PreviewSession: NSObject, QLPreviewControllerDataSource, QLPreviewControllerDelegate {
    let url: URL
    private let item: PreviewItem

    init(url: URL, title: String) {
        self.url = url
        item = PreviewItem(url: url, title: title)
    }

    func numberOfPreviewItems(in controller: QLPreviewController) -> Int { 1 }

    func previewController(_ controller: QLPreviewController, previewItemAt index: Int) -> QLPreviewItem {
        item
    }

    func previewControllerDidDismiss(_ controller: QLPreviewController) {
        FilePreviewModule.finished(self)
    }
}
