// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import AVFoundation
import ExpoModulesCore
import UIKit
import Vision

/// A live camera preview that reads text from every frame it can keep up with.
///
/// The photo-page capture used to take a still about once a second and read
/// that, so the holder waited on each attempt and had to line the page up with
/// a guide. Here the text of each video frame is read as it arrives and handed
/// to JavaScript with its position, which decides whether it is a machine
/// readable zone. The frame a reading came from is kept, so the picture that
/// goes on to the verifier is the very one that was read.
///
/// Nothing is stored and nothing leaves the phone from here.
final class MrzScannerView: ExpoView, AVCaptureVideoDataOutputSampleBufferDelegate {
    let onText = EventDispatcher()
    let onReady = EventDispatcher()
    let onCameraError = EventDispatcher()

    private let session: AVCaptureSession
    private let sessionQueue = DispatchQueue(label: "org.privasys.wallet.mrz.session")
    private let videoQueue = DispatchQueue(label: "org.privasys.wallet.mrz.video")
    private let output = AVCaptureVideoDataOutput()
    private let previewLayer: AVCaptureVideoPreviewLayer
    private let ciContext = CIContext()

    // sessionQueue only.
    private var configured = false
    private var wantsRunning = false

    // videoQueue only.
    private var frameId = 0

    private let heldLock = NSLock()
    private var held: CGImage?

    required init(appContext: AppContext? = nil) {
        let session = AVCaptureSession()
        self.session = session
        previewLayer = AVCaptureVideoPreviewLayer(session: session)
        super.init(appContext: appContext)
        backgroundColor = .black
        clipsToBounds = true
        previewLayer.videoGravity = .resizeAspectFill
        layer.addSublayer(previewLayer)
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(orientationChanged),
            name: UIDevice.orientationDidChangeNotification,
            object: nil
        )
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
        let session = self.session
        sessionQueue.async {
            if session.isRunning { session.stopRunning() }
        }
    }

    // MARK: - Props and functions

    func setActive(_ active: Bool) {
        sessionQueue.async { [weak self] in
            guard let self = self else { return }
            self.wantsRunning = active
            self.applyRunning()
        }
    }

    /// The kept frame as a JPEG, cut to the given part of it (fractions of the
    /// frame, from its top left). Empty when no frame has been kept.
    func snapshot(x: Double, y: Double, width: Double, height: Double) -> String {
        heldLock.lock()
        let image = held
        heldLock.unlock()
        guard let image = image else { return "" }

        let w = Double(image.width)
        let h = Double(image.height)
        let left = max(0, min(1, x)) * w
        let top = max(0, min(1, y)) * h
        let right = max(0, min(1, x + width)) * w
        let bottom = max(0, min(1, y + height)) * h
        var cut = image
        if right - left >= 16, bottom - top >= 16 {
            let rect = CGRect(x: left, y: top, width: right - left, height: bottom - top).integral
            if let cropped = image.cropping(to: rect) { cut = cropped }
        }
        guard let data = UIImage(cgImage: cut).jpegData(compressionQuality: 0.9) else { return "" }
        return data.base64EncodedString()
    }

    // MARK: - View

    override func layoutSubviews() {
        super.layoutSubviews()
        previewLayer.frame = bounds
        applyOrientation()
    }

    override func didMoveToWindow() {
        super.didMoveToWindow()
        let visible = window != nil
        if visible { applyOrientation() }
        sessionQueue.async { [weak self] in
            guard let self = self else { return }
            if !visible, self.session.isRunning { self.session.stopRunning() }
            if visible { self.applyRunning() }
        }
    }

    @objc private func orientationChanged() {
        // The interface settles a moment after the device reports its turn.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            self?.applyOrientation()
        }
    }

    /// Turn both the preview and the frames to the way the screen is held, so
    /// a frame is always upright and positions in it mean what they say.
    private func applyOrientation() {
        let orientation: AVCaptureVideoOrientation
        switch window?.windowScene?.interfaceOrientation {
        case .landscapeLeft: orientation = .landscapeLeft
        case .landscapeRight: orientation = .landscapeRight
        case .portraitUpsideDown: orientation = .portraitUpsideDown
        case .portrait: orientation = .portrait
        default: return
        }
        if let connection = previewLayer.connection, connection.isVideoOrientationSupported {
            connection.videoOrientation = orientation
        }
        sessionQueue.async { [weak self] in
            guard let self = self,
                  let connection = self.output.connection(with: .video),
                  connection.isVideoOrientationSupported else { return }
            connection.videoOrientation = orientation
        }
    }

    // MARK: - Session (sessionQueue)

    private func applyRunning() {
        if wantsRunning {
            if !configured { configure() }
            guard configured else { return }
            if !session.isRunning {
                session.startRunning()
                DispatchQueue.main.async { [weak self] in
                    self?.applyOrientation()
                    self?.onReady([:])
                }
            }
        } else if session.isRunning {
            session.stopRunning()
        }
    }

    private func fail(_ message: String) {
        DispatchQueue.main.async { [weak self] in
            self?.onCameraError(["message": message])
        }
    }

    private func configure() {
        guard AVCaptureDevice.authorizationStatus(for: .video) == .authorized else {
            fail("camera permission has not been granted")
            return
        }
        // A phone with an ultra-wide lens offers a camera that changes lens by
        // itself when the subject is close, which is what a page held near the
        // phone needs; the plain wide lens of recent phones cannot focus there.
        let discovery = AVCaptureDevice.DiscoverySession(
            deviceTypes: [.builtInTripleCamera, .builtInDualWideCamera, .builtInWideAngleCamera],
            mediaType: .video,
            position: .back
        )
        guard let device = discovery.devices.first else {
            fail("no back camera on this device")
            return
        }

        session.beginConfiguration()
        session.sessionPreset = session.canSetSessionPreset(.hd1920x1080) ? .hd1920x1080 : .high
        do {
            let input = try AVCaptureDeviceInput(device: device)
            guard session.canAddInput(input) else {
                session.commitConfiguration()
                fail("the camera could not be opened")
                return
            }
            session.addInput(input)
        } catch {
            session.commitConfiguration()
            fail(error.localizedDescription)
            return
        }

        output.alwaysDiscardsLateVideoFrames = true
        output.videoSettings = [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA
        ]
        output.setSampleBufferDelegate(self, queue: videoQueue)
        guard session.canAddOutput(output) else {
            session.commitConfiguration()
            fail("the camera could not be read")
            return
        }
        session.addOutput(output)
        session.commitConfiguration()

        do {
            try device.lockForConfiguration()
            if device.isFocusModeSupported(.continuousAutoFocus) {
                device.focusMode = .continuousAutoFocus
            }
            if device.isAutoFocusRangeRestrictionSupported {
                device.autoFocusRangeRestriction = .near
            }
            if device.isExposureModeSupported(.continuousAutoExposure) {
                device.exposureMode = .continuousAutoExposure
            }
            // Such a camera starts on its ultra-wide lens. Start on the wide
            // one instead, and let it fall back to ultra-wide up close.
            if device.deviceType != .builtInWideAngleCamera,
               let wide = device.virtualDeviceSwitchOverVideoZoomFactors.first {
                let factor = CGFloat(truncating: wide)
                device.videoZoomFactor = min(
                    max(factor, device.minAvailableVideoZoomFactor),
                    device.maxAvailableVideoZoomFactor
                )
            }
            device.unlockForConfiguration()
        } catch {
            // Defaults still give a working camera.
        }
        configured = true
    }

    // MARK: - Frames (videoQueue)

    func captureOutput(
        _ output: AVCaptureOutput,
        didOutput sampleBuffer: CMSampleBuffer,
        from connection: AVCaptureConnection
    ) {
        // Reading blocks this queue, and frames that arrive meanwhile are
        // dropped, so this runs as often as the phone can manage and no more.
        guard let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }

        let request = VNRecognizeTextRequest()
        request.recognitionLevel = .accurate
        request.usesLanguageCorrection = false
        let handler = VNImageRequestHandler(cvPixelBuffer: pixelBuffer, orientation: .up, options: [:])
        do { try handler.perform([request]) } catch { return }

        var lines: [[String: Any]] = []
        var candidate = false
        for observation in request.results ?? [] {
            guard let text = observation.topCandidates(1).first?.string else { continue }
            let compact = text.replacingOccurrences(of: " ", with: "")
            guard compact.count >= 20 else { continue }
            if compact.count >= 28, compact.contains("<<") { candidate = true }
            // Vision measures from the bottom left; report from the top left.
            let box = observation.boundingBox
            lines.append([
                "text": text,
                "x": Double(box.minX),
                "y": Double(1 - box.maxY),
                "w": Double(box.width),
                "h": Double(box.height)
            ])
        }

        frameId += 1
        if candidate {
            let image = CIImage(cvPixelBuffer: pixelBuffer)
            if let kept = ciContext.createCGImage(image, from: image.extent) {
                heldLock.lock()
                held = kept
                heldLock.unlock()
            } else {
                candidate = false
            }
        }

        let payload: [String: Any] = [
            "frame": frameId,
            "width": CVPixelBufferGetWidth(pixelBuffer),
            "height": CVPixelBufferGetHeight(pixelBuffer),
            "held": candidate,
            "lines": lines
        ]
        DispatchQueue.main.async { [weak self] in
            self?.onText(payload)
        }
    }
}
