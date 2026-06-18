// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import ExpoModulesCore
import CoreNFC
import NFCPassportReader
import Vision
import UIKit

/// eMRTD (ICAO 9303) NFC reader, backed by AndyQ/NFCPassportReader (MIT).
///
/// Reads the chip with the MRZ-derived BAC/PACE key and returns DG1 fields +
/// the DG2 portrait. Requires the NFC reader-session entitlement
/// (`com.apple.developer.nfc.readersession.formats`) and an NFC-capable device.
public class NativeEmrtdModule: Module {
    private let passportReader = PassportReader()

    public func definition() -> ModuleDefinition {
        Name("NativeEmrtd")

        AsyncFunction("isSupported") { () -> String in
            let available = NFCTagReaderSession.readingAvailable
            let reason = available ? "" : "NFC tag reading is not available on this device"
            return "{\"supported\":\(available),\"reason\":\"\(reason)\"}"
        }

        AsyncFunction("readDocument") {
            (documentNumber: String, dateOfBirth: String, dateOfExpiry: String, promise: Promise) in
            let mrzKey = NativeEmrtdModule.computeMrzKey(
                documentNumber: documentNumber,
                dateOfBirth: dateOfBirth,
                dateOfExpiry: dateOfExpiry
            )
            Task { [weak self] in
                guard let self = self else { return }
                do {
                    let passport = try await self.passportReader.readPassport(mrzKey: mrzKey)
                    promise.resolve(NativeEmrtdModule.toJson(passport))
                } catch {
                    promise.resolve("{\"error\":\"\(NativeEmrtdModule.escape(error.localizedDescription))\"}")
                }
            }
        }

        AsyncFunction("scanMrz") { (imageBase64: String, promise: Promise) in
            guard let data = Data(base64Encoded: imageBase64),
                  let image = UIImage(data: data),
                  let cgImage = image.cgImage else {
                promise.resolve("{\"error\":\"could not decode the photo\"}")
                return
            }
            let request = VNRecognizeTextRequest { (req, err) in
                if let err = err {
                    promise.resolve("{\"error\":\"\(NativeEmrtdModule.escape(err.localizedDescription))\"}")
                    return
                }
                let observations = (req.results as? [VNRecognizedTextObservation]) ?? []
                let lines = observations.compactMap { $0.topCandidates(1).first?.string }
                if let json = NativeEmrtdModule.parseTd3(lines) {
                    promise.resolve(json)
                } else {
                    promise.resolve("{\"error\":\"Could not find the MRZ. Frame the two lines of < at the bottom of the photo page.\"}")
                }
            }
            request.recognitionLevel = .accurate
            request.usesLanguageCorrection = false
            let handler = VNImageRequestHandler(cgImage: cgImage, options: [:])
            DispatchQueue.global(qos: .userInitiated).async {
                do { try handler.perform([request]) }
                catch { promise.resolve("{\"error\":\"\(NativeEmrtdModule.escape(error.localizedDescription))\"}") }
            }
        }
    }

    /// Parse a TD3 MRZ (two 44-char lines) from OCR'd text lines and return the
    /// chip-access fields. Line 2 carries documentNumber(0..9), DOB(13..19) and
    /// expiry(21..27); we pick the candidate line whose DOB/expiry slots are
    /// numeric, which reliably identifies the data line despite OCR noise.
    private static func parseTd3(_ rawLines: [String]) -> String? {
        let charset = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<")
        let candidates = rawLines
            .map { $0.uppercased().replacingOccurrences(of: " ", with: "") }
            .filter { $0.count >= 28 && $0.allSatisfy { charset.contains($0) } }

        for line in candidates.reversed() {
            let chars = Array(line)
            if chars.count < 28 { continue }
            let docNo = String(chars[0..<9]).replacingOccurrences(of: "<", with: "")
            let dob = String(chars[13..<19])
            let exp = String(chars[21..<27])
            if !docNo.isEmpty && dob.allSatisfy({ $0.isNumber }) && exp.allSatisfy({ $0.isNumber }) {
                return "{\"documentNumber\":\"\(escape(docNo))\",\"dateOfBirth\":\"\(dob)\",\"dateOfExpiry\":\"\(exp)\"}"
            }
        }
        return nil
    }

    private static func toJson(_ p: NFCPassportModel) -> String {
        var fields: [String: String] = [
            "given_name": p.firstName,
            "family_name": p.lastName,
            "nationality": p.nationality,
            "document_number": p.documentNumber,
        ]
        if let bd = isoDate(p.dateOfBirth) { fields["birthdate"] = bd }
        if let ex = isoDate(p.documentExpiryDate) { fields["expiry_date"] = ex }

        let fieldsJson = fields
            .map { "\"\($0.key)\":\"\(escape($0.value))\"" }
            .joined(separator: ",")

        var portrait = "null"
        if let img = p.passportImage, let data = img.jpegData(compressionQuality: 0.85) {
            portrait = "\"\(data.base64EncodedString())\""
        }
        return "{\"fields\":{\(fieldsJson)},\"portraitBase64\":\(portrait)}"
    }

    /// MRZ dates are YYMMDD; expand to YYYY-MM-DD with a century heuristic
    /// (years greater than the current 2-digit year are treated as 19xx).
    private static func isoDate(_ yymmdd: String) -> String? {
        guard yymmdd.count == 6,
              let yy = Int(yymmdd.prefix(2)),
              let mm = Int(yymmdd.dropFirst(2).prefix(2)),
              let dd = Int(yymmdd.suffix(2)) else { return nil }
        let currentYY = Calendar.current.component(.year, from: Date()) % 100
        let century = yy > currentYY ? 1900 : 2000
        return String(format: "%04d-%02d-%02d", century + yy, mm, dd)
    }

    private static func escape(_ s: String) -> String {
        return s
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }

    /// Build the eMRTD BAC/PACE MRZ key: the 9-char document number (padded
    /// with `<`) + its check digit, then DOB (YYMMDD) + check digit, then
    /// expiry (YYMMDD) + check digit. NFCPassportReader's readPassport derives
    /// the access key from this string.
    private static func computeMrzKey(documentNumber: String, dateOfBirth: String, dateOfExpiry: String) -> String {
        let docNo = documentNumber.uppercased().padding(toLength: 9, withPad: "<", startingAt: 0)
        return docNo + checkDigit(docNo)
            + dateOfBirth + checkDigit(dateOfBirth)
            + dateOfExpiry + checkDigit(dateOfExpiry)
    }

    /// ICAO 9303 check digit: weighted (7,3,1) sum mod 10 over the field
    /// (digits = value, A–Z = 10–35, `<` = 0).
    private static func checkDigit(_ value: String) -> String {
        let weights = [7, 3, 1]
        var sum = 0
        for (i, ch) in value.uppercased().enumerated() {
            let v: Int
            if ("0"..."9").contains(ch), let d = ch.wholeNumberValue {
                v = d
            } else if let a = ch.asciiValue, a >= 65, a <= 90 {
                v = Int(a) - 65 + 10
            } else {
                v = 0 // '<' and any filler
            }
            sum += v * weights[i % 3]
        }
        return String(sum % 10)
    }
}
