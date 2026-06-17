// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import ExpoModulesCore
import CoreNFC
import NFCPassportReader

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
            let mrzKey = PassportUtils.getMRZKey(
                passportNumber: documentNumber,
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
}
