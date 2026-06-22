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
            // Normalise: BAC fields are upper-case, no spaces; dates must be the
            // 6-digit YYMMDD as printed in the MRZ (not the human-readable date).
            let docNo = documentNumber.uppercased().trimmingCharacters(in: .whitespaces)
            let dob = dateOfBirth.trimmingCharacters(in: .whitespaces)
            let exp = dateOfExpiry.trimmingCharacters(in: .whitespaces)
            let mrzKey = NativeEmrtdModule.computeMrzKey(
                documentNumber: docNo,
                dateOfBirth: dob,
                dateOfExpiry: exp
            )
            // Diagnostic fingerprint (no full document number) so a rejected key
            // can be told apart from a chip/comms failure in the app logs.
            let padded = docNo.padding(toLength: 9, withPad: "<", startingAt: 0)
            let diag = "doc=\(docNo.count)c+cd\(NativeEmrtdModule.checkDigit(padded)) "
                + "dob=\(dob.count)c+cd\(NativeEmrtdModule.checkDigit(dob)) "
                + "exp=\(exp.count)c+cd\(NativeEmrtdModule.checkDigit(exp))"
            // Read only what we need + can read. DG1 (MRZ) and DG2 (portrait) are
            // the verification minimum; EF.COM/EF.SOD are read alongside for
            // Passive Authentication. DG11 (extra personal details: place of
            // birth, personal number) is requested too, as a best-effort extra.
            // EAC-protected groups (DG3 fingerprints / DG4 iris) are NEVER
            // requested — they need Terminal Authentication we don't hold, and an
            // unbounded read selects them and aborts (e.g. German passports list
            // DG3 in EF.COM → SELECT DG3 → SW 0x6A88, killing the whole read).
            let optionalTags: [DataGroupId] = [.COM, .SOD, .DG1, .DG2, .DG11]
            let minimumTags: [DataGroupId] = [.COM, .SOD, .DG1, .DG2]
            Task { [weak self] in
                guard let self = self else { return }
                func resolveError(_ error: Error) {
                    let reason = NativeEmrtdModule.escape(error.localizedDescription)
                    // The exact enum case (e.g. ResponseError carries SW1/SW2 APDU
                    // status words) plus the NSError domain/code, so the precise
                    // failure stage is visible — "InvalidMRZKey" alone is ambiguous.
                    // No document number is logged (the key fingerprint in `diag`
                    // is enough to tell a rejected key from a chip/comms failure).
                    let ns = error as NSError
                    let detail = NativeEmrtdModule.escape(
                        "\(String(describing: error)) | \(ns.domain)#\(ns.code)"
                    )
                    promise.resolve(
                        "{\"error\":\"\(reason)\",\"diag\":\"\(NativeEmrtdModule.escape(diag))\","
                        + "\"detail\":\"\(detail)\"}"
                    )
                }
                do {
                    let passport = try await self.passportReader.readPassport(mrzKey: mrzKey, tags: optionalTags)
                    promise.resolve(NativeEmrtdModule.toJson(passport))
                } catch {
                    // A document without DG11 (or with it access-protected) answers
                    // the DG11 SELECT with SW 0x6A88 "Referenced data not found".
                    // That optional group must never fail the whole read: retry
                    // once with just the verification minimum. Any other failure —
                    // or a minimum read that also fails — is surfaced to the caller.
                    if NativeEmrtdModule.isReferencedDataNotFound(error) {
                        do {
                            let passport = try await self.passportReader.readPassport(mrzKey: mrzKey, tags: minimumTags)
                            promise.resolve(NativeEmrtdModule.toJson(passport))
                        } catch {
                            resolveError(error)
                        }
                    } else {
                        resolveError(error)
                    }
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
                let arr = lines.map { "\"\(NativeEmrtdModule.escape($0))\"" }.joined(separator: ",")
                promise.resolve("{\"lines\":[\(arr)]}")
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


    private static func toJson(_ p: NFCPassportModel) -> String {
        var fields: [String: String] = [
            "given_name": p.firstName,
            "family_name": p.lastName,
            "nationality": p.nationality,
            "document_number": p.documentNumber,
        ]
        if let bd = isoDate(p.dateOfBirth) { fields["birthdate"] = bd }
        if let ex = isoDate(p.documentExpiryDate, future: true) { fields["expiry_date"] = ex }

        let fieldsJson = fields
            .map { "\"\($0.key)\":\"\(escape($0.value))\"" }
            .joined(separator: ",")

        var portrait = "null"
        if let img = p.passportImage, let data = img.jpegData(compressionQuality: 0.85) {
            portrait = "\"\(data.base64EncodedString())\""
        }

        // Raw EF.SOD + data groups (exact on-chip bytes) so the verifier enclave
        // can run Passive Authentication (SOD signature → DSC → CSCA + per-DG hash
        // check) and the DG2↔selfie face match itself. The parsed `fields` above
        // are a convenience; the enclave certifies from these raw bytes.
        let sod = rawDataGroup(p, .SOD)
        var dgEntries: [String] = []
        // DG1 (MRZ) + DG2 (portrait) are required; DG11 (additional personal
        // details: place of birth, personal number) is sent when present.
        for (id, num) in [(DataGroupId.DG1, "1"), (DataGroupId.DG2, "2"), (DataGroupId.DG11, "11")] {
            if let dg = p.getDataGroup(id) {
                dgEntries.append("\"\(num)\":\"\(Data(dg.data).base64EncodedString())\"")
            }
        }
        let dgJson = dgEntries.joined(separator: ",")
        return "{\"fields\":{\(fieldsJson)},\"portraitBase64\":\(portrait),"
            + "\"sod\":\(sod),\"dataGroups\":{\(dgJson)}}"
    }

    /// Base64 of a data group's exact on-chip bytes, or JSON null if absent.
    private static func rawDataGroup(_ p: NFCPassportModel, _ id: DataGroupId) -> String {
        guard let dg = p.getDataGroup(id) else { return "null" }
        return "\"\(Data(dg.data).base64EncodedString())\""
    }

    /// MRZ dates are YYMMDD; expand to YYYY-MM-DD. Birth dates are in the past, so
    /// a 2-digit year above the current one rolls back to 19xx; expiry dates are
    /// always in the future, so `future: true` always uses the 2000s.
    private static func isoDate(_ yymmdd: String, future: Bool = false) -> String? {
        guard yymmdd.count == 6,
              let yy = Int(yymmdd.prefix(2)),
              let mm = Int(yymmdd.dropFirst(2).prefix(2)),
              let dd = Int(yymmdd.suffix(2)) else { return nil }
        let currentYY = Calendar.current.component(.year, from: Date()) % 100
        let century = future ? 2000 : (yy > currentYY ? 1900 : 2000)
        return String(format: "%04d-%02d-%02d", century + yy, mm, dd)
    }

    /// True for an ISO-7816 SW 0x6A88 ("Referenced data not found") — what the
    /// chip answers when we SELECT a data group it doesn't have (e.g. an absent
    /// DG11). NFCPassportReader surfaces it as `ResponseError(_, sw1, sw2)`.
    private static func isReferencedDataNotFound(_ error: Error) -> Bool {
        if case NFCPassportReaderError.ResponseError(_, let sw1, let sw2) = error {
            return sw1 == 0x6A && sw2 == 0x88
        }
        return false
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
