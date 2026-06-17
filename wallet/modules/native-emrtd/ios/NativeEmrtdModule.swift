// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import ExpoModulesCore
import CoreNFC

/// eMRTD (ICAO 9303) NFC reader.
///
/// `isSupported` reports real device NFC availability. `readDocument` is the
/// integration point for the chip-read protocol (open `NFCTagReaderSession`,
/// select the LDS applet, run BAC/PACE with the MRZ-derived key, read
/// DG1/DG2/EF.SOD, return parsed fields + portrait + SOD). That protocol layer
/// is completed against AndyQ/NFCPassportReader (MIT) in a device-tested step,
/// and requires the `com.apple.developer.nfc.readersession.formats` entitlement
/// (an Apple App ID capability, provisioned separately). Until then it returns a
/// structured "not enabled" error and callers fall back (dev stub / coming-soon).
public class NativeEmrtdModule: Module {
    public func definition() -> ModuleDefinition {
        Name("NativeEmrtd")

        AsyncFunction("isSupported") { () -> String in
            let available = NFCTagReaderSession.readingAvailable
            let reason = available ? "" : "NFC tag reading is not available on this device"
            return "{\"supported\":\(available),\"reason\":\"\(reason)\"}"
        }

        AsyncFunction("readDocument") { (_ documentNumber: String, _ dateOfBirth: String, _ dateOfExpiry: String) -> String in
            return "{\"error\":\"eMRTD chip reading is not yet enabled in this build\"}"
        }
    }
}
