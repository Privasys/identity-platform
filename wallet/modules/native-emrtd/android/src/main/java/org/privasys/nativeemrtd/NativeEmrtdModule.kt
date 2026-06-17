// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.nativeemrtd

import android.nfc.NfcAdapter
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

/**
 * eMRTD (ICAO 9303) NFC reader.
 *
 * `isSupported` reports real device NFC availability. `readDocument` is the
 * integration point for the chip-read protocol (IsoDep + jMRTD: BAC/PACE with
 * the MRZ-derived key, read DG1/DG2/EF.SOD, return parsed fields + portrait +
 * SOD). That protocol layer is completed against jMRTD (LGPL, kept on the
 * wallet side per the design's licence separation) in a device-tested step;
 * until then it returns a structured "not enabled" error and callers fall back.
 */
class NativeEmrtdModule : Module() {
    override fun definition() = ModuleDefinition {
        Name("NativeEmrtd")

        AsyncFunction("isSupported") {
            val context = appContext.reactContext
            val adapter = context?.let { NfcAdapter.getDefaultAdapter(it) }
            val supported = adapter != null && adapter.isEnabled
            val reason = when {
                adapter == null -> "no NFC hardware on this device"
                !adapter.isEnabled -> "NFC is turned off"
                else -> ""
            }
            "{\"supported\":$supported,\"reason\":\"$reason\"}"
        }

        AsyncFunction("readDocument") { _: String, _: String, _: String ->
            "{\"error\":\"eMRTD chip reading is not yet enabled in this build\"}"
        }
    }
}
