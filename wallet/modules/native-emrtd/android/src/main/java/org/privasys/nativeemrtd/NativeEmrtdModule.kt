// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.nativeemrtd

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.util.Base64
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import net.sf.scuba.smartcards.CardService
import org.jmrtd.BACKey
import org.jmrtd.PassportService
import org.jmrtd.lds.icao.DG1File
import org.jmrtd.lds.icao.DG2File
import org.json.JSONObject
import java.security.Security

/**
 * eMRTD (ICAO 9303) NFC reader, backed by jMRTD (LGPL) over IsoDep.
 *
 * Uses NFC reader-mode on the current activity: when the document chip is
 * tapped, runs BAC with the MRZ-derived key, reads DG1 (MRZ fields) and DG2
 * (portrait), and returns them. Needs the NFC permission and an NFC-capable
 * device. The chip data only leaves the device for the RA-TLS hop to the
 * verifier enclave (services/kyc.ts).
 */
class NativeEmrtdModule : Module() {
    init {
        // jMRTD relies on a registered SpongyCastle/BouncyCastle JCE provider.
        try {
            Security.insertProviderAt(org.spongycastle.jce.provider.BouncyCastleProvider(), 1)
        } catch (_: Throwable) {
        }
    }

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

        AsyncFunction("readDocument") { documentNumber: String, dateOfBirth: String, dateOfExpiry: String, promise: Promise ->
            val activity = appContext.currentActivity
            val adapter = activity?.let { NfcAdapter.getDefaultAdapter(it) }
            if (activity == null || adapter == null) {
                promise.resolve("{\"error\":\"NFC is unavailable on this device\"}")
                return@AsyncFunction
            }
            val bacKey = BACKey(documentNumber, dateOfBirth, dateOfExpiry)
            val settled = java.util.concurrent.atomic.AtomicBoolean(false)
            adapter.enableReaderMode(
                activity,
                { tag: Tag ->
                    if (!settled.compareAndSet(false, true)) return@enableReaderMode
                    val out = try {
                        readTag(tag, bacKey)
                    } catch (e: Exception) {
                        "{\"error\":\"${escape(e.message ?: "chip read failed")}\"}"
                    } finally {
                        runCatching { adapter.disableReaderMode(activity) }
                    }
                    promise.resolve(out)
                },
                NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                null,
            )
        }
    }

    private fun readTag(tag: Tag, bacKey: BACKey): String {
        val isoDep = IsoDep.get(tag) ?: throw IllegalStateException("not an ISO-DEP (eMRTD) tag")
        isoDep.timeout = 10_000
        val service = PassportService(
            CardService.getInstance(isoDep),
            PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
            PassportService.DEFAULT_MAX_BLOCKSIZE,
            false,
            false,
        )
        service.open()
        service.sendSelectApplet(false)
        service.doBAC(bacKey)

        val dg1 = DG1File(service.getInputStream(PassportService.EF_DG1))
        val mrz = dg1.mrzInfo

        val fields = JSONObject()
            .put("given_name", mrz.secondaryIdentifier.replace('<', ' ').trim())
            .put("family_name", mrz.primaryIdentifier.replace('<', ' ').trim())
            .put("nationality", mrz.nationality)
            .put("document_number", mrz.documentNumber)
        isoDate(mrz.dateOfBirth)?.let { fields.put("birthdate", it) }
        isoDate(mrz.dateOfExpiry)?.let { fields.put("expiry_date", it) }

        val result = JSONObject().put("fields", fields)

        // DG2 portrait — return raw image bytes (JPEG/JP2/WSQ); the enclave
        // decodes for the face match.
        runCatching {
            val dg2 = DG2File(service.getInputStream(PassportService.EF_DG2))
            val faceImage = dg2.faceInfos.firstOrNull()?.faceImageInfos?.firstOrNull()
            if (faceImage != null) {
                val bytes = faceImage.imageInputStream.readBytes()
                result.put("portraitBase64", Base64.encodeToString(bytes, Base64.NO_WRAP))
            }
        }
        return result.toString()
    }

    // MRZ YYMMDD -> YYYY-MM-DD (years > the current 2-digit year are 19xx).
    private fun isoDate(yymmdd: String?): String? {
        if (yymmdd == null || yymmdd.length != 6) return null
        val yy = yymmdd.substring(0, 2).toIntOrNull() ?: return null
        val mm = yymmdd.substring(2, 4).toIntOrNull() ?: return null
        val dd = yymmdd.substring(4, 6).toIntOrNull() ?: return null
        val currentYy = (java.util.Calendar.getInstance().get(java.util.Calendar.YEAR)) % 100
        val century = if (yy > currentYy) 1900 else 2000
        return "%04d-%02d-%02d".format(century + yy, mm, dd)
    }

    private fun escape(s: String): String =
        s.replace("\\", "\\\\").replace("\"", "\\\"")
}
