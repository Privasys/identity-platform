// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.nativeemrtd

import android.graphics.BitmapFactory
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.util.Base64
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import net.sf.scuba.smartcards.CardService
import org.jmrtd.BACKey
import org.jmrtd.PassportService
import org.jmrtd.lds.icao.DG1File
import org.jmrtd.lds.icao.DG2File
import org.jmrtd.lds.icao.DG15File
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.security.SecureRandom
import java.security.Security

/**
 * eMRTD (ICAO 9303) NFC reader, backed by jMRTD (LGPL) over IsoDep.
 *
 * Uses NFC reader-mode on the current activity: when the document chip is
 * tapped, runs BAC with the MRZ-derived key and reads the exact on-chip bytes
 * of EF.SOD + DG1 + DG2 (the verification minimum), plus DG11 (extra personal
 * details) and DG15 (the Active Authentication key) when present. It returns the
 * raw EF.SOD + data groups so the enclave can run Passive Authentication and the
 * DG2 face match itself, and — when the chip carries DG15 — relays an Active
 * Authentication signature over a fresh challenge so the enclave can prove the
 * chip is the original and not a clone. Parity with the iOS reader. Needs the
 * NFC permission and an NFC-capable device. The chip data only leaves the device
 * for the RA-TLS hop to the verifier enclave (services/kyc.ts).
 */
class NativeEmrtdModule : Module() {
    init {
        // jMRTD 0.7.x relies on a registered BouncyCastle JCE provider.
        try {
            Security.insertProviderAt(org.bouncycastle.jce.provider.BouncyCastleProvider(), 1)
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

        AsyncFunction("scanMrz") { imageBase64: String, promise: Promise ->
            val bytes = try {
                Base64.decode(imageBase64, Base64.DEFAULT)
            } catch (_: Throwable) {
                null
            }
            val bitmap = bytes?.let { BitmapFactory.decodeByteArray(it, 0, it.size) }
            if (bitmap == null) {
                promise.resolve("{\"error\":\"could not decode the photo\"}")
                return@AsyncFunction
            }

            val recognizer = TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS)
            recognizer.process(InputImage.fromBitmap(bitmap, 0))
                .addOnSuccessListener { text ->
                    val lines = JSONArray()
                    text.textBlocks.forEach { block ->
                        block.lines.forEach { line -> lines.put(line.text) }
                    }
                    promise.resolve(JSONObject().put("lines", lines).toString())
                }
                .addOnFailureListener { error ->
                    promise.resolve(
                        JSONObject()
                            .put("error", error.localizedMessage ?: "text recognition failed")
                            .toString()
                    )
                }
                .addOnCompleteListener {
                    bitmap.recycle()
                    recognizer.close()
                }
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

        // Exact on-chip bytes — the enclave runs Passive Authentication (EF.SOD
        // CMS → DSC → CSCA + per-DG hash) and the DG2 face match from these, so
        // we forward the raw files rather than re-encoded objects. SOD + DG1 + DG2
        // are required; DG11 + DG15 are best-effort (an absent group answers the
        // SELECT with SW 0x6A88, which must not fail the whole read).
        val sodBytes = readEf(service, PassportService.EF_SOD)
        val dg1Bytes = readEf(service, PassportService.EF_DG1)
        val dg2Bytes = readEf(service, PassportService.EF_DG2)
        val dg11Bytes = runCatching { readEf(service, PassportService.EF_DG11) }.getOrNull()
        val dg15Bytes = runCatching { readEf(service, PassportService.EF_DG15) }.getOrNull()

        val mrz = DG1File(ByteArrayInputStream(dg1Bytes)).mrzInfo
        val fields = JSONObject()
            .put("given_name", mrz.secondaryIdentifier.replace('<', ' ').trim())
            .put("family_name", mrz.primaryIdentifier.replace('<', ' ').trim())
            .put("nationality", mrz.nationality)
            .put("document_number", mrz.documentNumber)
        isoDate(mrz.dateOfBirth)?.let { fields.put("birthdate", it) }
        isoDate(mrz.dateOfExpiry)?.let { fields.put("expiry_date", it) }

        val dataGroups = JSONObject()
            .put("1", b64(dg1Bytes))
            .put("2", b64(dg2Bytes))
        dg11Bytes?.let { dataGroups.put("11", b64(it)) }

        val result = JSONObject()
            .put("fields", fields)
            .put("sod", b64(sodBytes))
            .put("dataGroups", dataGroups)

        // DG2 portrait for the wallet's local display (picture_id); the enclave
        // does its own face match from the raw DG2 above.
        runCatching {
            val dg2 = DG2File(ByteArrayInputStream(dg2Bytes))
            val faceImage = dg2.faceInfos.firstOrNull()?.faceImageInfos?.firstOrNull()
            if (faceImage != null) {
                val bytes = faceImage.imageInputStream.readBytes()
                result.put("portraitBase64", Base64.encodeToString(bytes, Base64.NO_WRAP))
            }
        }

        // Active Authentication (anti-clone): when the chip carries DG15, have it
        // sign a fresh random challenge with its non-extractable AA key, and relay
        // the challenge + signature for the enclave to verify against DG15. DG15
        // and the aa block are emitted *together or not at all* — the enclave
        // requires AA whenever DG15 is present, so a DG15 without a usable
        // signature would spuriously hard-fail a genuine read.
        if (dg15Bytes != null) {
            runCatching {
                val aaKey = DG15File(ByteArrayInputStream(dg15Bytes)).publicKey
                val challenge = ByteArray(8).also { SecureRandom().nextBytes(it) }
                val sigAlg = if (aaKey.algorithm.equals("EC", true)) "SHA256withECDSA"
                             else "SHA1withRSA/ISO9796-2"
                val response = service.doAA(aaKey, "SHA-256", sigAlg, challenge).response
                if (response != null && response.isNotEmpty()) {
                    dataGroups.put("15", b64(dg15Bytes))
                    result.put(
                        "aa",
                        JSONObject()
                            .put("challenge", b64url(challenge))
                            .put("signature", b64url(response)),
                    )
                }
            }
        }
        return result.toString()
    }

    /** Read a data group / EF's exact on-chip bytes over the open secure channel. */
    private fun readEf(service: PassportService, fid: Short): ByteArray =
        service.getInputStream(fid).readBytes()

    /** Standard base64 (padded) for EF.SOD + data groups — the enclave decodes
     *  these tolerantly. */
    private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

    /** Base64url (no padding) for the AA challenge + signature — the shape the
     *  enclave's b64u_decode expects. */
    private fun b64url(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

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
