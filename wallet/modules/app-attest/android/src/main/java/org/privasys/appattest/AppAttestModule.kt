// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.appattest

import android.content.Context
import android.util.Base64
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.tasks.await
import java.security.MessageDigest

/**
 * Expo module wrapping Android Play Integrity API.
 *
 * On Android, we use Play Integrity tokens instead of iOS App Attest.
 * The broker validates the integrity token with Google's servers.
 */
class AppAttestModule : Module() {
    override fun definition() = ModuleDefinition {
        Name("AppAttest")

        // Every function takes the optional `scope` the JS wrapper + the iOS
        // module accept (a key namespace for App Attest). Android uses Play
        // Integrity, which has no per-scope key, so scope is ignored here — but
        // the parameter MUST exist or the Expo bridge rejects the call with an
        // arity mismatch ("Received 1 arguments, but 0 was expected").
        AsyncFunction("getState") { _scope: String? ->
            // Play Integrity is available on all Google Play devices.
            """{"supported":true,"keyId":null,"attested":false}"""
        }

        AsyncFunction("generateKey") { _scope: String? ->
            // No persistent key needed for Play Integrity — return a placeholder.
            "play-integrity"
        }

        AsyncFunction("attestKey") { challengeBase64: String, _scope: String? ->
            runBlocking(Dispatchers.IO) {
                val context = appContext.reactContext
                    ?: throw Exception("React context not available")
                requestIntegrityToken(context, normaliseNonce(challengeBase64))
            }
        }

        // Mint a Play Integrity token with the given nonce, verbatim. The
        // caller supplies a URL-safe base64 string (Play Integrity's required
        // nonce alphabet); no decode/re-encode happens here. This is the WIA
        // enrolment path, where the IdP pins the exact nonce bytes it will
        // check. attestKey/generateAssertion normalise instead, because the
        // broker hands them STANDARD base64.
        AsyncFunction("integrityToken") { nonce: String ->
            runBlocking(Dispatchers.IO) {
                val context = appContext.reactContext
                    ?: throw Exception("React context not available")
                requestIntegrityToken(context, nonce)
            }
        }

        AsyncFunction("generateAssertion") { clientDataHashBase64: String, _scope: String? ->
            runBlocking(Dispatchers.IO) {
                val context = appContext.reactContext
                    ?: throw Exception("React context not available")
                // For assertions, the client-data hash IS the nonce.
                requestIntegrityToken(context, normaliseNonce(clientDataHashBase64))
            }
        }

        // No-op on Android — Play Integrity has no persistent key state.
        AsyncFunction("reset") { _scope: String? ->
        }
    }

    /**
     * Coerce a server-supplied challenge into a nonce Play Integrity accepts.
     *
     * Play rejects anything outside URL-safe base64 with no line wrapping
     * (error -13, NONCE_IS_NOT_BASE64) and anything shorter than 16 raw bytes
     * (error -10, NONCE_TOO_SHORT). The broker issues its challenge as STANDARD
     * base64, whose '+' and '/' are both outside Play's alphabet, so the string
     * cannot be passed through unchanged. The previous code decoded it and
     * handed Play the resulting bytes as a UTF-8 string — random binary, which
     * tripped -13 or -10 on every call. Android could therefore never obtain an
     * attestation-service token, and every enclave approval reported the
     * attestation service as unavailable (found on a tester's phone
     * 2026-08-26).
     *
     * The rule is decode-then-re-encode, so a verifier recovers the original
     * challenge bytes by base64url-decoding the nonce. Inputs that are not
     * base64, and inputs too short for Play, are hashed to 32 bytes instead: a
     * deterministic fallback rather than a rejected request.
     */
    private fun normaliseNonce(input: String): String {
        val raw = decodeBase64OrNull(input) ?: sha256(input.toByteArray(Charsets.UTF_8))
        val bytes = if (raw.size >= MIN_NONCE_BYTES) raw else sha256(raw)
        return Base64.encodeToString(bytes, NONCE_FLAGS)
    }

    /** Decode standard OR URL-safe base64; null when the input is not base64. */
    private fun decodeBase64OrNull(s: String): ByteArray? = try {
        Base64.decode(s.replace('-', '+').replace('_', '/'), Base64.DEFAULT)
            .takeIf { it.isNotEmpty() }
    } catch (notBase64: IllegalArgumentException) {
        null
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    private suspend fun requestIntegrityToken(context: Context, nonce: String): String {
        val manager = IntegrityManagerFactory.create(context)
        val request = IntegrityTokenRequest.builder()
            .setNonce(nonce)
            .build()
        val response = manager.requestIntegrityToken(request).await()
        return response.token()
    }

    private companion object {
        /** Play Integrity's documented floor for the raw (pre-base64) nonce. */
        const val MIN_NONCE_BYTES = 16
        val NONCE_FLAGS = Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
    }
}
