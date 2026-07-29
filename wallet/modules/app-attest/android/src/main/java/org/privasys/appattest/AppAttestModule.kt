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
                val challenge = String(
                    Base64.decode(challengeBase64, Base64.DEFAULT),
                    Charsets.UTF_8
                )
                requestIntegrityToken(context, challenge)
            }
        }

        AsyncFunction("generateAssertion") { clientDataHashBase64: String, _scope: String? ->
            runBlocking(Dispatchers.IO) {
                val context = appContext.reactContext
                    ?: throw Exception("React context not available")
                // For assertions, use the hash as the nonce.
                requestIntegrityToken(context, clientDataHashBase64)
            }
        }

        // No-op on Android — Play Integrity has no persistent key state.
        AsyncFunction("reset") { _scope: String? ->
        }
    }

    private suspend fun requestIntegrityToken(context: Context, nonce: String): String {
        val manager = IntegrityManagerFactory.create(context)
        val request = IntegrityTokenRequest.builder()
            .setNonce(nonce)
            .build()
        val response = manager.requestIntegrityToken(request).await()
        return response.token()
    }
}
