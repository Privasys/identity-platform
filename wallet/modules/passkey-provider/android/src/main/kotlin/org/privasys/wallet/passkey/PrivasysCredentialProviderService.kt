// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.wallet.passkey

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.util.Base64
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.PublicKeyCredentialEntry
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Reads the website passkey root the wallet stored with
 * NativeKeysModule.setPasskeyRoot.
 *
 * This is a deliberate duplicate of the reading half of the store in
 * modules/native-keys (NativeKeysModule.kt, "Website passkey root"): the two
 * are separate Gradle libraries with no dependency between them, and the
 * credential provider runs in the app's own process, so reading the same
 * private SharedPreferences and the same Keystore key is enough. The names
 * and the blob layout below MUST stay identical to that file.
 *
 * Layout: prefs [ROOT_PREFS], key [ROOT_PREF_KEY], value base64(iv(12) || AES-GCM(root) || tag).
 */
internal object PasskeyRootStore {
    const val ROOT_PREFS = "org.privasys.wallet.passkey-root"
    const val ROOT_PREF_KEY = "root"
    const val WRAP_KEY_ALIAS = "org.privasys.wallet.passkey-root-wrap"
    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BITS = 128

    fun exists(context: Context): Boolean =
        context.getSharedPreferences(ROOT_PREFS, Context.MODE_PRIVATE).contains(ROOT_PREF_KEY)

    /** The 32-byte root, or null when the wallet has none (no seed yet, or wiped). The caller wipes it after use. */
    fun read(context: Context): ByteArray? = try {
        val blob = context.getSharedPreferences(ROOT_PREFS, Context.MODE_PRIVATE)
            .getString(ROOT_PREF_KEY, null)
            ?.let { Base64.decode(it, Base64.NO_WRAP) }
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = keyStore.getKey(WRAP_KEY_ALIAS, null) as? SecretKey
        if (blob == null || key == null || blob.size <= GCM_IV_BYTES) {
            null
        } else {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, blob, 0, GCM_IV_BYTES))
            cipher.doFinal(blob, GCM_IV_BYTES, blob.size - GCM_IV_BYTES).takeIf { it.size == 32 }
        }
    } catch (_: Exception) {
        // A missing or unreadable root means "no synced passkeys here", never a crash in the picker.
        null
    }
}

/**
 * Privasys Wallet Credential Provider Service.
 *
 * Android 14+ asks it which passkeys the wallet offers when a website or app
 * calls `navigator.credentials.create()` or `get()`. It answers with entries
 * only; choosing one opens PasskeyActivity, which verifies the relying party
 * (over RA-TLS for a Privasys enclave), asks the holder, and makes or signs
 * with the passkey.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE) // API 34 (Android 14)
class PrivasysCredentialProviderService : CredentialProviderService() {

    companion object {
        private const val PREFS_NAME = "org.privasys.wallet.credentials"
    }

    private fun getPrefs(): SharedPreferences =
        applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // ─── Registration ──────────────────────────────────────────────────

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>
    ) {
        try {
            val createEntries = listOf(
                CreateEntry.Builder(
                    "Privasys Wallet",
                    android.app.PendingIntent.getActivity(
                        applicationContext, 0,
                        android.content.Intent(applicationContext, PasskeyActivity::class.java).apply {
                            putExtra(PasskeyActivity.EXTRA_ACTION, PasskeyActivity.ACTION_CREATE)
                        },
                        android.app.PendingIntent.FLAG_MUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT
                    )
                ).build()
            )

            callback.onResult(
                BeginCreateCredentialResponse.Builder()
                    .setCreateEntries(createEntries)
                    .build()
            )
        } catch (e: Exception) {
            callback.onError(
                CreateCredentialUnknownException(e.message)
            )
        }
    }

    // ─── Assertion ─────────────────────────────────────────────────────

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>
    ) {
        try {
            val prefs = getPrefs()
            val allCredentials = prefs.all

            if (allCredentials.isEmpty()) {
                callback.onError(
                    GetCredentialUnknownException("No stored credentials")
                )
                return
            }

            // Without the root a synced passkey cannot be derived, so offering
            // it would only lead to a failed sign-in.
            val hasRoot = PasskeyRootStore.exists(applicationContext)

            val entries = mutableListOf<CredentialEntry>()
            for ((key, value) in allCredentials) {
                if (value !is String) continue
                try {
                    val entry = JSONObject(value)
                    val rpId = entry.getString("rpId")
                    val kind = entry.optString("kind", "")
                    if (kind != "local" && kind != "synced") continue
                    if (kind == "synced" && !hasRoot) continue
                    val beginOption = request.beginGetCredentialOptions
                        .filterIsInstance<androidx.credentials.provider.BeginGetPublicKeyCredentialOption>()
                        .firstOrNull() ?: continue
                    // Only surface credentials for the RP actually being asked
                    // about — offering every stored passkey for every site both
                    // confuses the picker and leaks which RPs the user holds
                    // credentials for.
                    val requestedRpId = try {
                        JSONObject(beginOption.requestJson).optString("rpId", "")
                    } catch (_: Exception) {
                        ""
                    }
                    if (requestedRpId.isNotEmpty() && requestedRpId != rpId) continue
                    entries.add(
                        PublicKeyCredentialEntry.Builder(
                            applicationContext,
                            // The account name tells two passkeys for one site apart; a site may send none.
                            entry.optString("userName", "").ifEmpty { rpId },
                            android.app.PendingIntent.getActivity(
                                applicationContext, entries.size,
                                android.content.Intent(applicationContext, PasskeyActivity::class.java).apply {
                                    putExtra(PasskeyActivity.EXTRA_ACTION, PasskeyActivity.ACTION_GET)
                                    putExtra("rpId", rpId)
                                    putExtra("credentialId", entry.getString("credentialId"))
                                },
                                android.app.PendingIntent.FLAG_MUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT
                            ),
                            beginOption
                        ).build()
                    )
                } catch (_: Exception) {
                    // Skip malformed entries
                }
            }

            callback.onResult(
                BeginGetCredentialResponse.Builder()
                    .setCredentialEntries(entries)
                    .build()
            )
        } catch (e: Exception) {
            callback.onError(
                GetCredentialUnknownException(e.message)
            )
        }
    }

    // ─── Clear State ───────────────────────────────────────────────────

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>
    ) {
        // Any app calls clearCredentialState when its user signs out. It asks
        // the provider to forget session state (a remembered choice, say), not
        // to destroy credentials: deleting every passkey here would wipe the
        // holder's passkeys for all websites whenever any one app signed out.
        // We keep no such session state, so there is nothing to clear.
        // Passkeys are removed only through deleteWebsitePasskey or the
        // wallet's wipe.
        callback.onResult(null)
    }
}
