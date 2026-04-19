// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.wallet.passkey

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
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
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * Privasys Wallet Credential Provider Service.
 *
 * Android 14+ invokes this when a website calls `navigator.credentials.get()`
 * and the RP ID matches a domain associated with this app.
 *
 * Flow:
 * 1. onBeginGetCredentialRequest — system asks which credentials we have for the RP
 * 2. If RP is a Privasys enclave: verify attestation via RA-TLS (JNI to Rust FFI)
 * 3. User selects credential → system calls back for assertion
 * 4. Sign the challenge with StrongBox/TEE-backed key
 * 5. Return the signed assertion
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE) // API 34 (Android 14)
class PrivasysCredentialProviderService : CredentialProviderService() {

    companion object {
        private const val PREFS_NAME = "org.privasys.wallet.credentials"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

        /** AAGUID for Privasys Wallet — matches fido2.ts and iOS extension. */
        private val AAGUID = byteArrayOf(
            0xf4.toByte(), 0x7a.toByte(), 0xc1.toByte(), 0x0b.toByte(),
            0x58.toByte(), 0xcc.toByte(), 0x43.toByte(), 0x72.toByte(),
            0xa5.toByte(), 0x67.toByte(), 0x0e.toByte(), 0x02.toByte(),
            0xb2.toByte(), 0xc3.toByte(), 0xd4.toByte(), 0x79.toByte()
        )
    }

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
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

    /**
     * Called by the system with the full credential creation request after the user
     * picks our provider. Generate a StrongBox-backed key and return the attestation.
     */
    fun handleCreateCredential(rpId: String, clientDataHash: ByteArray): ByteArray? {
        val keyAlias = "org.privasys.wallet.fido2.$rpId.${UUID.randomUUID()}"

        // Generate P-256 key in StrongBox (falls back to TEE if unavailable)
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER
        )
        val specBuilder = KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            specBuilder.setIsStrongBoxBacked(true)
        }

        try {
            keyPairGenerator.initialize(specBuilder.build())
        } catch (_: Exception) {
            // StrongBox not available, fall back to TEE
            specBuilder.setIsStrongBoxBacked(false)
            keyPairGenerator.initialize(specBuilder.build())
        }

        val keyPair = keyPairGenerator.generateKeyPair()
        val publicKeyEncoded = keyPair.public.encoded // X.509 SubjectPublicKeyInfo

        // Extract raw x, y from the X.509 encoding (last 64 bytes for uncompressed P-256)
        val rawPublicKey = extractRawECPublicKey(publicKeyEncoded)
            ?: return null

        val credentialId = MessageDigest.getInstance("SHA-256").digest(publicKeyEncoded)

        // Build authenticator data
        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        val authData = buildRegistrationAuthData(rpIdHash, credentialId, rawPublicKey)

        // Build attestation object (fmt: "none")
        val attestationObject = buildAttestationObjectCBOR(authData)

        // Store credential mapping
        storeCredential(rpId, credentialId, keyAlias)

        return attestationObject
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

            val entries = mutableListOf<CredentialEntry>()
            for ((key, value) in allCredentials) {
                if (value !is String) continue
                try {
                    val entry = JSONObject(value)
                    val rpId = entry.getString("rpId")
                    val beginOption = request.beginGetCredentialOptions
                        .filterIsInstance<androidx.credentials.provider.BeginGetPublicKeyCredentialOption>()
                        .firstOrNull() ?: continue
                    entries.add(
                        PublicKeyCredentialEntry.Builder(
                            applicationContext,
                            rpId,
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

    /**
     * Sign an assertion challenge for the given credential.
     */
    fun handleGetAssertion(
        rpId: String,
        credentialId: ByteArray,
        clientDataHash: ByteArray
    ): Pair<ByteArray, ByteArray>? { // (authenticatorData, signature)
        val keyAlias = lookupKeyAlias(rpId, credentialId) ?: return null

        val privateKeyEntry = keyStore.getEntry(keyAlias, null) as? KeyStore.PrivateKeyEntry
            ?: return null

        // Build authenticator data (no attested credential data for assertions)
        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        val authData = buildAssertionAuthData(rpIdHash, credentialId)

        // Sign: authData || clientDataHash
        val signInput = authData + clientDataHash
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(privateKeyEntry.privateKey)
        sig.update(signInput)
        val signature = sig.sign()

        return Pair(authData, signature)
    }

    // ─── Clear State ───────────────────────────────────────────────────

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>
    ) {
        // Delete all credential entries
        val prefs = getPrefs()
        val allCredentials = prefs.all
        for ((_, value) in allCredentials) {
            if (value !is String) continue
            try {
                val entry = JSONObject(value)
                val keyAlias = entry.getString("keyAlias")
                keyStore.deleteEntry(keyAlias)
            } catch (_: Exception) {
                // Best effort
            }
        }
        prefs.edit().clear().apply()
        callback.onResult(null)
    }

    // ─── Credential Storage ────────────────────────────────────────────

    private fun storeCredential(rpId: String, credentialId: ByteArray, keyAlias: String) {
        val credIdB64 = Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_WRAP)
        val entry = JSONObject().apply {
            put("rpId", rpId)
            put("credentialId", credIdB64)
            put("keyAlias", keyAlias)
            put("createdAt", System.currentTimeMillis())
        }
        getPrefs().edit()
            .putString("$rpId:$credIdB64", entry.toString())
            .apply()
    }

    private fun lookupKeyAlias(rpId: String, credentialId: ByteArray): String? {
        val credIdB64 = Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_WRAP)
        val json = getPrefs().getString("$rpId:$credIdB64", null) ?: return null
        return try {
            JSONObject(json).getString("keyAlias")
        } catch (_: Exception) {
            null
        }
    }

    // ─── Auth Data Builders ────────────────────────────────────────────

    private fun buildRegistrationAuthData(
        rpIdHash: ByteArray,
        credentialId: ByteArray,
        rawPublicKey: ByteArray // 64 bytes: x || y
    ): ByteArray {
        val x = rawPublicKey.sliceArray(0 until 32)
        val y = rawPublicKey.sliceArray(32 until 64)

        val coseKey = buildCoseKey(x, y)

        val authData = mutableListOf<Byte>()
        authData.addAll(rpIdHash.toList())       // 32 bytes
        authData.add(0x45)                        // flags: UP | UV | AT
        authData.addAll(byteArrayOf(0, 0, 0, 0).toList()) // signCount = 0
        authData.addAll(AAGUID.toList())          // 16 bytes
        authData.add(((credentialId.size shr 8) and 0xFF).toByte())
        authData.add((credentialId.size and 0xFF).toByte())
        authData.addAll(credentialId.toList())
        authData.addAll(coseKey.toList())

        return authData.toByteArray()
    }

    private fun buildAssertionAuthData(rpIdHash: ByteArray, credentialId: ByteArray): ByteArray {
        val authData = mutableListOf<Byte>()
        authData.addAll(rpIdHash.toList())
        authData.add(0x05)                        // flags: UP | UV
        // Platform authenticator: always send signCount=0 (non-exportable key)
        authData.add(0)
        authData.add(0)
        authData.add(0)
        authData.add(0)
        return authData.toByteArray()
    }

    // ─── CBOR / COSE Helpers ───────────────────────────────────────────

    private fun buildCoseKey(x: ByteArray, y: ByteArray): ByteArray {
        val cbor = mutableListOf<Byte>()
        cbor.add(0xa5.toByte()) // Map(5)

        // 1 (kty) => 2 (EC2)
        cbor.addAll(byteArrayOf(0x01, 0x02).toList())
        // 3 (alg) => -7 (ES256)
        cbor.addAll(byteArrayOf(0x03, 0x26).toList())
        // -1 (crv) => 1 (P-256)
        cbor.addAll(byteArrayOf(0x20, 0x01).toList())
        // -2 (x) => bstr(32)
        cbor.addAll(byteArrayOf(0x21, 0x58, 0x20).toList())
        cbor.addAll(x.toList())
        // -3 (y) => bstr(32)
        cbor.addAll(byteArrayOf(0x22, 0x58, 0x20).toList())
        cbor.addAll(y.toList())

        return cbor.toByteArray()
    }

    private fun buildAttestationObjectCBOR(authData: ByteArray): ByteArray {
        val cbor = mutableListOf<Byte>()
        cbor.add(0xa3.toByte()) // Map(3)

        // "fmt" => "none"
        cbor.addAll(byteArrayOf(0x63, 0x66, 0x6d, 0x74).toList())
        cbor.addAll(byteArrayOf(0x64, 0x6e, 0x6f, 0x6e, 0x65).toList())

        // "attStmt" => {}
        cbor.addAll(byteArrayOf(0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74).toList())
        cbor.add(0xa0.toByte())

        // "authData" => bstr
        cbor.addAll(byteArrayOf(0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61).toList())
        if (authData.size < 256) {
            cbor.addAll(byteArrayOf(0x58, authData.size.toByte()).toList())
        } else {
            cbor.addAll(byteArrayOf(
                0x59,
                ((authData.size shr 8) and 0xFF).toByte(),
                (authData.size and 0xFF).toByte()
            ).toList())
        }
        cbor.addAll(authData.toList())

        return cbor.toByteArray()
    }

    /** Extract raw 64-byte EC public key (x || y) from X.509 SubjectPublicKeyInfo DER. */
    private fun extractRawECPublicKey(encoded: ByteArray): ByteArray? {
        // X.509 SPKI for P-256 ends with 04 || x (32) || y (32)
        if (encoded.size < 65) return null
        val offset = encoded.size - 65
        if (encoded[offset] != 0x04.toByte()) return null
        return encoded.sliceArray(offset + 1 until encoded.size)
    }
}
