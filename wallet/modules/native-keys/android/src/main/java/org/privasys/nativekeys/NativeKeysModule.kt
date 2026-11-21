// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.nativekeys

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.json.JSONArray
import org.json.JSONObject

class NativeKeysModule : Module() {
    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    }

    companion object {
        // Cryptographic unlock window for a signing key after a strong biometric.
        // This is the hardware layer that BACKS the JS "Biometric Grace Period"
        // (settings.gracePeriodSec): it MUST be >= the largest grace option
        // (GRACE_OPTIONS max = 60s) so the key is still unlocked whenever the JS
        // gate decides to skip re-prompting. The margin above 60 covers the
        // biometric→signature delay. Not user-facing — it is the enforcement
        // ceiling, distinct from the user's re-prompt cadence.
        private const val AUTH_VALIDITY_SECONDS = 75

        // Website passkeys: names shared with modules/passkey-provider.
        private const val CREDENTIAL_PREFS = "org.privasys.wallet.credentials"
        private const val ROOT_PREFS = "org.privasys.wallet.passkey-root"
        private const val ROOT_PREF_KEY = "root"
        private const val ROOT_WRAP_KEY_ALIAS = "org.privasys.wallet.passkey-root-wrap"
        private const val ROOT_GCM_IV_BYTES = 12
        private const val KIND_LOCAL = "local"
        private const val KIND_SYNCED = "synced"
    }

    override fun definition() = ModuleDefinition {
        Name("NativeKeys")

        AsyncFunction("generateKey") { keyId: String, requireBiometric: Boolean ->
            runBlocking(Dispatchers.IO) { generateKeyImpl(keyId, requireBiometric) }
        }

        AsyncFunction("sign") { keyId: String, dataBase64url: String ->
            runBlocking(Dispatchers.IO) { signImpl(keyId, dataBase64url) }
        }

        AsyncFunction("keyExists") { keyId: String ->
            keyStore.containsAlias(aliasFor(keyId))
        }

        AsyncFunction("deleteKey") { keyId: String ->
            val alias = aliasFor(keyId)
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        }

        AsyncFunction("getPublicKey") { keyId: String ->
            runBlocking(Dispatchers.IO) { getPublicKeyImpl(keyId) }
        }

        // ── Website passkeys ─────────────────────────────────────────────
        // The credential provider (modules/passkey-provider) keeps one record
        // per passkey in the "org.privasys.wallet.credentials" prefs and
        // derives the keys of "synced" ones from a root the wallet gives it.
        // These read and write the same prefs (the .operations
        // website-passkeys plan). The provider runs in this app's process.

        AsyncFunction("setPasskeyRoot") { rootB64url: String ->
            val root = try { base64urlDecodeLenient(rootB64url) } catch (_: Exception) { null }
            if (root == null || root.size != 32) {
                throw IllegalArgumentException("the passkey root must be 32 bytes, base64url")
            }
            try {
                writePasskeyRoot(root)
            } finally {
                root.fill(0)
            }
        }

        AsyncFunction("clearPasskeyRoot") {
            rootPrefs().edit().remove(ROOT_PREF_KEY).commit()
            if (keyStore.containsAlias(ROOT_WRAP_KEY_ALIAS)) keyStore.deleteEntry(ROOT_WRAP_KEY_ALIAS)
        }

        AsyncFunction("listWebsitePasskeys") {
            listWebsitePasskeysImpl()
        }

        AsyncFunction("importWebsitePasskeys") { json: String ->
            importWebsitePasskeysImpl(json)
        }

        AsyncFunction("deleteWebsitePasskey") { rpId: String, credentialIdB64url: String ->
            deleteWebsitePasskeyImpl(rpId, credentialIdB64url)
        }
    }

    // ─── Website passkey root ──────────────────────────────────────────
    //
    // Stored wrapped by a non-exportable Keystore AES-GCM key with no user
    // authentication: the provider must read it before it shows its own
    // biometric prompt, and the wrap is there so the root never sits in the
    // prefs file in the clear. The credential provider's PasskeyRootStore
    // (PrivasysCredentialProviderService.kt) reads it; the two modules are
    // separate Gradle libraries, so that reader is a duplicate of the layout
    // here. Names and layout MUST stay identical:
    // prefs ROOT_PREFS, key ROOT_PREF_KEY, value base64(iv(12) || AES-GCM(root) || tag).

    private val hostContext: Context
        get() = appContext.reactContext ?: throw IllegalStateException("no React context")

    private fun rootPrefs(): SharedPreferences =
        hostContext.getSharedPreferences(ROOT_PREFS, Context.MODE_PRIVATE)

    private fun credentialPrefs(): SharedPreferences =
        hostContext.getSharedPreferences(CREDENTIAL_PREFS, Context.MODE_PRIVATE)

    private fun rootWrapKey(): SecretKey {
        (keyStore.getKey(ROOT_WRAP_KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                ROOT_WRAP_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    private fun writePasskeyRoot(root: ByteArray) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // The Keystore picks the IV (randomised encryption), so it is read back from the cipher.
        cipher.init(Cipher.ENCRYPT_MODE, rootWrapKey())
        val iv = cipher.iv
        check(iv.size == ROOT_GCM_IV_BYTES) { "unexpected GCM IV length" }
        val blob = iv + cipher.doFinal(root)
        // commit, not apply: the wallet may hand off to the provider straight after.
        rootPrefs().edit().putString(ROOT_PREF_KEY, Base64.encodeToString(blob, Base64.NO_WRAP)).commit()
    }

    // ─── Website passkey records ───────────────────────────────────────
    //
    // A record is keyed "$rpId:$credIdB64" where credIdB64 is the id in
    // URL_SAFE | NO_WRAP Base64 (padded), as the provider has always written
    // it; the outside world (and iOS) uses unpadded base64url, so ids are
    // normalised on the way in and out.

    private fun listWebsitePasskeysImpl(): String {
        val out = JSONArray()
        for ((_, value) in credentialPrefs().all) {
            if (value !is String) continue
            val record = try { JSONObject(value) } catch (_: Exception) { continue }
            val rpId = record.optString("rpId", "")
            val credentialId = try {
                base64urlDecodeLenient(record.optString("credentialId", ""))
            } catch (_: Exception) {
                continue
            }
            if (rpId.isEmpty() || credentialId.isEmpty()) continue
            // "userId" is the field older records used for the same value.
            val userHandle = record.optString("userHandle", "").ifEmpty { record.optString("userId", "") }
            out.put(JSONObject().apply {
                put("rpId", rpId)
                put("credentialId", base64urlEncode(credentialId))
                put("userName", record.optString("userName", ""))
                put("userHandle", normaliseB64url(userHandle))
                // A record without a kind predates synced passkeys: local.
                put("kind", if (record.optString("kind", KIND_LOCAL) == KIND_SYNCED) KIND_SYNCED else KIND_LOCAL)
                put("createdAt", record.optLong("createdAt", 0L))
            })
        }
        return out.toString()
    }

    private fun importWebsitePasskeysImpl(json: String): Int {
        val entries = try {
            JSONArray(json)
        } catch (_: Exception) {
            throw IllegalArgumentException("the website passkey list must be a JSON array")
        }
        val prefs = credentialPrefs()
        val editor = prefs.edit()
        var added = 0
        for (i in 0 until entries.length()) {
            val entry = entries.optJSONObject(i) ?: continue
            // Synced passkeys only: a local one's key stays on the device that
            // made it, so its record would be useless anywhere else.
            if (entry.optString("kind", "") != KIND_SYNCED) continue
            val rpId = entry.optString("rpId", "")
            val credentialId = try {
                base64urlDecodeLenient(entry.optString("credentialId", ""))
            } catch (_: Exception) {
                continue
            }
            if (rpId.isEmpty() || !isSyncedCredentialId(credentialId)) continue

            val credIdB64 = Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_WRAP)
            val prefKey = "$rpId:$credIdB64"
            if (prefs.contains(prefKey)) continue

            val userHandle = normaliseB64url(entry.optString("userHandle", ""))
            val createdAt = entry.optLong("createdAt", 0L).takeIf { it > 0 } ?: System.currentTimeMillis()
            // The same shape PasskeyActivity writes, so the provider cannot
            // tell an imported record from one it made. Android has no identity
            // store to register with: the provider lists these prefs each time
            // the system asks.
            val record = JSONObject().apply {
                put("rpId", rpId)
                put("credentialId", credIdB64)
                put("kind", KIND_SYNCED)
                put("userId", userHandle)
                put("userHandle", userHandle)
                put("userName", entry.optString("userName", ""))
                put("createdAt", createdAt)
            }
            editor.putString(prefKey, record.toString())
            added++
        }
        if (added > 0) editor.commit()
        return added
    }

    private fun deleteWebsitePasskeyImpl(rpId: String, credentialIdB64url: String) {
        val credentialId = try { base64urlDecodeLenient(credentialIdB64url) } catch (_: Exception) { return }
        val prefKey = "$rpId:" + Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_WRAP)
        val prefs = credentialPrefs()
        val record = prefs.getString(prefKey, null)?.let { try { JSONObject(it) } catch (_: Exception) { null } }
        // A local passkey's Keystore key goes with it; a synced one has none.
        val keyAlias = record?.optString("keyAlias", "") ?: ""
        if (keyAlias.isNotEmpty() && keyStore.containsAlias(keyAlias)) keyStore.deleteEntry(keyAlias)
        prefs.edit().remove(prefKey).commit()
    }

    private fun isSyncedCredentialId(credentialId: ByteArray) =
        credentialId.size == 17 && credentialId[0] == 0x01.toByte()

    /** Accepts base64url with or without padding, or standard base64, as the wallet and iOS may send either. */
    private fun base64urlDecodeLenient(str: String): ByteArray =
        Base64.decode(
            str.trim().replace('+', '-').replace('/', '_').trimEnd('='),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        )

    private fun normaliseB64url(str: String): String =
        if (str.isEmpty()) "" else try { base64urlEncode(base64urlDecodeLenient(str)) } catch (_: Exception) { str }

    private fun aliasFor(keyId: String) = "org.privasys.wallet.key.$keyId"

    private fun generateKeyImpl(keyId: String, requireBiometric: Boolean): String {
        val alias = aliasFor(keyId)

        // Return existing key if present
        if (keyStore.containsAlias(alias)) {
            return getPublicKeyImpl(keyId)
        }

        val paramBuilder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)

        // Try StrongBox first, fall back to TEE
        var hardwareBacked = true
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            paramBuilder.setIsStrongBoxBacked(true)
        }

        if (requireBiometric) {
            // Time-bound, NOT per-use: a strong biometric authenticated within
            // AUTH_VALIDITY_SECONDS unlocks the key, so a single OS biometric
            // shown by the signing flow (fido2 register/authenticate, vault
            // approval) covers the whole ceremony. A per-use key (timeout 0)
            // would instead demand a CryptoObject-bound BiometricPrompt on every
            // signature — which the flows do not do, giving KEY_USER_NOT_AUTHENTICATED.
            paramBuilder.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // Strong biometric OR device credential: mirrors the OS prompts
                // (which allow a passcode fallback), so either unlocks the key.
                // If StrongBox rejects this combination the catch below retries
                // on the TEE, which is still hardware-backed.
                paramBuilder.setUserAuthenticationParameters(
                    AUTH_VALIDITY_SECONDS,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                )
            } else {
                @Suppress("DEPRECATION")
                paramBuilder.setUserAuthenticationValidityDurationSeconds(AUTH_VALIDITY_SECONDS)
            }
        }

        try {
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            kpg.initialize(paramBuilder.build())
            val keyPair = kpg.generateKeyPair()
            val pubBytes = encodeUncompressedPoint(keyPair.public as ECPublicKey)
            return keyInfoJson(keyId, pubBytes, hardwareBacked)
        } catch (e: Exception) {
            // StrongBox not available — retry without it
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                paramBuilder.setIsStrongBoxBacked(false)
                hardwareBacked = true // TEE is still hardware-backed
                val kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
                )
                kpg.initialize(paramBuilder.build())
                val keyPair = kpg.generateKeyPair()
                val pubBytes = encodeUncompressedPoint(keyPair.public as ECPublicKey)
                return keyInfoJson(keyId, pubBytes, hardwareBacked)
            }
            return """{"error":"${e.message?.replace("\"", "\\\"")}"}"""
        }
    }

    private fun signImpl(keyId: String, dataBase64url: String): String {
        val alias = aliasFor(keyId)
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: return """{"error":"key not found"}"""

        val data = base64urlDecode(dataBase64url)
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(entry.privateKey)
        sig.update(data)
        val signature = sig.sign()
        return """{"signature":"${base64urlEncode(signature)}"}"""
    }

    private fun getPublicKeyImpl(keyId: String): String {
        val alias = aliasFor(keyId)
        val cert = keyStore.getCertificate(alias)
            ?: return """{"error":"key not found"}"""
        val ecPub = cert.publicKey as? ECPublicKey
            ?: return """{"error":"not an EC key"}"""
        val pubBytes = encodeUncompressedPoint(ecPub)
        return keyInfoJson(keyId, pubBytes, true)
    }

    private fun encodeUncompressedPoint(pub: ECPublicKey): ByteArray {
        val x = pub.w.affineX.toByteArray().padOrTrim(32)
        val y = pub.w.affineY.toByteArray().padOrTrim(32)
        return byteArrayOf(0x04) + x + y
    }

    private fun ByteArray.padOrTrim(len: Int): ByteArray {
        return when {
            size == len -> this
            size > len -> copyOfRange(size - len, size) // strip leading zero
            else -> ByteArray(len - size) + this         // left-pad
        }
    }

    private fun keyInfoJson(keyId: String, publicKey: ByteArray, hardwareBacked: Boolean): String {
        val b64 = base64urlEncode(publicKey)
        return """{"keyId":"$keyId","publicKey":"$b64","hardwareBacked":$hardwareBacked}"""
    }

    private fun base64urlEncode(data: ByteArray): String =
        Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun base64urlDecode(str: String): ByteArray =
        Base64.decode(str, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
}
