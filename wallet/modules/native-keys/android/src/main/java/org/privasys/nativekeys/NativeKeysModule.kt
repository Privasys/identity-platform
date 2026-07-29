// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.nativekeys

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

class NativeKeysModule : Module() {
    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    }

    companion object {
        // Seconds a strong biometric keeps a signing key usable after the OS
        // prompt. Time-bound (not per-use) so one biometric shown by the signing
        // flow covers the burst of signatures in a ceremony — mirroring the iOS
        // Secure Enclave reuse window. Long enough for one connect ceremony.
        private const val AUTH_VALIDITY_SECONDS = 30
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
    }

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
