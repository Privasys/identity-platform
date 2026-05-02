// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.wallet.passkey

import android.app.Activity
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.PendingIntentHandler
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.util.UUID

/**
 * Activity launched by PendingIntent when the system invokes Privasys Wallet
 * as a credential provider. Verifies enclave attestation via RA-TLS before
 * creating or signing WebAuthn credentials.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class PasskeyActivity : Activity() {

    companion object {
        const val EXTRA_ACTION = "org.privasys.wallet.passkey.ACTION"
        const val ACTION_CREATE = "create"
        const val ACTION_GET = "get"

        private const val PREFS_NAME = "org.privasys.wallet.credentials"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

        private val AAGUID = byteArrayOf(
            0xf4.toByte(), 0x7a.toByte(), 0xc1.toByte(), 0x0b.toByte(),
            0x58.toByte(), 0xcc.toByte(), 0x43.toByte(), 0x72.toByte(),
            0xa5.toByte(), 0x67.toByte(), 0x0e.toByte(), 0x02.toByte(),
            0xb2.toByte(), 0xc3.toByte(), 0xd4.toByte(), 0x79.toByte()
        )
    }

    private lateinit var statusText: TextView
    private lateinit var detailText: TextView
    private lateinit var approveButton: Button
    private lateinit var cancelButton: Button
    private lateinit var spinner: ProgressBar

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUI()

        val action = intent.getStringExtra(EXTRA_ACTION)

        when (action) {
            ACTION_CREATE -> handleCreate()
            ACTION_GET -> handleGet()
            else -> {
                setResult(RESULT_CANCELED)
                finish()
            }
        }
    }

    // ─── Registration Flow ─────────────────────────────────────────────

    private fun handleCreate() {
        val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        if (request == null) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }

        val requestJson = try {
            JSONObject(
                (request.callingRequest as? androidx.credentials.CreatePublicKeyCredentialRequest)
                    ?.requestJson ?: ""
            )
        } catch (_: Exception) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }

        val rpId = requestJson.optJSONObject("rp")?.optString("id", "") ?: ""
        val rpName = requestJson.optJSONObject("rp")?.optString("name", rpId) ?: rpId
        val userId = requestJson.optJSONObject("user")?.optString("id", "") ?: ""
        val userName = requestJson.optJSONObject("user")?.optString("name", "") ?: ""

        showVerifying(rpId)
        verifyAndPrompt(rpId) { approved ->
            if (!approved) {
                setResult(RESULT_CANCELED)
                finish()
                return@verifyAndPrompt
            }

            val credential = createCredential(rpId, userId)
            if (credential == null) {
                setResult(RESULT_CANCELED)
                finish()
                return@verifyAndPrompt
            }

            val responseJson = JSONObject().apply {
                put("id", credential.credentialIdB64)
                put("rawId", credential.credentialIdB64)
                put("type", "public-key")
                put("response", JSONObject().apply {
                    put("attestationObject", base64UrlEncode(credential.attestationObject))
                    put("clientDataJSON", base64UrlEncode(ByteArray(0))) // System provides real clientDataJSON
                })
            }

            val resultData = android.content.Intent()
            PendingIntentHandler.setCreateCredentialResponse(
                resultData,
                CreatePublicKeyCredentialResponse(responseJson.toString())
            )
            setResult(RESULT_OK, resultData)
            finish()
        }
    }

    // ─── Assertion Flow ────────────────────────────────────────────────

    private fun handleGet() {
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        if (request == null) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }

        // Find the passkey option
        val option = request.credentialOptions
            .filterIsInstance<androidx.credentials.provider.ProviderGetCredentialRequest>()
            .firstOrNull()

        // Extract rpId from the first PublicKeyCredential option
        val rpId = intent.getStringExtra("rpId") ?: ""

        showVerifying(rpId)
        verifyAndPrompt(rpId) { approved ->
            if (!approved) {
                setResult(RESULT_CANCELED)
                finish()
                return@verifyAndPrompt
            }

            val credentialIdB64 = intent.getStringExtra("credentialId") ?: ""
            val credentialId = Base64.decode(credentialIdB64, Base64.URL_SAFE or Base64.NO_WRAP)
            val clientDataHash = intent.getByteArrayExtra("clientDataHash") ?: ByteArray(32)

            val assertion = signAssertion(rpId, credentialId, clientDataHash)
            if (assertion == null) {
                setResult(RESULT_CANCELED)
                finish()
                return@verifyAndPrompt
            }

            val responseJson = JSONObject().apply {
                put("id", credentialIdB64)
                put("rawId", credentialIdB64)
                put("type", "public-key")
                put("response", JSONObject().apply {
                    put("authenticatorData", base64UrlEncode(assertion.authData))
                    put("signature", base64UrlEncode(assertion.signature))
                    put("userHandle", assertion.userHandleB64)
                    put("clientDataJSON", base64UrlEncode(ByteArray(0)))
                })
            }

            val resultData = android.content.Intent()
            PendingIntentHandler.setGetCredentialResponse(
                resultData,
                GetCredentialResponse(PublicKeyCredential(responseJson.toString()))
            )
            setResult(RESULT_OK, resultData)
            finish()
        }
    }

    // ─── Attestation Verification ──────────────────────────────────────

    private fun showVerifying(rpId: String) {
        spinner.visibility = android.view.View.VISIBLE
        statusText.text = "Verifying server…"
        detailText.text = rpId
        approveButton.visibility = android.view.View.GONE
    }

    private fun verifyAndPrompt(rpId: String, callback: (Boolean) -> Unit) {
        Thread {
            val parts = rpId.split(":", limit = 2)
            val host = parts[0]
            val port = if (parts.size > 1) parts[1].toIntOrNull() ?: 443 else 443

            val attestation = inspectEnclave(host, port)

            runOnUiThread {
                if (attestation != null) {
                    val json = try { JSONObject(attestation) } catch (_: Exception) { null }
                    val valid = json?.optBoolean("valid", false) ?: false

                    if (valid) {
                        spinner.visibility = android.view.View.GONE
                        statusText.text = "Server Verified ✓"

                        val teeType = json?.optString("tee_type", "") ?: ""
                        val codeHash = json?.optString("workload_code_hash", "") ?: ""
                        val detail = buildString {
                            append(rpId)
                            if (teeType.isNotEmpty()) append("\nTEE: $teeType")
                            if (codeHash.length > 16) append("\nCode: ${codeHash.take(16)}…")
                        }
                        detailText.text = detail

                        approveButton.visibility = android.view.View.VISIBLE
                        approveButton.setOnClickListener { callback(true) }
                        cancelButton.setOnClickListener { callback(false) }
                    } else {
                        spinner.visibility = android.view.View.GONE
                        statusText.text = "Attestation Failed"
                        detailText.text = "$rpId\nCould not verify server integrity."
                        approveButton.visibility = android.view.View.GONE
                        cancelButton.postDelayed({ callback(false) }, 2000)
                    }
                } else {
                    spinner.visibility = android.view.View.GONE
                    statusText.text = "Attestation Unavailable"
                    detailText.text = "$rpId\nRA-TLS library not loaded."
                    approveButton.visibility = android.view.View.GONE
                    cancelButton.postDelayed({ callback(false) }, 2000)
                }
            }
        }.start()
    }

    /**
     * Invoke the RA-TLS inspect function via reflection. The native library
     * (ratls_jni) is loaded by the NativeRaTlsBridge in the native-ratls module.
     * Since we run in the same process, we can access it via reflection.
     */
    private fun inspectEnclave(host: String, port: Int): String? {
        return try {
            try { System.loadLibrary("ratls_jni") } catch (_: UnsatisfiedLinkError) { /* already loaded */ }

            val bridge = Class.forName("org.privasys.nativeratls.NativeRaTlsBridge")
            val method = bridge.getDeclaredMethod(
                "nativeInspect",
                String::class.java,
                Int::class.javaPrimitiveType,
                String::class.java
            )
            method.isAccessible = true
            method.invoke(null, host, port, null) as? String
        } catch (_: Exception) {
            null
        }
    }

    // ─── Credential Creation ───────────────────────────────────────────

    private data class CreatedCredential(
        val credentialIdB64: String,
        val attestationObject: ByteArray,
    )

    private fun createCredential(rpId: String, userId: String): CreatedCredential? {
        val keyAlias = "org.privasys.wallet.fido2.$rpId.${UUID.randomUUID()}"

        val keyPairGen = KeyPairGenerator.getInstance(
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
            keyPairGen.initialize(specBuilder.build())
        } catch (_: Exception) {
            specBuilder.setIsStrongBoxBacked(false)
            keyPairGen.initialize(specBuilder.build())
        }

        val keyPair = keyPairGen.generateKeyPair()
        val publicKeyEncoded = keyPair.public.encoded

        val rawPublicKey = extractRawECPublicKey(publicKeyEncoded) ?: return null
        val credentialId = MessageDigest.getInstance("SHA-256").digest(publicKeyEncoded)
        val credentialIdB64 = Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_WRAP)

        // Build authenticator data
        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        val authData = buildRegistrationAuthData(rpIdHash, credentialId, rawPublicKey)
        val attestationObject = buildAttestationObjectCBOR(authData)

        // Store credential mapping
        storeCredential(rpId, credentialId, keyAlias, userId)

        return CreatedCredential(credentialIdB64, attestationObject)
    }

    // ─── Assertion Signing ─────────────────────────────────────────────

    private data class SignedAssertion(
        val authData: ByteArray,
        val signature: ByteArray,
        val userHandleB64: String,
    )

    private fun signAssertion(
        rpId: String,
        credentialId: ByteArray,
        clientDataHash: ByteArray
    ): SignedAssertion? {
        val credIdB64 = Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_WRAP)
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        val json = prefs.getString("$rpId:$credIdB64", null) ?: return null

        val entry = try { JSONObject(json) } catch (_: Exception) { return null }
        val keyAlias = entry.optString("keyAlias") ?: return null
        val userId = entry.optString("userId", "")

        val privateKeyEntry = keyStore.getEntry(keyAlias, null) as? KeyStore.PrivateKeyEntry
            ?: return null

        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        val authData = buildAssertionAuthData(rpIdHash, credentialId)

        val signInput = authData + clientDataHash
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(privateKeyEntry.privateKey)
        sig.update(signInput)
        val signature = sig.sign()

        return SignedAssertion(
            authData,
            signature,
            Base64.encodeToString(userId.toByteArray(), Base64.URL_SAFE or Base64.NO_WRAP)
        )
    }

    // ─── Credential Storage ────────────────────────────────────────────

    private fun storeCredential(rpId: String, credentialId: ByteArray, keyAlias: String, userId: String) {
        val credIdB64 = Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_WRAP)
        val stored = JSONObject().apply {
            put("rpId", rpId)
            put("credentialId", credIdB64)
            put("keyAlias", keyAlias)
            put("userId", userId)
            put("createdAt", System.currentTimeMillis())
        }
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
            .edit()
            .putString("$rpId:$credIdB64", stored.toString())
            .apply()
    }

    // ─── Auth Data & CBOR ──────────────────────────────────────────────

    private fun buildRegistrationAuthData(
        rpIdHash: ByteArray,
        credentialId: ByteArray,
        rawPublicKey: ByteArray
    ): ByteArray {
        val x = rawPublicKey.sliceArray(0 until 32)
        val y = rawPublicKey.sliceArray(32 until 64)
        val coseKey = buildCoseKey(x, y)

        val buf = mutableListOf<Byte>()
        buf.addAll(rpIdHash.toList())
        buf.add(0x45) // flags: UP | UV | AT
        buf.addAll(byteArrayOf(0, 0, 0, 0).toList()) // signCount = 0
        buf.addAll(AAGUID.toList())
        buf.add(((credentialId.size shr 8) and 0xFF).toByte())
        buf.add((credentialId.size and 0xFF).toByte())
        buf.addAll(credentialId.toList())
        buf.addAll(coseKey.toList())
        return buf.toByteArray()
    }

    private fun buildAssertionAuthData(rpIdHash: ByteArray, credentialId: ByteArray): ByteArray {
        val buf = mutableListOf<Byte>()
        buf.addAll(rpIdHash.toList())
        buf.add(0x05) // flags: UP | UV
        // Platform authenticator: always send signCount=0 (non-exportable key)
        buf.add(0)
        buf.add(0)
        buf.add(0)
        buf.add(0)
        return buf.toByteArray()
    }

    private fun buildCoseKey(x: ByteArray, y: ByteArray): ByteArray {
        val cbor = mutableListOf<Byte>()
        cbor.add(0xa5.toByte())
        cbor.addAll(byteArrayOf(0x01, 0x02).toList())
        cbor.addAll(byteArrayOf(0x03, 0x26).toList())
        cbor.addAll(byteArrayOf(0x20, 0x01).toList())
        cbor.addAll(byteArrayOf(0x21, 0x58, 0x20).toList())
        cbor.addAll(x.toList())
        cbor.addAll(byteArrayOf(0x22, 0x58, 0x20).toList())
        cbor.addAll(y.toList())
        return cbor.toByteArray()
    }

    private fun buildAttestationObjectCBOR(authData: ByteArray): ByteArray {
        val cbor = mutableListOf<Byte>()
        cbor.add(0xa3.toByte())
        cbor.addAll(byteArrayOf(0x63, 0x66, 0x6d, 0x74).toList())
        cbor.addAll(byteArrayOf(0x64, 0x6e, 0x6f, 0x6e, 0x65).toList())
        cbor.addAll(byteArrayOf(0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74).toList())
        cbor.add(0xa0.toByte())
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

    private fun extractRawECPublicKey(encoded: ByteArray): ByteArray? {
        if (encoded.size < 65) return null
        val offset = encoded.size - 65
        if (encoded[offset] != 0x04.toByte()) return null
        return encoded.sliceArray(offset + 1 until encoded.size)
    }

    private fun base64UrlEncode(data: ByteArray): String =
        Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_WRAP)

    // ─── UI ────────────────────────────────────────────────────────────

    private fun buildUI() {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(64, 64, 64, 64)
        }

        spinner = ProgressBar(this).apply {
            isIndeterminate = true
        }
        layout.addView(spinner)

        statusText = TextView(this).apply {
            textSize = 20f
            gravity = Gravity.CENTER
            setPadding(0, 32, 0, 8)
        }
        layout.addView(statusText)

        detailText = TextView(this).apply {
            textSize = 14f
            gravity = Gravity.CENTER
            setTextColor(0xFF888888.toInt())
            setPadding(0, 0, 0, 32)
        }
        layout.addView(detailText)

        approveButton = Button(this).apply {
            text = "Approve"
            visibility = android.view.View.GONE
        }
        layout.addView(approveButton)

        cancelButton = Button(this).apply {
            text = "Cancel"
            setOnClickListener {
                setResult(RESULT_CANCELED)
                finish()
            }
        }
        layout.addView(cancelButton)

        setContentView(layout)
    }
}
