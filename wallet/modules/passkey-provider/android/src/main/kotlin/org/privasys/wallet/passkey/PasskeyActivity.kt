// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.wallet.passkey

import android.app.Activity
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.util.Base64
import android.view.Gravity
import android.view.View
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
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.util.UUID

/**
 * Activity launched by PendingIntent when the system invokes Privasys Wallet
 * as a credential provider. Verifies enclave attestation via RA-TLS before
 * creating or signing WebAuthn credentials.
 *
 * Two kinds of website passkey:
 * - "local": a StrongBox/TEE Keystore key that never leaves this device.
 * - "synced": derived from the holder's passkey root, so the holder's other
 *   devices can derive it again. Its credential id carries the random input.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class PasskeyActivity : Activity() {

    companion object {
        const val EXTRA_ACTION = "org.privasys.wallet.passkey.ACTION"
        const val ACTION_CREATE = "create"
        const val ACTION_GET = "get"

        private const val PREFS_NAME = "org.privasys.wallet.credentials"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

        const val KIND_LOCAL = "local"
        const val KIND_SYNCED = "synced"

        // Authenticator data flags. BE (backup eligible) and BS (backed up)
        // tell the site a synced passkey survives the loss of this device.
        private const val FLAGS_REGISTER_LOCAL: Byte = 0x45 // UP | UV | AT
        private const val FLAGS_ASSERT_LOCAL: Byte = 0x05 // UP | UV
        private const val FLAGS_REGISTER_SYNCED: Byte = 0x5D // UP | UV | BE | BS | AT
        private const val FLAGS_ASSERT_SYNCED: Byte = 0x1D // UP | UV | BE | BS

        private val AAGUID = byteArrayOf(
            0xf4.toByte(), 0x7a.toByte(), 0xc1.toByte(), 0x0b.toByte(),
            0x58.toByte(), 0xcc.toByte(), 0x43.toByte(), 0x72.toByte(),
            0xa5.toByte(), 0x67.toByte(), 0x0e.toByte(), 0x02.toByte(),
            0xb2.toByte(), 0xc3.toByte(), 0xd4.toByte(), 0x79.toByte()
        )

        private const val WARNING_LOCAL = "It stays on this device and is lost with it."
    }

    /** What the holder may choose between when a passkey is created. */
    private enum class SaveOptions {
        /** The site asked for attestation, so a hardware-bound key: no choice. */
        LOCAL_HARDWARE_REQUIRED,

        /** The wallet has not set a passkey root (no seed yet), so only local is possible. */
        LOCAL_NO_ROOT,

        /** Both kinds on offer. */
        CHOICE,
    }

    private lateinit var statusText: TextView
    private lateinit var detailText: TextView
    private lateinit var noteText: TextView
    private lateinit var syncButton: Button
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
            else -> cancel()
        }
    }

    private fun cancel() {
        setResult(RESULT_CANCELED)
        finish()
    }

    // ─── Registration Flow ─────────────────────────────────────────────

    private fun handleCreate() {
        val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        if (request == null) {
            cancel()
            return
        }

        val requestJson = try {
            JSONObject(
                (request.callingRequest as? androidx.credentials.CreatePublicKeyCredentialRequest)
                    ?.requestJson ?: ""
            )
        } catch (_: Exception) {
            cancel()
            return
        }

        val rpId = requestJson.optJSONObject("rp")?.optString("id", "") ?: ""
        // user.id arrives base64url encoded in the WebAuthn JSON; it is kept as
        // is and is the userHandle the site gets back at sign-in.
        val userId = requestJson.optJSONObject("user")?.optString("id", "") ?: ""
        val userName = requestJson.optJSONObject("user")?.optString("name", "") ?: ""

        val options = when {
            requiresHardwareKey(requestJson) -> SaveOptions.LOCAL_HARDWARE_REQUIRED
            !PasskeyRootStore.exists(this) -> SaveOptions.LOCAL_NO_ROOT
            else -> SaveOptions.CHOICE
        }

        showVerifying(rpId)
        verifyAndPrompt(
            rpId,
            onVerified = {
                showSaveChoice(options) { kind ->
                    if (kind == KIND_SYNCED) {
                        // The root is touched only after the holder proves
                        // presence, as the UV flag in the response claims.
                        authenticateHolder(rpId, "Save your passkey") { ok ->
                            if (ok) finishCreate(createSyncedCredential(rpId, userId, userName)) else cancel()
                        }
                    } else {
                        finishCreate(createLocalCredential(rpId, userId, userName))
                    }
                }
            },
            onRejected = { cancel() }
        )
    }

    /**
     * A site that asks for "direct" or "enterprise" attestation wants to know
     * the key is bound to hardware, which a synced key is not. Only the
     * attestation preference says so; residentKey and the WebAuthn hints
     * ("security-key", "client-device", "hybrid") describe where a key is
     * found, not whether it may be backed up.
     */
    private fun requiresHardwareKey(requestJson: JSONObject): Boolean =
        when (requestJson.optString("attestation", "none")) {
            "direct", "enterprise" -> true
            else -> false
        }

    private fun finishCreate(credential: CreatedCredential?) {
        if (credential == null) {
            cancel()
            return
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

    // ─── Assertion Flow ────────────────────────────────────────────────

    private fun handleGet() {
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        if (request == null) {
            cancel()
            return
        }

        // The passkey option carries the WebAuthn request JSON and, for
        // privileged callers (browsers), the precomputed clientDataHash the
        // assertion signature MUST cover. The previous code read the hash from
        // an intent extra nobody set and silently signed over 32 zero bytes,
        // producing signatures every relying party rejects.
        val option = request.credentialOptions
            .filterIsInstance<androidx.credentials.GetPublicKeyCredentialOption>()
            .firstOrNull()
        if (option == null) {
            cancel()
            return
        }

        val rpId = intent.getStringExtra("rpId") ?: ""

        showVerifying(rpId)
        verifyAndPrompt(
            rpId,
            onVerified = {
                approveButton.text = "Approve"
                approveButton.visibility = View.VISIBLE
                approveButton.setOnClickListener {
                    approveButton.isEnabled = false
                    val credentialIdB64 = intent.getStringExtra("credentialId") ?: ""
                    val credentialId = Base64.decode(credentialIdB64, Base64.URL_SAFE or Base64.NO_WRAP)

                    // Privileged caller: sign its hash, the system supplies the
                    // clientDataJSON. Ordinary app: build clientDataJSON
                    // ourselves (challenge from the request, android:apk-key-hash
                    // origin of the caller), sign over its hash, and return it.
                    val providedHash = option.clientDataHash
                    val builtClientData: ByteArray? =
                        if (providedHash == null) buildClientDataJson(option.requestJson, request.callingAppInfo)
                        else null
                    val clientDataHash = providedHash
                        ?: MessageDigest.getInstance("SHA-256").digest(builtClientData!!)

                    signAssertion(rpId, credentialId, clientDataHash) { assertion ->
                        finishGet(credentialIdB64, assertion, builtClientData)
                    }
                }
            },
            onRejected = { cancel() }
        )
    }

    private fun finishGet(credentialIdB64: String, assertion: SignedAssertion?, builtClientData: ByteArray?) {
        if (assertion == null) {
            cancel()
            return
        }
        val responseJson = JSONObject().apply {
            put("id", credentialIdB64)
            put("rawId", credentialIdB64)
            put("type", "public-key")
            put("response", JSONObject().apply {
                put("authenticatorData", base64UrlEncode(assertion.authData))
                put("signature", base64UrlEncode(assertion.signature))
                if (assertion.userHandleB64.isNotEmpty()) put("userHandle", assertion.userHandleB64)
                put("clientDataJSON", base64UrlEncode(builtClientData ?: ByteArray(0)))
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

    /** WebAuthn clientDataJSON for a non-privileged caller: the challenge from
     *  the request JSON plus the caller's android:apk-key-hash origin. */
    private fun buildClientDataJson(
        requestJson: String,
        callingAppInfo: androidx.credentials.provider.CallingAppInfo?
    ): ByteArray {
        val challenge = try {
            JSONObject(requestJson).optString("challenge", "")
        } catch (_: Exception) {
            ""
        }
        return JSONObject().apply {
            put("type", "webauthn.get")
            put("challenge", challenge)
            put("origin", androidAppOrigin(callingAppInfo))
            put("crossOrigin", false)
        }.toString().toByteArray()
    }

    /** `android:apk-key-hash:<b64url SHA-256 of the caller's signing cert>`,
     *  the origin format RPs registered for Android app callers expect. */
    private fun androidAppOrigin(info: androidx.credentials.provider.CallingAppInfo?): String {
        val cert = info?.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
            ?: return "android:apk-key-hash:unknown"
        val hash = MessageDigest.getInstance("SHA-256").digest(cert)
        return "android:apk-key-hash:" + Base64.encodeToString(hash, Base64.URL_SAFE or Base64.NO_WRAP)
    }

    // ─── Attestation Verification ──────────────────────────────────────

    private fun showVerifying(rpId: String) {
        spinner.visibility = View.VISIBLE
        statusText.text = "Verifying server…"
        detailText.text = rpId
        approveButton.visibility = View.GONE
        syncButton.visibility = View.GONE
        noteText.visibility = View.GONE
    }

    /**
     * Checks the site's attestation over RA-TLS. On success it shows the
     * verified details and hands over to [onVerified], which puts up the
     * buttons for this flow; Cancel then rejects. On failure it rejects
     * after a short pause so the holder can read why.
     */
    private fun verifyAndPrompt(rpId: String, onVerified: () -> Unit, onRejected: () -> Unit) {
        Thread {
            val parts = rpId.split(":", limit = 2)
            val host = parts[0]
            val port = if (parts.size > 1) parts[1].toIntOrNull() ?: 443 else 443

            val attestation = inspectEnclave(host, port)

            runOnUiThread {
                val json = attestation?.let { try { JSONObject(it) } catch (_: Exception) { null } }
                // A Privasys enclave is a host whose RA-TLS answer carries its
                // measurements. Anything else is an ordinary website (or one
                // the RA-TLS library could not inspect): the wallet is a
                // general passkey provider, so it gets a plain consent prompt,
                // as on iOS, instead of being refused. An enclave whose
                // attestation fails is still a hard stop.
                val isEnclave = json != null && (json.has("mrtd") || json.has("mrenclave"))
                if (!isEnclave) {
                    spinner.visibility = View.GONE
                    statusText.text = "Use your Privasys passkey?"
                    detailText.text = rpId
                    cancelButton.setOnClickListener { onRejected() }
                    onVerified()
                } else if (attestation != null) {
                    val valid = json?.optBoolean("valid", false) ?: false

                    if (valid) {
                        spinner.visibility = View.GONE
                        statusText.text = "Server Verified ✓"

                        val teeType = json?.optString("tee_type", "") ?: ""
                        val codeHash = json?.optString("workload_code_hash", "") ?: ""
                        val detail = buildString {
                            append(rpId)
                            if (teeType.isNotEmpty()) append("\nTEE: $teeType")
                            if (codeHash.length > 16) append("\nCode: ${codeHash.take(16)}…")
                        }
                        detailText.text = detail

                        cancelButton.setOnClickListener { onRejected() }
                        onVerified()
                    } else {
                        spinner.visibility = View.GONE
                        statusText.text = "Attestation Failed"
                        detailText.text = "$rpId\nCould not verify server integrity."
                        approveButton.visibility = View.GONE
                        cancelButton.postDelayed({ onRejected() }, 2000)
                    }
                } else {
                    spinner.visibility = View.GONE
                    statusText.text = "Attestation Unavailable"
                    detailText.text = "$rpId\nRA-TLS library not loaded."
                    approveButton.visibility = View.GONE
                    cancelButton.postDelayed({ onRejected() }, 2000)
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

    // ─── Save choice ───────────────────────────────────────────────────

    /**
     * After the server is verified, the holder picks where the passkey lives.
     * "This device only" always carries the warning that it is lost with the
     * device; "your devices" is offered only when the site does not insist on
     * hardware and the wallet has a passkey root.
     */
    private fun showSaveChoice(options: SaveOptions, onChosen: (kind: String) -> Unit) {
        noteText.visibility = View.VISIBLE
        noteText.text = when (options) {
            SaveOptions.CHOICE ->
                "Where should this passkey be saved?\n\n" +
                    "Your devices: backed up to your other devices through your Privasys Wallet. Never to Google.\n\n" +
                    "This device only: $WARNING_LOCAL"
            SaveOptions.LOCAL_HARDWARE_REQUIRED ->
                "This website asks for a passkey kept in this device's secure hardware, " +
                    "so it is saved on this device only. $WARNING_LOCAL"
            SaveOptions.LOCAL_NO_ROOT ->
                "This passkey is saved on this device only. $WARNING_LOCAL"
        }

        approveButton.text = "Save on this device only"
        approveButton.visibility = View.VISIBLE

        syncButton.visibility = if (options == SaveOptions.CHOICE) View.VISIBLE else View.GONE

        val choose = { kind: String ->
            // One tap only: the system expects a single result.
            approveButton.isEnabled = false
            syncButton.isEnabled = false
            onChosen(kind)
        }
        approveButton.setOnClickListener { choose(KIND_LOCAL) }
        syncButton.setOnClickListener { choose(KIND_SYNCED) }
    }

    // ─── Holder check ──────────────────────────────────────────────────

    /**
     * Biometric or device passcode, asked for by the provider itself, before a
     * synced key is derived. The key is software, so this prompt (not the
     * Keystore) is what stands between the root and a signature.
     */
    private fun authenticateHolder(rpId: String, title: String, onResult: (Boolean) -> Unit) {
        val prompt = BiometricPrompt.Builder(this)
            .setTitle(title)
            .setSubtitle(rpId)
            .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL)
            .build()
        prompt.authenticate(CancellationSignal(), mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onResult(true)
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onResult(false)
            // onAuthenticationFailed (a finger not recognised) leaves the prompt up for another try.
        })
    }

    // ─── Credential Creation ───────────────────────────────────────────

    private data class CreatedCredential(
        val credentialIdB64: String,
        val attestationObject: ByteArray,
    )

    private fun createLocalCredential(rpId: String, userId: String, userName: String): CreatedCredential? {
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

        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        val authData = buildRegistrationAuthData(rpIdHash, FLAGS_REGISTER_LOCAL, credentialId, rawPublicKey)
        val attestationObject = buildAttestationObjectCBOR(authData)

        storeCredential(rpId, credentialId, KIND_LOCAL, keyAlias, userId, userName)

        return CreatedCredential(credentialIdB64, attestationObject)
    }

    /**
     * A synced passkey: credential id 0x01 || r, key derived from the passkey
     * root, r and the rpId. Nothing secret is stored; the record only lets the
     * picker list it and the wallet copy it to the holder's other devices.
     */
    private fun createSyncedCredential(rpId: String, userId: String, userName: String): CreatedCredential? {
        val root = PasskeyRootStore.read(this) ?: return null
        val r = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val credentialId = byteArrayOf(SyncedPasskeyDerivation.SYNCED_ID_VERSION) + r

        val key = try {
            SyncedPasskeyDerivation.derive(root, r, rpId)
        } catch (_: Exception) {
            return null
        } finally {
            root.fill(0)
        }
        // Registration needs only the public key; the scalar goes at once.
        key.wipe()

        val credentialIdB64 = Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_WRAP)
        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        val authData = buildRegistrationAuthData(rpIdHash, FLAGS_REGISTER_SYNCED, credentialId, key.rawPublicKey)
        val attestationObject = buildAttestationObjectCBOR(authData)

        storeCredential(rpId, credentialId, KIND_SYNCED, null, userId, userName)

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
        clientDataHash: ByteArray,
        onSigned: (SignedAssertion?) -> Unit
    ) {
        val credIdB64 = Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_WRAP)
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        val entry = prefs.getString("$rpId:$credIdB64", null)
            ?.let { try { JSONObject(it) } catch (_: Exception) { null } }
        if (entry == null) {
            onSigned(null)
            return
        }

        // user.id was stored as the site sent it, base64url, which is what the
        // response's userHandle wants. Re-encoding it would hand the site a
        // userHandle it never issued.
        val userHandle = entry.optString("userHandle", "")
        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())

        val kind = entry.optString("kind", "")
        if (kind != KIND_LOCAL && kind != KIND_SYNCED) {
            onSigned(null)
            return
        }
        if (kind == KIND_SYNCED) {
            if (!SyncedPasskeyDerivation.isSyncedCredentialId(credentialId)) {
                onSigned(null)
                return
            }
            authenticateHolder(rpId, "Sign in with your passkey") { ok ->
                if (!ok) {
                    onSigned(null)
                    return@authenticateHolder
                }
                val authData = buildAssertionAuthData(rpIdHash, FLAGS_ASSERT_SYNCED)
                val signature = signSynced(rpId, credentialId, authData + clientDataHash)
                onSigned(signature?.let { SignedAssertion(authData, it, userHandle) })
            }
            return
        }

        val keyAlias = entry.optString("keyAlias", "")
        val privateKeyEntry = (if (keyAlias.isEmpty()) null else keyStore.getEntry(keyAlias, null))
            as? KeyStore.PrivateKeyEntry
        if (privateKeyEntry == null) {
            onSigned(null)
            return
        }

        val authData = buildAssertionAuthData(rpIdHash, FLAGS_ASSERT_LOCAL)
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(privateKeyEntry.privateKey)

        // The local key is made with per-use strong biometric authentication
        // (timeout 0), so the Keystore refuses to sign unless this very
        // Signature is unlocked through a BiometricPrompt CryptoObject.
        // Biometric only, as that key allows no passcode.
        val prompt = BiometricPrompt.Builder(this)
            .setTitle("Sign in with your passkey")
            .setSubtitle(rpId)
            .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG)
            .setNegativeButton("Cancel", mainExecutor) { _, _ -> onSigned(null) }
            .build()
        prompt.authenticate(
            BiometricPrompt.CryptoObject(sig), CancellationSignal(), mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val unlocked = result.cryptoObject?.signature ?: sig
                    val signature = try {
                        unlocked.update(authData + clientDataHash)
                        unlocked.sign()
                    } catch (_: Exception) {
                        null
                    }
                    onSigned(signature?.let { SignedAssertion(authData, it, userHandle) })
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onSigned(null)
            }
        )
    }

    /** Derive the synced key, sign (ES256, DER) and forget the key. */
    private fun signSynced(rpId: String, credentialId: ByteArray, message: ByteArray): ByteArray? {
        val root = PasskeyRootStore.read(this) ?: return null
        var scalar: ByteArray? = null
        return try {
            val derived = SyncedPasskeyDerivation.deriveScalar(root, SyncedPasskeyDerivation.randomOf(credentialId), rpId)
            scalar = derived
            Signature.getInstance("SHA256withECDSA").run {
                initSign(SyncedPasskeyDerivation.privateKeyFor(derived))
                update(message)
                sign()
            }
        } catch (_: Exception) {
            null
        } finally {
            root.fill(0)
            scalar?.fill(0)
        }
    }

    // ─── Credential Storage ────────────────────────────────────────────

    /**
     * Record shape shared with NativeKeysModule (listWebsitePasskeys,
     * importWebsitePasskeys, deleteWebsitePasskey): keyed "$rpId:$credIdB64"
     * with the id in URL_SAFE | NO_WRAP Base64 (padded). userHandle is the
     * site's user.id as it sent it (base64url).
     */
    private fun storeCredential(
        rpId: String,
        credentialId: ByteArray,
        kind: String,
        keyAlias: String?,
        userHandle: String,
        userName: String,
    ) {
        val credIdB64 = Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_WRAP)
        val stored = JSONObject().apply {
            put("rpId", rpId)
            put("credentialId", credIdB64)
            put("kind", kind)
            if (keyAlias != null) put("keyAlias", keyAlias)
            put("userHandle", userHandle)
            put("userName", userName)
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
        flags: Byte,
        credentialId: ByteArray,
        rawPublicKey: ByteArray
    ): ByteArray {
        val x = rawPublicKey.sliceArray(0 until 32)
        val y = rawPublicKey.sliceArray(32 until 64)
        val coseKey = buildCoseKey(x, y)

        val buf = mutableListOf<Byte>()
        buf.addAll(rpIdHash.toList())
        buf.add(flags)
        buf.addAll(byteArrayOf(0, 0, 0, 0).toList()) // signCount = 0
        buf.addAll(AAGUID.toList())
        buf.add(((credentialId.size shr 8) and 0xFF).toByte())
        buf.add((credentialId.size and 0xFF).toByte())
        buf.addAll(credentialId.toList())
        buf.addAll(coseKey.toList())
        return buf.toByteArray()
    }

    private fun buildAssertionAuthData(rpIdHash: ByteArray, flags: Byte): ByteArray {
        val buf = mutableListOf<Byte>()
        buf.addAll(rpIdHash.toList())
        buf.add(flags)
        // signCount stays 0: a synced key is used from several devices, and a
        // local one has no counter to keep, so 0 tells the site not to check.
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

        noteText = TextView(this).apply {
            textSize = 14f
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, 32)
            visibility = View.GONE
        }
        layout.addView(noteText)

        syncButton = Button(this).apply {
            text = "Save to your devices"
            visibility = View.GONE
        }
        layout.addView(syncButton)

        approveButton = Button(this).apply {
            text = "Approve"
            visibility = View.GONE
        }
        layout.addView(approveButton)

        cancelButton = Button(this).apply {
            text = "Cancel"
            setOnClickListener { cancel() }
        }
        layout.addView(cancelButton)

        setContentView(layout)
    }
}
