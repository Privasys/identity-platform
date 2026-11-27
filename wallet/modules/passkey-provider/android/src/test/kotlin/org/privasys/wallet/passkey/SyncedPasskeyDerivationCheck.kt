// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.wallet.passkey

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/**
 * Main-style check of the synced passkey derivation against the test vector
 * the wallet's src/__tests__/website-passkeys.test.ts and the iOS side use.
 *
 * The module has no JUnit dependency, so this is a plain `main` that needs
 * only the Kotlin stdlib and a JDK. Run it by compiling this file together
 * with SyncedPasskeyDerivation.kt; it exits non-zero on a mismatch.
 */
fun main() {
    fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    fun range(from: Int, to: Int) = ByteArray(to - from + 1) { (from + it).toByte() }

    val seed = range(0x00, 0x1f)
    val r = range(0xa0, 0xaf)
    val rpId = "example.com"

    // The root is derived by the wallet's JavaScript, not here; recomputing it
    // checks the HKDF with an empty salt as well.
    val root = SyncedPasskeyDerivation.hkdfSha256(
        ikm = seed, salt = ByteArray(0),
        info = "privasys-website-passkeys/v1".toByteArray(), length = 32
    )
    val key = SyncedPasskeyDerivation.derive(root, r, rpId)

    val expectedRoot = "dbf48f5caf769655c82494e38ee824617874a623539f5b33640abe1cdb9dedf5"
    val expectedScalar = "9c69d00194d9cd3bee2b12c2ab4be00f72f6e23b7ca186c39d0d3f52cb3caf54"
    val expectedPub = "04685fddec15bcd5babcb8be6b181a43964279b8f9cc63a7620f9f5b9fdcd0094a" +
        "3c2506a8b0a00426b39c47475b61423a3074a0f9092735b9b868c26571c48556"

    var ok = true
    fun check(name: String, got: String, want: String) {
        val pass = got == want
        ok = ok && pass
        println("${if (pass) "PASS" else "FAIL"} $name: $got")
    }
    check("passkeyRoot", hex(root), expectedRoot)
    check("scalar", hex(key.scalar), expectedScalar)
    check("scalar (deriveScalar)", hex(SyncedPasskeyDerivation.deriveScalar(root, r, rpId)), expectedScalar)
    check("public key", hex(key.publicKey), expectedPub)

    // Same r on another site must give another key.
    val other = SyncedPasskeyDerivation.deriveScalar(root, r, "example.org")
    val differs = hex(other) != expectedScalar
    ok = ok && differs
    println("${if (differs) "PASS" else "FAIL"} another rpId gives another key")

    // The derived public point is on the curve, and a signature made with the
    // platform PrivateKey verifies against it.
    val x = BigInteger(1, key.rawPublicKey.copyOfRange(0, 32))
    val y = BigInteger(1, key.rawPublicKey.copyOfRange(32, 64))
    val onCurve = SyncedPasskeyDerivation.isOnCurve(x, y)
    ok = ok && onCurve
    println("${if (onCurve) "PASS" else "FAIL"} public key on curve")

    val message = "authData || clientDataHash".toByteArray()
    val signer = Signature.getInstance("SHA256withECDSA")
    signer.initSign(SyncedPasskeyDerivation.privateKeyFor(key.scalar))
    signer.update(message)
    val der = signer.sign()

    val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
    val pub = KeyFactory.getInstance("EC").generatePublic(
        ECPublicKeySpec(ECPoint(x, y), params.getParameterSpec(ECParameterSpec::class.java))
    )
    val verifier = Signature.getInstance("SHA256withECDSA")
    verifier.initVerify(pub)
    verifier.update(message)
    val verified = verifier.verify(der) && der[0] == 0x30.toByte()
    ok = ok && verified
    println("${if (verified) "PASS" else "FAIL"} DER signature verifies against the derived public key")

    val idOk = SyncedPasskeyDerivation.isSyncedCredentialId(byteArrayOf(0x01) + r) &&
        !SyncedPasskeyDerivation.isSyncedCredentialId(ByteArray(32))
    ok = ok && idOk
    println("${if (idOk) "PASS" else "FAIL"} credential id kinds tell apart")

    if (!ok) {
        println("FAILED")
        kotlin.system.exitProcess(1)
    }
    println("ALL PASS")
}
