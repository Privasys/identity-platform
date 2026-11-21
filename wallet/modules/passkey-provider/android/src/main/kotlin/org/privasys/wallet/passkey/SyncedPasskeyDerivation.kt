// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.wallet.passkey

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Key derivation for "backed up to your devices" website passkeys.
 *
 * Pure JVM on purpose (no Android imports) so the derivation can be checked
 * against the plan's test vector on a desktop JDK. Every device of the holder
 * derives the same key from the passkey root, the 16 random bytes `r` carried
 * in the credential id, and the site's rpId, so nothing secret is stored per
 * passkey.
 *
 * Spec: .operations/plans/website-passkeys-plan.md, "A synced passkey".
 */
object SyncedPasskeyDerivation {

    /** First byte of a synced credential id: "synced v1". */
    const val SYNCED_ID_VERSION: Byte = 0x01

    /** 0x01 followed by the 16 random bytes `r`. */
    const val SYNCED_ID_LENGTH = 17

    private const val INFO_PREFIX = "privasys-website-passkey/v1"

    // secp256r1 domain parameters (SEC 2). Hard-coded so the derivation and
    // its check do not depend on which EC provider a platform ships.
    val P: BigInteger = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    val A: BigInteger = P.subtract(BigInteger.valueOf(3))
    val B: BigInteger = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
    val N: BigInteger = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
    val GX: BigInteger = BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
    val GY: BigInteger = BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)

    /** A derived passkey: the 32-byte big-endian scalar and its SEC1 uncompressed public key. */
    class DerivedKey(val scalar: ByteArray, val publicKey: ByteArray) {
        /** x || y, 64 bytes, as the COSE key builder wants. */
        val rawPublicKey: ByteArray get() = publicKey.copyOfRange(1, 65)

        /** Overwrite the scalar once the signature is made, so it lives in memory as briefly as we can manage. */
        fun wipe() = scalar.fill(0)
    }

    fun isSyncedCredentialId(credentialId: ByteArray): Boolean =
        credentialId.size == SYNCED_ID_LENGTH && credentialId[0] == SYNCED_ID_VERSION

    /** The 16 random bytes `r` a synced credential id carries after its version byte. */
    fun randomOf(credentialId: ByteArray): ByteArray {
        require(isSyncedCredentialId(credentialId)) { "not a synced credential id" }
        return credentialId.copyOfRange(1, SYNCED_ID_LENGTH)
    }

    /** The P-256 scalar only, for signing. The public point is not needed there, and skipping it keeps signing quick. */
    fun deriveScalar(root: ByteArray, r: ByteArray, rpId: String): ByteArray {
        require(root.size == 32) { "passkey root must be 32 bytes" }
        require(r.size == 16) { "r must be 16 bytes" }
        val info = INFO_PREFIX.toByteArray(Charsets.UTF_8) + byteArrayOf(0x00) + rpId.toByteArray(Charsets.UTF_8)
        val okm = hkdfSha256(ikm = root, salt = r, info = info, length = 48)
        // 48 bytes reduced mod (n - 1), plus 1: the bias is negligible and the
        // result is never zero. The same reduction as holder-keys.ts.
        val d = BigInteger(1, okm).mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE)
        okm.fill(0)
        return toFixed32(d)
    }

    /** The scalar and its public key: what registration needs. */
    fun derive(root: ByteArray, r: ByteArray, rpId: String): DerivedKey {
        val scalar = deriveScalar(root, r, rpId)
        val q = multiply(BigInteger(1, scalar), GX, GY)
            ?: error("derived scalar gave the point at infinity")
        return DerivedKey(scalar, byteArrayOf(0x04) + toFixed32(q.first) + toFixed32(q.second))
    }

    /**
     * A software PrivateKey for the scalar, for Signature("SHA256withECDSA").
     * The curve comes from the platform by name so the key carries exactly
     * the parameter spec the platform's signer expects.
     */
    fun privateKeyFor(scalar: ByteArray): PrivateKey {
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
        val spec = params.getParameterSpec(ECParameterSpec::class.java)
        return KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, scalar), spec))
    }

    // ─── HKDF-SHA256 (RFC 5869) ────────────────────────────────────────

    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..(255 * 32)) { "HKDF length out of range" }
        // RFC 5869: an absent salt is HashLen zero bytes. SecretKeySpec refuses
        // an empty key, and HMAC pads a short key with zeros anyway, so the
        // two are the same HMAC.
        val extractKey = if (salt.isEmpty()) ByteArray(32) else salt
        val prk = hmac(extractKey, ikm)

        val okm = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            previous = hmac(prk, previous + info + byteArrayOf(counter.toByte()))
            val take = minOf(previous.size, length - offset)
            System.arraycopy(previous, 0, okm, offset, take)
            offset += take
            counter++
        }
        prk.fill(0)
        return okm
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    // ─── P-256 point arithmetic (affine, for the public key only) ──────
    //
    // BigInteger is not constant time. It is used here only to compute the
    // public point at registration; signing goes through the platform's
    // Signature with the scalar, never through this code.

    private fun multiply(k: BigInteger, x: BigInteger, y: BigInteger): Pair<BigInteger, BigInteger>? {
        // Montgomery ladder: the same sequence of add and double for every bit.
        var r0: Pair<BigInteger, BigInteger>? = null
        var r1: Pair<BigInteger, BigInteger>? = Pair(x, y)
        for (i in k.bitLength() - 1 downTo 0) {
            if (k.testBit(i)) {
                r0 = add(r0, r1)
                r1 = add(r1, r1)
            } else {
                r1 = add(r0, r1)
                r0 = add(r0, r0)
            }
        }
        return r0
    }

    /** Affine point addition; null is the point at infinity. */
    private fun add(p1: Pair<BigInteger, BigInteger>?, p2: Pair<BigInteger, BigInteger>?): Pair<BigInteger, BigInteger>? {
        if (p1 == null) return p2
        if (p2 == null) return p1
        val (x1, y1) = p1
        val (x2, y2) = p2
        val lambda = if (x1 == x2) {
            if (y1.add(y2).mod(P).signum() == 0) return null // P + (-P)
            // Doubling: (3x^2 + a) / 2y
            x1.multiply(x1).multiply(BigInteger.valueOf(3)).add(A)
                .multiply(y1.shiftLeft(1).modInverse(P)).mod(P)
        } else {
            y2.subtract(y1).multiply(x2.subtract(x1).modInverse(P)).mod(P)
        }
        val x3 = lambda.multiply(lambda).subtract(x1).subtract(x2).mod(P)
        val y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(P)
        return Pair(x3, y3)
    }

    fun isOnCurve(x: BigInteger, y: BigInteger): Boolean =
        y.multiply(y).subtract(x.pow(3).add(A.multiply(x)).add(B)).mod(P).signum() == 0

    private fun toFixed32(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        return when {
            raw.size == 32 -> raw
            raw.size > 32 -> raw.copyOfRange(raw.size - 32, raw.size) // drop the sign byte
            else -> ByteArray(32 - raw.size) + raw
        }
    }
}
