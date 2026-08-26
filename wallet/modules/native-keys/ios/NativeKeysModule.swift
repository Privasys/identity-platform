// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import ExpoModulesCore
import Security
import LocalAuthentication

public class NativeKeysModule: Module {
    private static let keyTagPrefix = "org.privasys.wallet.key."

    // Shared biometric grace window. A single "connect" action signs several
    // times on the same Secure Enclave key back-to-back — the FIDO2 assertion,
    // the EncAuth voucher, and one voucher per extra app host (multi-app
    // attestation). Without a reuse window each SecKeyCreateSignature prompts
    // Face ID again, so one connect became three prompts. Binding signing to a
    // shared LAContext with a short reuse duration means the first signature
    // prompts and the rest of the burst ride that authentication; once the
    // window lapses the next signature prompts afresh. Public-key reads never
    // use this context, so they never prompt.
    private static var signingContext = makeSigningContext()

    private static func makeSigningContext() -> LAContext {
        let ctx = LAContext()
        ctx.touchIDAuthenticationAllowableReuseDuration =
            min(60, LATouchIDAuthenticationMaximumAllowableReuseDuration)
        return ctx
    }

    public func definition() -> ModuleDefinition {
        Name("NativeKeys")

        AsyncFunction("generateKey") { (keyId: String, requireBiometric: Bool) -> String in
            let tag = Self.tag(for: keyId)

            // Return existing key if present
            if let existingPub = Self.loadPublicKey(tag: tag) {
                let info = Self.keyInfoJson(keyId: keyId, publicKey: existingPub, hardwareBacked: true)
                return info
            }

            var accessFlags: SecAccessControlCreateFlags = [.privateKeyUsage]
            if requireBiometric {
                accessFlags.insert(.biometryCurrentSet)
            }

            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                accessFlags,
                nil
            ) else {
                return "{\"error\":\"failed to create access control\"}"
            }

            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: true,
                    kSecAttrApplicationTag as String: tag,
                    kSecAttrAccessControl as String: access
                ] as [String: Any]
            ]

            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                let msg = error?.takeRetainedValue().localizedDescription ?? "unknown"
                return "{\"error\":\"\(msg)\"}"
            }

            guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
                return "{\"error\":\"failed to get public key\"}"
            }

            guard let pubData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
                return "{\"error\":\"failed to export public key\"}"
            }

            return Self.keyInfoJson(keyId: keyId, publicKey: pubData, hardwareBacked: true)
        }

        AsyncFunction("sign") { (keyId: String, dataBase64url: String) -> String in
            let tag = Self.tag(for: keyId)

            guard let data = Self.base64urlDecode(dataBase64url) else {
                return "{\"error\":\"invalid base64url data\"}"
            }

            // Sign with the shared biometric context so a burst of signatures
            // in one ceremony rides a single Face ID (see signingContext).
            //
            // An LAContext is good for ONE authentication. Its reuse window
            // lets a burst of Secure Enclave operations ride that single Face
            // ID, but once the window lapses the context is spent: the next
            // operation FAILS instead of prompting again. The context here is
            // static and was only ever replaced by an explicit step-up, so the
            // first signature more than a minute after the last one failed and
            // kept failing. On a wallet set up minutes earlier that was every
            // WIA enrolment, which is what put the identity verifier out of
            // reach (2026-08-26).
            //
            // So a failure is retried exactly once on a FRESH context, which is
            // guaranteed unspent and prompts. The burst optimisation is intact:
            // the retry only runs when the fast path has already failed.
            if let sig = Self.trySign(tag: tag, data: data, context: Self.signingContext) {
                return "{\"signature\":\"\(Self.base64urlEncode(sig))\"}"
            }
            let fresh = Self.makeSigningContext()
            Self.signingContext = fresh
            if let sig = Self.trySign(tag: tag, data: data, context: fresh) {
                return "{\"signature\":\"\(Self.base64urlEncode(sig))\"}"
            }
            return "{\"error\":\"\(Self.lastSignError)\"}"
        }

        // Force a fresh biometric bound to the signing context for a sensitive
        // step-up (e.g. a vault approval). A brand-new context never silently
        // reuses an earlier unlock, so this always prompts; binding the
        // signature that immediately follows to the same context means that one
        // prompt also authorises the operation-bound signature, instead of the
        // caller showing its own biometric gate AND the Secure Enclave prompting
        // again on the signature (two Face IDs). Resolves false on cancel or
        // when biometry is unavailable.
        AsyncFunction("authenticateForSigning") { (reason: String, promise: Promise) in
            let ctx = Self.makeSigningContext()
            Self.signingContext = ctx
            ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, _ in
                promise.resolve(success)
            }
        }

        AsyncFunction("keyExists") { (keyId: String) -> Bool in
            let tag = Self.tag(for: keyId)
            return Self.loadPublicKey(tag: tag) != nil
        }

        AsyncFunction("deleteKey") { (keyId: String) in
            let tag = Self.tag(for: keyId)
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            ]
            SecItemDelete(query as CFDictionary)
        }

        AsyncFunction("getPublicKey") { (keyId: String) -> String in
            let tag = Self.tag(for: keyId)
            guard let pubData = Self.loadPublicKey(tag: tag) else {
                return "{\"error\":\"key not found\"}"
            }
            return Self.keyInfoJson(keyId: keyId, publicKey: pubData, hardwareBacked: true)
        }
    }

    // MARK: - Helpers

    /// Last failure from `trySign`, so the retry can report why BOTH attempts
    /// failed rather than a bare "unknown".
    private static var lastSignError = "unknown"

    /// One signing attempt on the given context. nil on any failure, with the
    /// reason recorded in `lastSignError`.
    private static func trySign(tag: Data, data: Data, context: LAContext) -> Data? {
        guard let privateKey = loadPrivateKey(tag: tag, context: context) else {
            lastSignError = "key not found"
            return nil
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            lastSignError = (error?.takeRetainedValue().localizedDescription ?? "unknown")
                .replacingOccurrences(of: "\"", with: "'")
            return nil
        }
        return signature
    }

    private static func tag(for keyId: String) -> Data {
        (keyTagPrefix + keyId).data(using: .utf8)!
    }

    private static func loadPrivateKey(tag: Data, context: LAContext? = nil) -> SecKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        // Bind the biometric authentication to the caller's context so the
        // Secure Enclave can honour its reuse window; omitted for public-key
        // reads, which must never prompt.
        if let context = context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { return nil }
        return (item as! SecKey)
    }

    private static func loadPublicKey(tag: Data) -> Data? {
        guard let privateKey = loadPrivateKey(tag: tag),
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let pubData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
        else { return nil }
        return pubData
    }

    private static func keyInfoJson(keyId: String, publicKey: Data, hardwareBacked: Bool) -> String {
        let b64 = base64urlEncode(publicKey)
        return """
        {"keyId":"\(keyId)","publicKey":"\(b64)","hardwareBacked":\(hardwareBacked)}
        """
    }

    private static func base64urlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func base64urlDecode(_ string: String) -> Data? {
        var b64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let pad = (4 - b64.count % 4) % 4
        b64 += String(repeating: "=", count: pad)
        return Data(base64Encoded: b64)
    }
}
