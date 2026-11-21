// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import AuthenticationServices
import ExpoModulesCore
import Security
import LocalAuthentication

/// The passkey root handed to setPasskeyRoot was not 32 bytes of base64url.
internal final class InvalidPasskeyRootException: Exception {
    override var reason: String {
        "the passkey root must be 32 bytes, base64url"
    }
}

/// importWebsitePasskeys was given something other than a JSON array.
internal final class InvalidPasskeyListException: Exception {
    override var reason: String {
        "the website passkey list must be a JSON array"
    }
}

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

            // A key the holder must be present to use. With a biometric enrolled
            // it is bound to that enrolment (a changed Face ID invalidates it);
            // on a phone with no working biometric it is gated by the device
            // passcode instead, so the wallet still works, and the choice is
            // remembered so the attestation can say which (key_protection).
            var accessFlags: SecAccessControlCreateFlags = [.privateKeyUsage]
            var protection = "none"
            if requireBiometric {
                if Self.biometricsAvailable() {
                    accessFlags.insert(.biometryCurrentSet)
                    protection = "biometric"
                } else {
                    accessFlags.insert(.userPresence)
                    protection = "passcode"
                }
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
            Self.rememberProtection(tag: tag, protection: protection)

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
            // Biometrics when the phone has them; the device passcode otherwise
            // (the key itself is passcode-gated on such a phone, see generateKey).
            let policy: LAPolicy = Self.biometricsAvailable()
                ? .deviceOwnerAuthenticationWithBiometrics
                : .deviceOwnerAuthentication
            ctx.evaluatePolicy(policy, localizedReason: reason) { success, _ in
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

        // ── Website passkeys ─────────────────────────────────────────────
        // The passkey provider extension (modules/passkey-provider) keeps one
        // record per passkey in the shared keychain group, and derives the
        // keys of "synced" ones from a root the wallet gives it. These read
        // and write the same items (the .operations website-passkeys plan).

        AsyncFunction("setPasskeyRoot") { (rootB64url: String) in
            guard let root = Self.base64urlDecode(rootB64url), root.count == 32 else {
                throw InvalidPasskeyRootException()
            }
            Self.writePasskeyRoot(root)
        }

        AsyncFunction("clearPasskeyRoot") {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: Self.passkeyRootService,
                kSecAttrAccount as String: Self.passkeyRootAccount,
                kSecAttrAccessGroup as String: Self.sharedKeychainGroup,
            ]
            SecItemDelete(query as CFDictionary)
        }

        AsyncFunction("listWebsitePasskeys") { () -> String in
            let list: [[String: Any]] = Self.loadPasskeyRecords().compactMap { record -> [String: Any]? in
                guard let rpId = record["rpId"] as? String,
                      let credentialId = (record["credentialId"] as? String).flatMap({ Data(base64Encoded: $0) })
                else { return nil }
                let userHandle = (record["userHandle"] as? String).flatMap { Data(base64Encoded: $0) } ?? Data()
                return [
                    "rpId": rpId,
                    "credentialId": Self.base64urlEncode(credentialId),
                    "userName": record["userName"] as? String ?? "",
                    "userHandle": Self.base64urlEncode(userHandle),
                    // A record without a kind predates synced passkeys: local.
                    "kind": (record["kind"] as? String) == Self.kindSynced ? Self.kindSynced : Self.kindLocal,
                    "createdAt": Self.createdAtMillis(record["createdAt"]),
                ]
            }
            guard let data = try? JSONSerialization.data(withJSONObject: list),
                  let json = String(data: data, encoding: .utf8) else {
                return "[]"
            }
            return json
        }

        AsyncFunction("importWebsitePasskeys") { (json: String) -> Int in
            guard let data = json.data(using: .utf8),
                  let parsed = try? JSONSerialization.jsonObject(with: data),
                  let entries = parsed as? [[String: Any]] else {
                throw InvalidPasskeyListException()
            }

            var added: [(rpId: String, userName: String, credentialId: Data, userHandle: Data)] = []
            for entry in entries {
                // Synced passkeys only: a local one's key stays on the device
                // that made it, so its record would be useless anywhere else.
                guard (entry["kind"] as? String) == Self.kindSynced,
                      let rpId = entry["rpId"] as? String, !rpId.isEmpty,
                      let credentialId = (entry["credentialId"] as? String).flatMap({ Self.base64urlDecode($0) }),
                      Self.isSyncedCredentialId(credentialId)
                else { continue }
                let userName = entry["userName"] as? String ?? ""
                let userHandle = (entry["userHandle"] as? String).flatMap { Self.base64urlDecode($0) } ?? Data()

                if Self.passkeyRecordExists(rpId: rpId, credentialId: credentialId) { continue }

                // The same shape the extension writes (standard base64 inside
                // the record and in the account name, which is what it looks
                // up), so it cannot tell an imported record from its own.
                var createdAt = Int64(Date().timeIntervalSince1970 * 1000)
                if entry["createdAt"] != nil {
                    createdAt = Self.createdAtMillis(entry["createdAt"])
                }
                let record: [String: Any] = [
                    "rpId": rpId,
                    "credentialId": credentialId.base64EncodedString(),
                    "kind": Self.kindSynced,
                    "userName": userName,
                    "userHandle": userHandle.base64EncodedString(),
                    "createdAt": createdAt,
                ]
                guard let recordData = try? JSONSerialization.data(withJSONObject: record) else { continue }
                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: Self.credentialService,
                    kSecAttrAccount as String: Self.passkeyAccount(rpId: rpId, credentialId: credentialId),
                    kSecAttrAccessGroup as String: Self.sharedKeychainGroup,
                    kSecValueData as String: recordData,
                ]
                if SecItemAdd(query as CFDictionary, nil) == errSecSuccess {
                    added.append((rpId: rpId, userName: userName, credentialId: credentialId, userHandle: userHandle))
                }
            }

            // Tell the OS about them, or AutoFill never offers them. Passkey
            // identities need iOS 17, as does the extension that serves them.
            if #available(iOS 17.0, *), !added.isEmpty {
                let identities: [ASCredentialIdentity] = added.map { item -> ASCredentialIdentity in
                    ASPasskeyCredentialIdentity(
                        relyingPartyIdentifier: item.rpId,
                        userName: item.userName,
                        credentialID: item.credentialId,
                        userHandle: item.userHandle
                    )
                }
                ASCredentialIdentityStore.shared.saveCredentialIdentities(identities) { _, error in
                    if let error {
                        // Non-fatal: the records are there and the provider
                        // list still finds them; only the suggestion waits.
                        NSLog("NativeKeys: identity-store save failed: %@", error.localizedDescription)
                    }
                }
            }
            return added.count
        }

        AsyncFunction("deleteWebsitePasskey") { (rpId: String, credentialIdB64url: String) in
            guard let credentialId = Self.base64urlDecode(credentialIdB64url) else { return }
            let account = Self.passkeyAccount(rpId: rpId, credentialId: credentialId)
            let record = Self.loadPasskeyRecord(account: account)

            // A local passkey's Secure Enclave key goes with it. The extension
            // made it without naming a group, and its only group is the shared
            // one, so a search by tag across this app's groups finds it.
            if let keyTag = record?["keyTag"] as? String, let tag = keyTag.data(using: .utf8) {
                let keyQuery: [String: Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecAttrApplicationTag as String: tag,
                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                ]
                SecItemDelete(keyQuery as CFDictionary)
            }

            let recordQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: Self.credentialService,
                kSecAttrAccount as String: account,
                kSecAttrAccessGroup as String: Self.sharedKeychainGroup,
            ]
            SecItemDelete(recordQuery as CFDictionary)

            if #available(iOS 17.0, *) {
                let userName = record?["userName"] as? String ?? ""
                let userHandle = (record?["userHandle"] as? String).flatMap { Data(base64Encoded: $0) } ?? Data()
                let identity = ASPasskeyCredentialIdentity(
                    relyingPartyIdentifier: rpId,
                    userName: userName,
                    credentialID: credentialId,
                    userHandle: userHandle
                )
                ASCredentialIdentityStore.shared.removeCredentialIdentities([identity]) { _, error in
                    if let error {
                        NSLog("NativeKeys: identity-store removal failed: %@", error.localizedDescription)
                    }
                }
            }
        }
    }

    // MARK: - Website Passkeys

    /// The keychain access group the passkey provider extension shares with
    /// the app (unprefixed, as the extension and the notification service use
    /// it: iOS resolves it against the entitled list).
    private static let sharedKeychainGroup = "org.privasys.shared"
    /// One record per website passkey, written by the extension.
    private static let credentialService = "org.privasys.wallet.credentials"
    /// The passkey root the extension derives synced passkeys from.
    private static let passkeyRootService = "org.privasys.wallet.passkey-root"
    private static let passkeyRootAccount = "root"

    private static let kindLocal = "local"
    private static let kindSynced = "synced"

    /// Writes the root as 32 raw bytes, on this device only: never in a
    /// backup, never in iCloud Keychain. A new device gets its own from the
    /// seed when the wallet is set up there.
    private static func writePasskeyRoot(_ root: Data) {
        let match: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: passkeyRootService,
            kSecAttrAccount as String: passkeyRootAccount,
            kSecAttrAccessGroup as String: sharedKeychainGroup,
        ]
        let update: [String: Any] = [
            kSecValueData as String: root,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemUpdate(match as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = match
            add[kSecValueData as String] = root
            add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            add[kSecAttrSynchronizable as String] = false
            SecItemAdd(add as CFDictionary, nil)
        }
    }

    /// The extension's account name for a record: rpId, a colon, and the
    /// credential id in standard base64.
    private static func passkeyAccount(rpId: String, credentialId: Data) -> String {
        "\(rpId):\(credentialId.base64EncodedString())"
    }

    /// 0x01 followed by 16 random bytes: the shape of a synced credential id.
    private static func isSyncedCredentialId(_ credentialId: Data) -> Bool {
        credentialId.count == 17 && credentialId.first == 0x01
    }

    private static func loadPasskeyRecords() -> [[String: Any]] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: credentialService,
            kSecAttrAccessGroup as String: sharedKeychainGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        guard status == errSecSuccess, let dataArray = items as? [Data] else { return [] }
        return dataArray.compactMap {
            try? JSONSerialization.jsonObject(with: $0) as? [String: Any]
        }
    }

    private static func loadPasskeyRecord(account: String) -> [String: Any]? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: credentialService,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: sharedKeychainGroup,
            kSecReturnData as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    private static func passkeyRecordExists(rpId: String, credentialId: Data) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: credentialService,
            kSecAttrAccount as String: passkeyAccount(rpId: rpId, credentialId: credentialId),
            kSecAttrAccessGroup as String: sharedKeychainGroup,
        ]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    /// createdAt in milliseconds. Records the extension wrote before synced
    /// passkeys hold seconds (a Double); anything below 1e11 cannot be a
    /// millisecond time after 1973, so it is taken as seconds.
    private static func createdAtMillis(_ value: Any?) -> Int64 {
        guard let number = value as? NSNumber else { return 0 }
        let raw = number.doubleValue
        guard raw.isFinite, raw > 0 else { return 0 }
        return raw < 1e11 ? Int64(raw * 1000) : Int64(raw)
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

    /// Whether a biometric is enrolled and usable right now.
    private static func biometricsAvailable() -> Bool {
        var err: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
    }

    private static let protectionPrefix = "org.privasys.wallet.keyprotection."

    /// Remembers how a key gates its use, so key info can report it later.
    private static func rememberProtection(tag: Data, protection: String) {
        UserDefaults.standard.set(protection, forKey: protectionPrefix + base64urlEncode(tag))
    }

    /// How a key gates its use: "biometric" (the default for keys made before
    /// this was recorded), "passcode" or "none".
    private static func protection(tag: Data) -> String {
        UserDefaults.standard.string(forKey: protectionPrefix + base64urlEncode(tag)) ?? "biometric"
    }

    private static func keyInfoJson(keyId: String, publicKey: Data, hardwareBacked: Bool) -> String {
        let b64 = base64urlEncode(publicKey)
        let prot = protection(tag: tag(for: keyId))
        return """
        {"keyId":"\(keyId)","publicKey":"\(b64)","hardwareBacked":\(hardwareBacked),"protection":"\(prot)"}
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
