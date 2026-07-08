// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import ExpoModulesCore
import DeviceCheck
import CryptoKit
import Security

/// Expo module wrapping iOS App Attest (DCAppAttestService).
///
/// Generates a hardware-bound key in the Secure Enclave, attests it with Apple,
/// and produces assertions that prove this is a genuine Privasys Wallet.
public class AppAttestModule: Module {

    private static let keychainService = "org.privasys.wallet.appattest"
    private static let keychainKeyIdAccount = "keyId"
    private static let keychainAttestedAccount = "attested"

    public func definition() -> ModuleDefinition {
        Name("AppAttest")

        AsyncFunction("getState") { (scope: String?) -> String in
            let service = DCAppAttestService.shared
            let supported = service.isSupported
            let keyId = Self.loadKeyId(scope)
            let attested = Self.loadAttested(scope)
            return """
            {"supported":\(supported),"keyId":\(keyId.map { "\"\($0)\"" } ?? "null"),"attested":\(attested)}
            """
        }

        // `scope` namespaces the key (nil = the legacy shared key). The WIA
        // flow uses a fresh scoped key per enrolment so every enrol carries a
        // FULL attestation object (a key attests once; assertions cannot
        // satisfy the IdP's strict mode).
        AsyncFunction("generateKey") { (scope: String?) -> String in
            // Return existing key if already generated.
            if let existing = Self.loadKeyId(scope) {
                return existing
            }

            let service = DCAppAttestService.shared
            guard service.isSupported else {
                throw AppAttestError.notSupported
            }

            let keyId = try await service.generateKey()
            Self.saveKeyId(keyId, scope)
            return keyId
        }

        AsyncFunction("attestKey") { (challengeBase64: String, scope: String?) -> String in
            guard let keyId = Self.loadKeyId(scope) else {
                throw AppAttestError.noKey
            }

            let service = DCAppAttestService.shared
            guard service.isSupported else {
                throw AppAttestError.notSupported
            }

            guard let challengeData = Data(base64Encoded: challengeBase64) else {
                throw AppAttestError.invalidChallenge
            }

            // Hash the challenge — App Attest expects SHA-256 of the client data.
            let hash = Data(SHA256.hash(data: challengeData))

            let attestation = try await service.attestKey(keyId, clientDataHash: hash)
            Self.saveAttested(true, scope)
            return attestation.base64EncodedString()
        }

        AsyncFunction("generateAssertion") { (clientDataHashBase64: String, scope: String?) -> String in
            guard let keyId = Self.loadKeyId(scope) else {
                throw AppAttestError.noKey
            }

            let service = DCAppAttestService.shared
            guard service.isSupported else {
                throw AppAttestError.notSupported
            }

            guard let hashData = Data(base64Encoded: clientDataHashBase64) else {
                throw AppAttestError.invalidChallenge
            }

            let assertion = try await service.generateAssertion(keyId, clientDataHash: hashData)
            return assertion.base64EncodedString()
        }

        // Clear cached keyId + attested flag from the Keychain. Used to
        // recover from a stale keyId in the Keychain whose underlying
        // Secure Enclave key no longer exists (e.g. after a reinstall —
        // App Attest keys are bound to the app instance and do not
        // survive uninstall, but our Keychain entry does). Apple
        // rejects attestKey/generateAssertion calls against an unknown
        // keyId with `DCError.invalidInput` (numeric code 2).
        AsyncFunction("reset") { (scope: String?) -> Void in
            Self.deleteKeychainEntry(account: Self.account(Self.keychainKeyIdAccount, scope))
            Self.deleteKeychainEntry(account: Self.account(Self.keychainAttestedAccount, scope))
        }
    }

    // MARK: - Keychain helpers

    /// Keychain account for a key scope: nil/empty = the legacy shared key
    /// ("keyId"), otherwise "keyId-<scope>" (e.g. the WIA enrolment key).
    private static func account(_ base: String, _ scope: String?) -> String {
        guard let s = scope, !s.isEmpty else { return base }
        return "\(base)-\(s)"
    }

    private static func saveKeyId(_ keyId: String, _ scope: String?) {
        saveKeychainString(keyId, account: account(keychainKeyIdAccount, scope))
    }

    private static func loadKeyId(_ scope: String?) -> String? {
        loadKeychainString(account: account(keychainKeyIdAccount, scope))
    }

    private static func saveAttested(_ value: Bool, _ scope: String?) {
        saveKeychainString(value ? "1" : "0", account: account(keychainAttestedAccount, scope))
    }

    private static func loadAttested(_ scope: String?) -> Bool {
        loadKeychainString(account: account(keychainAttestedAccount, scope)) == "1"
    }

    private static func saveKeychainString(_ value: String, account: String) {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
        var addQuery = query
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(addQuery as CFDictionary, nil)
    }

    private static func loadKeychainString(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func deleteKeychainEntry(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }
}

enum AppAttestError: Error, LocalizedError {
    case notSupported
    case noKey
    case invalidChallenge

    var errorDescription: String? {
        switch self {
        case .notSupported: return "App Attest is not supported on this device"
        case .noKey: return "No attestation key — call generateKey() first"
        case .invalidChallenge: return "Invalid base64 challenge data"
        }
    }
}
