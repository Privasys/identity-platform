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

        AsyncFunction("getState") { () -> String in
            let service = DCAppAttestService.shared
            let supported = service.isSupported
            let keyId = Self.loadKeyId()
            let attested = Self.loadAttested()
            return """
            {"supported":\(supported),"keyId":\(keyId.map { "\"\($0)\"" } ?? "null"),"attested":\(attested)}
            """
        }

        AsyncFunction("generateKey") { () -> String in
            // Return existing key if already generated.
            if let existing = Self.loadKeyId() {
                return existing
            }

            let service = DCAppAttestService.shared
            guard service.isSupported else {
                throw AppAttestError.notSupported
            }

            let keyId = try await service.generateKey()
            Self.saveKeyId(keyId)
            return keyId
        }

        AsyncFunction("attestKey") { (challengeBase64: String) -> String in
            guard let keyId = Self.loadKeyId() else {
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
            Self.saveAttested(true)
            return attestation.base64EncodedString()
        }

        AsyncFunction("generateAssertion") { (clientDataHashBase64: String) -> String in
            guard let keyId = Self.loadKeyId() else {
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
        AsyncFunction("reset") { () -> Void in
            Self.deleteKeychainEntry(account: keychainKeyIdAccount)
            Self.deleteKeychainEntry(account: keychainAttestedAccount)
        }
    }

    // MARK: - Keychain helpers

    private static func saveKeyId(_ keyId: String) {
        saveKeychainString(keyId, account: keychainKeyIdAccount)
    }

    private static func loadKeyId() -> String? {
        loadKeychainString(account: keychainKeyIdAccount)
    }

    private static func saveAttested(_ value: Bool) {
        saveKeychainString(value ? "1" : "0", account: keychainAttestedAccount)
    }

    private static func loadAttested() -> Bool {
        loadKeychainString(account: keychainAttestedAccount) == "1"
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
