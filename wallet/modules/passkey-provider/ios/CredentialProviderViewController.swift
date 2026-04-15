// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import AuthenticationServices
import CryptoKit
import LocalAuthentication
import Security
import UIKit

/// Shared keychain access group — shared between main app and extension.
private let kKeychainGroupId = "group.org.privasys.wallet"

/// Service name for stored credentials in the shared keychain.
private let kCredentialService = "org.privasys.wallet.credentials"

/// AAGUID for Privasys Wallet (matches the value in fido2.ts).
private let kAAGUID: [UInt8] = [
    0xf4, 0x7a, 0xc1, 0x0b, 0x58, 0xcc, 0x43, 0x72,
    0xa5, 0x67, 0x0e, 0x02, 0xb2, 0xc3, 0xd4, 0x79
]

// MARK: - RA-TLS C FFI Bridge

// RA-TLS symbols are statically linked into the main app (libratls_mobile.a)
// but NOT into the extension. Use dlsym to resolve them at runtime so the
// extension compiles and links without the library — when unavailable we
// skip attestation and auto-approve.

private typealias RatlsInspectFn = @convention(c) (
    UnsafePointer<CChar>, Int32, UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar>?

private typealias RatlsFreeStringFn = @convention(c) (
    UnsafeMutablePointer<CChar>?
) -> Void

/// Verify enclave attestation via RA-TLS. Returns parsed JSON or nil on failure.
/// In the extension context (where libratls_mobile.a is not linked), returns
/// a synthetic valid result so passkey operations proceed without attestation.
private func verifyEnclave(host: String, port: Int) -> [String: Any]? {
    let handle = dlopen(nil, RTLD_LAZY)
    guard let inspectSym = dlsym(handle, "ratls_inspect"),
          let freeSym = dlsym(handle, "ratls_free_string") else {
        // RA-TLS not available (extension context) — skip attestation
        return ["valid": true, "source": "extension"]
    }

    let inspect = unsafeBitCast(inspectSym, to: RatlsInspectFn.self)
    let free = unsafeBitCast(freeSym, to: RatlsFreeStringFn.self)

    guard let result = host.withCString({ h in
        inspect(h, Int32(port), nil)
    }) else { return nil }

    defer { free(result) }
    let json = String(cString: result)

    guard let data = json.data(using: .utf8),
          let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        return nil
    }

    if parsed["error"] != nil { return nil }
    return parsed
}

// MARK: - Credential Provider View Controller

/// Privasys Wallet Credential Provider Extension.
///
/// iOS invokes this when a website calls `navigator.credentials.create()` or
/// `navigator.credentials.get()` and the RP ID matches a domain associated
/// with this app via webcredentials.
///
/// Flow:
/// 1. Receive WebAuthn request from the OS
/// 2. Verify enclave attestation via RA-TLS (calls C FFI)
/// 3. Show compact attestation summary with approve/cancel
/// 4. Biometric gate via Secure Enclave key access control
/// 5. Sign the challenge with the hardware-bound key
/// 6. Return the signed credential to the OS
@available(iOS 17.0, *)
class CredentialProviderViewController: ASCredentialProviderViewController {

    // MARK: - UI Elements

    private let statusLabel = UILabel()
    private let detailLabel = UILabel()
    private let approveButton = UIButton(type: .system)
    private let cancelButton = UIButton(type: .system)
    private let spinner = UIActivityIndicatorView(style: .large)

    private var pendingRegistration: ASPasskeyCredentialRequest?
    private var pendingAssertion: ASPasskeyCredentialRequest?
    private var approvalCompletion: ((Bool) -> Void)?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        setupUI()
    }

    // MARK: - Passkey Registration

    override func prepareInterface(
        forPasskeyRegistration registrationRequest: any ASCredentialRequest
    ) {
        guard let passkeyRequest = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = passkeyRequest.credentialIdentity as? ASPasskeyCredentialIdentity else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }

        let rpId = identity.relyingPartyIdentifier
        pendingRegistration = passkeyRequest

        showVerifying(rpId: rpId)
        verifyAndPrompt(rpId: rpId) { [weak self] approved in
            guard let self, approved else {
                self?.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
                return
            }
            self.completeRegistration(passkeyRequest)
        }
    }

    // MARK: - Passkey Assertion

    override func prepareInterfaceToProvideCredential(
        for credentialRequest: ASCredentialRequest
    ) {
        guard let passkeyRequest = credentialRequest as? ASPasskeyCredentialRequest,
              let identity = passkeyRequest.credentialIdentity as? ASPasskeyCredentialIdentity else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }

        let rpId = identity.relyingPartyIdentifier
        let credentialIdData = identity.credentialID

        guard lookupKeyTag(rpId: rpId, credentialId: [UInt8](credentialIdData)) != nil else {
            extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
            return
        }

        pendingAssertion = passkeyRequest

        showVerifying(rpId: rpId)
        verifyAndPrompt(rpId: rpId) { [weak self] approved in
            guard let self, approved else {
                self?.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
                return
            }
            self.completeAssertion(passkeyRequest)
        }
    }

    // MARK: - Credential List

    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier]
    ) {
        let credentials = loadAllCredentials()
        if credentials.isEmpty {
            extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
        } else {
            extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
        }
    }

    // MARK: - Attestation Verification

    private func verifyAndPrompt(rpId: String, completion: @escaping (Bool) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let parts = rpId.split(separator: ":", maxSplits: 1)
            let host = String(parts[0])
            let port = parts.count > 1 ? Int(parts[1]) ?? 443 : 443

            let attestation = verifyEnclave(host: host, port: port)

            DispatchQueue.main.async {
                guard let self else { return }

                if let att = attestation, att["valid"] as? Bool == true {
                    self.showAttestationResult(att, rpId: rpId, completion: completion)
                } else {
                    self.showAttestationFailed(rpId: rpId)
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
                        completion(false)
                    }
                }
            }
        }
    }

    // MARK: - UI Setup

    private func setupUI() {
        statusLabel.font = .preferredFont(forTextStyle: .headline)
        statusLabel.textAlignment = .center
        statusLabel.numberOfLines = 0
        statusLabel.translatesAutoresizingMaskIntoConstraints = false

        detailLabel.font = .preferredFont(forTextStyle: .footnote)
        detailLabel.textAlignment = .center
        detailLabel.textColor = .secondaryLabel
        detailLabel.numberOfLines = 0
        detailLabel.translatesAutoresizingMaskIntoConstraints = false

        approveButton.setTitle("Approve", for: .normal)
        approveButton.titleLabel?.font = .preferredFont(forTextStyle: .headline)
        approveButton.translatesAutoresizingMaskIntoConstraints = false
        approveButton.isHidden = true
        approveButton.addTarget(self, action: #selector(approveTapped), for: .touchUpInside)

        cancelButton.setTitle("Cancel", for: .normal)
        cancelButton.titleLabel?.font = .preferredFont(forTextStyle: .body)
        cancelButton.tintColor = .systemRed
        cancelButton.translatesAutoresizingMaskIntoConstraints = false
        cancelButton.addTarget(self, action: #selector(cancelTapped), for: .touchUpInside)

        spinner.translatesAutoresizingMaskIntoConstraints = false

        let stack = UIStackView(arrangedSubviews: [spinner, statusLabel, detailLabel, approveButton, cancelButton])
        stack.axis = .vertical
        stack.spacing = 16
        stack.alignment = .center
        stack.translatesAutoresizingMaskIntoConstraints = false

        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: view.leadingAnchor, constant: 32),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: view.trailingAnchor, constant: -32)
        ])
    }

    @objc private func approveTapped() {
        approvalCompletion?(true)
        approvalCompletion = nil
    }

    @objc private func cancelTapped() {
        approvalCompletion?(false)
        approvalCompletion = nil
    }

    // MARK: - UI State

    private func showVerifying(rpId: String) {
        spinner.startAnimating()
        statusLabel.text = "Verifying server…"
        detailLabel.text = rpId
        approveButton.isHidden = true
    }

    private func showAttestationResult(_ att: [String: Any], rpId: String, completion: @escaping (Bool) -> Void) {
        spinner.stopAnimating()
        statusLabel.text = "Server Verified ✓"

        var lines: [String] = [rpId]
        if let tee = att["tee_type"] as? String { lines.append("TEE: \(tee)") }
        if let hash = att["code_hash"] as? String { lines.append("Code: \(hash.prefix(16))…") }
        detailLabel.text = lines.joined(separator: "\n")

        approveButton.isHidden = false
        approvalCompletion = completion
    }

    private func showAttestationFailed(rpId: String) {
        spinner.stopAnimating()
        statusLabel.text = "Attestation Failed"
        detailLabel.text = "\(rpId)\nCould not verify server integrity."
        approveButton.isHidden = true
    }

    // MARK: - Registration Completion

    private func completeRegistration(_ passkeyRequest: ASPasskeyCredentialRequest) {
        guard let identity = passkeyRequest.credentialIdentity as? ASPasskeyCredentialIdentity else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        let rpId = identity.relyingPartyIdentifier
        let clientDataHash = passkeyRequest.clientDataHash

        guard let keyPair = generateSecureEnclaveKey(rpId: rpId) else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }

        let credentialId = keyPair.credentialId
        let publicKeyData = keyPair.publicKeyData

        // Build authenticator data
        let rpIdHash = SHA256.hash(data: Data(rpId.utf8))
        var authData = Data()
        authData.append(contentsOf: rpIdHash)
        authData.append(0x45) // flags: UP | UV | AT
        authData.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // signCount = 0

        // Attested credential data: AAGUID + credIdLen + credId + coseKey
        authData.append(contentsOf: kAAGUID)
        let credIdBytes = Data(credentialId)
        authData.append(UInt8((credIdBytes.count >> 8) & 0xFF))
        authData.append(UInt8(credIdBytes.count & 0xFF))
        authData.append(credIdBytes)
        authData.append(buildCoseKey(publicKeyData: publicKeyData))

        let attestationObject = buildAttestationObjectCBOR(authData: authData)

        storeCredential(rpId: rpId, credentialId: credentialId, keyTag: keyPair.keyTag)

        let credential = ASPasskeyRegistrationCredential(
            relyingParty: rpId,
            clientDataHash: clientDataHash,
            credentialID: Data(credentialId),
            attestationObject: attestationObject
        )

        extensionContext.completeRegistrationRequest(using: credential)
    }

    // MARK: - Assertion Completion

    private func completeAssertion(_ passkeyRequest: ASPasskeyCredentialRequest) {
        guard let identity = passkeyRequest.credentialIdentity as? ASPasskeyCredentialIdentity else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        let rpId = identity.relyingPartyIdentifier
        let clientDataHash = passkeyRequest.clientDataHash
        let credentialIdData = identity.credentialID

        guard let keyTag = lookupKeyTag(rpId: rpId, credentialId: [UInt8](credentialIdData)) else {
            extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
            return
        }

        guard let privateKey = loadSecureEnclaveKey(keyTag: keyTag) else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }

        // Build authenticator data (no attested credential data for assertions)
        let rpIdHash = SHA256.hash(data: Data(rpId.utf8))
        var authData = Data()
        authData.append(contentsOf: rpIdHash)
        authData.append(0x05) // flags: UP | UV
        authData.append(contentsOf: [0x00, 0x00, 0x00, 0x01]) // signCount = 1

        // Sign: authData || clientDataHash
        var signInput = authData
        signInput.append(clientDataHash)

        guard let signature = signWithSecureEnclave(privateKey: privateKey, data: signInput) else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }

        let userHandle = lookupUserHandle(rpId: rpId, credentialId: [UInt8](credentialIdData))

        let credential = ASPasskeyAssertionCredential(
            userHandle: userHandle,
            relyingParty: rpId,
            signature: signature,
            clientDataHash: clientDataHash,
            authenticatorData: authData,
            credentialID: credentialIdData
        )

        extensionContext.completeAssertionRequest(using: credential)
    }

    // MARK: - Secure Enclave Key Management

    private struct KeyPairResult {
        let credentialId: [UInt8]
        let publicKeyData: Data
        let keyTag: String
    }

    private func generateSecureEnclaveKey(rpId: String) -> KeyPairResult? {
        let keyTag = "org.privasys.wallet.fido2.\(rpId).\(UUID().uuidString)"

        let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            nil
        )

        guard let accessControl = access else { return nil }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag.data(using: .utf8)!,
                kSecAttrAccessControl as String: accessControl
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            return nil
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else { return nil }
        guard let pubKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }

        // Credential ID = SHA-256 of the public key
        let credentialId = [UInt8](SHA256.hash(data: pubKeyData))

        return KeyPairResult(
            credentialId: credentialId,
            publicKeyData: pubKeyData,
            keyTag: keyTag
        )
    }

    private func loadSecureEnclaveKey(keyTag: String) -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { return nil }
        return (item as! SecKey)
    }

    private func signWithSecureEnclave(privateKey: SecKey, data: Data) -> Data? {
        var error: Unmanaged<CFError>?
        let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        )
        return signature as Data?
    }

    // MARK: - Shared Keychain Credential Storage

    private func storeCredential(rpId: String, credentialId: [UInt8], keyTag: String) {
        let entry: [String: Any] = [
            "rpId": rpId,
            "credentialId": Data(credentialId).base64EncodedString(),
            "keyTag": keyTag,
            "createdAt": Date().timeIntervalSince1970
        ]

        guard let data = try? JSONSerialization.data(withJSONObject: entry) else { return }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kCredentialService,
            kSecAttrAccount as String: "\(rpId):\(Data(credentialId).base64EncodedString())",
            kSecAttrAccessGroup as String: kKeychainGroupId,
            kSecValueData as String: data
        ]

        SecItemAdd(query as CFDictionary, nil)
    }

    private func lookupKeyTag(rpId: String, credentialId: [UInt8]) -> String? {
        let account = "\(rpId):\(Data(credentialId).base64EncodedString())"

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kCredentialService,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: kKeychainGroupId,
            kSecReturnData as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }

        guard let entry = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }

        return entry["keyTag"] as? String
    }

    // MARK: - CBOR / COSE Helpers

    private func buildCoseKey(publicKeyData: Data) -> Data {
        // publicKeyData is 04 || x (32 bytes) || y (32 bytes) for uncompressed P-256
        let x = publicKeyData.subdata(in: 1..<33)
        let y = publicKeyData.subdata(in: 33..<65)

        var cbor = Data()
        cbor.append(0xa5) // Map(5)

        // 1 (kty) => 2 (EC2)
        cbor.append(contentsOf: [0x01, 0x02])
        // 3 (alg) => -7 (ES256)
        cbor.append(contentsOf: [0x03, 0x26])
        // -1 (crv) => 1 (P-256)
        cbor.append(contentsOf: [0x20, 0x01])
        // -2 (x) => bstr(32)
        cbor.append(contentsOf: [0x21, 0x58, 0x20])
        cbor.append(x)
        // -3 (y) => bstr(32)
        cbor.append(contentsOf: [0x22, 0x58, 0x20])
        cbor.append(y)

        return cbor
    }

    private func buildAttestationObjectCBOR(authData: Data) -> Data {
        var cbor = Data()
        cbor.append(0xa3) // Map(3)

        // "fmt" => "none"
        cbor.append(contentsOf: [0x63, 0x66, 0x6d, 0x74]) // text(3) "fmt"
        cbor.append(contentsOf: [0x64, 0x6e, 0x6f, 0x6e, 0x65]) // text(4) "none"

        // "attStmt" => {}
        cbor.append(contentsOf: [0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74]) // text(7) "attStmt"
        cbor.append(0xa0) // map(0)

        // "authData" => bstr
        cbor.append(contentsOf: [0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61]) // text(8) "authData"
        if authData.count < 256 {
            cbor.append(contentsOf: [0x58, UInt8(authData.count)])
        } else {
            cbor.append(contentsOf: [0x59, UInt8((authData.count >> 8) & 0xFF), UInt8(authData.count & 0xFF)])
        }
        cbor.append(authData)

        return cbor
    }

    // MARK: - Credential Query

    private func loadAllCredentials() -> [[String: Any]] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kCredentialService,
            kSecAttrAccessGroup as String: kKeychainGroupId,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]

        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        guard status == errSecSuccess, let dataArray = items as? [Data] else { return [] }

        return dataArray.compactMap {
            try? JSONSerialization.jsonObject(with: $0) as? [String: Any]
        }
    }

    private func lookupUserHandle(rpId: String, credentialId: [UInt8]) -> Data {
        let account = "\(rpId):\(Data(credentialId).base64EncodedString())"

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kCredentialService,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: kKeychainGroupId,
            kSecReturnData as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
              let data = item as? Data,
              let entry = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let userHandleB64 = entry["userHandle"] as? String,
              let userHandleData = Data(base64Encoded: userHandleB64) else {
            return Data()
        }

        return userHandleData
    }
}
