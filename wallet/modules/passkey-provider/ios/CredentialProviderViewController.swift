// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import AuthenticationServices
import CryptoKit
import LocalAuthentication
import Security
import UIKit

/// Shared keychain access group, matching the extension entitlement
/// `$(AppIdentifierPrefix)org.privasys.shared`.
///
/// This read "group.org.privasys.wallet", which is an APP GROUP identifier, not
/// a keychain access group, and no app group is entitled anywhere in the
/// project. Every SecItem call therefore failed with errSecMissingEntitlement:
/// lookupKeyTag found nothing, the assertion path cancelled with
/// credentialIdentityNotFound, and picking Privasys Wallet in the OS passkey
/// sheet did visibly nothing at all (2026-09-08).
///
/// No team prefix: iOS resolves an unprefixed group against the entitled list.
private let kKeychainGroupId = "org.privasys.shared"

/// Service name for stored credentials in the shared keychain.
private let kCredentialService = "org.privasys.wallet.credentials"

/// AAGUID for Privasys Wallet (matches the value in fido2.ts).
private let kAAGUID: [UInt8] = [
    0xf4, 0x7a, 0xc1, 0x0b, 0x58, 0xcc, 0x43, 0x72,
    0xa5, 0x67, 0x0e, 0x02, 0xb2, 0xc3, 0xd4, 0x79
]

// MARK: - Synced Website Passkeys

/// The passkey root: the one secret the wallet hands this extension so it can
/// derive "synced" website passkeys. The extension never sees the seed. The
/// wallet (NativeKeysModule.setPasskeyRoot) writes it as 32 raw bytes in the
/// shared group, this device only.
private let kPasskeyRootService = "org.privasys.wallet.passkey-root"
private let kPasskeyRootAccount = "root"

/// First byte of a synced credential id ("synced v1"). A synced id is this
/// byte followed by 16 random bytes; a local id is SHA-256 of the public key,
/// 32 bytes, so the length and first byte tell them apart.
private let kSyncedCredentialVersion: UInt8 = 0x01
private let kSyncedCredentialIdLength = 17

/// The record `kind` values. A record without a kind predates synced passkeys
/// and is local.
private let kKindLocal = "local"
private let kKindSynced = "synced"

/// Authenticator data flags. Local keys cannot be backed up (no BE/BS); a
/// synced key is backup eligible and backed up from the moment it is made,
/// since every device of the holder can derive it again.
private let kFlagsLocalRegistration: UInt8 = 0x45   // UP | UV | AT
private let kFlagsLocalAssertion: UInt8 = 0x05      // UP | UV
private let kFlagsSyncedRegistration: UInt8 = 0x5D  // UP | UV | BE | BS | AT
private let kFlagsSyncedAssertion: UInt8 = 0x1D     // UP | UV | BE | BS

/// n - 1 for P-256, as four 64-bit limbs, most significant first.
/// n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551.
private let kP256OrderMinusOne: [UInt64] = [
    0xFFFF_FFFF_0000_0000,
    0xFFFF_FFFF_FFFF_FFFF,
    0xBCE6_FAAD_A717_9E84,
    0xF3B9_CAC2_FC63_2550
]

/// Whether a credential id is a synced one, by its shape alone.
func isSyncedCredentialId(_ credentialId: [UInt8]) -> Bool {
    credentialId.count == kSyncedCredentialIdLength && credentialId.first == kSyncedCredentialVersion
}

/// A synced website passkey's private scalar (32 bytes, big-endian), from the
/// passkey root, the credential's random part `r` and the site. Pure, so a
/// test target can check it against the plan's vector without a keychain:
///
///   okm    = HKDF-SHA256(ikm = root, salt = r, info = "privasys-website-passkey/v1" || 0x00 || rpId, L = 48)
///   scalar = (BE-int(okm) mod (n - 1)) + 1
///
/// The same reduction as the wallet's holder-keys.ts and
/// services/website-passkeys.ts: 48 bytes keep the bias negligible and the +1
/// keeps the scalar out of zero. Binding rpId into the info means the same r
/// on another site gives another, unrelated key.
///
/// Test vector (the wallet's src/__tests__/website-passkeys.test.ts), with seed = 00 01 .. 1f,
/// r = a0 a1 .. af, rpId = "example.com":
///   root   = dbf48f5caf769655c82494e38ee824617874a623539f5b33640abe1cdb9dedf5
///   scalar = 9c69d00194d9cd3bee2b12c2ab4be00f72f6e23b7ca186c39d0d3f52cb3caf54
///   pub    = 04685fddec15bcd5babcb8be6b181a43964279b8f9cc63a7620f9f5b9fdcd0094a
///              3c2506a8b0a00426b39c47475b61423a3074a0f9092735b9b868c26571c48556
func derivePasskeyScalar(root: [UInt8], r: [UInt8], rpId: String) -> [UInt8] {
    var info = Array("privasys-website-passkey/v1".utf8)
    info.append(0x00)
    info.append(contentsOf: Array(rpId.utf8))
    let okm = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: root),
        salt: r,
        info: info,
        outputByteCount: 48
    )
    var wide = okm.withUnsafeBytes { Array($0) }
    defer { wipe(&wide) }
    return reduceToP256Scalar(wide)
}

/// (BE-int(bytes) mod (n - 1)) + 1 as 32 big-endian bytes.
///
/// Binary long division one bit at a time: shift the remainder left, bring in
/// the next bit, and subtract the modulus whenever the result reached it. The
/// remainder stays below n - 1 < 2^256, so after a shift it is below 2^257:
/// four limbs plus the one bit shifted out of the top. The subtraction is
/// always computed and then selected with a mask, so the time taken does not
/// depend on the key's bits.
func reduceToP256Scalar(_ bytes: [UInt8]) -> [UInt8] {
    let m = kP256OrderMinusOne
    var acc: [UInt64] = [0, 0, 0, 0]
    var diff: [UInt64] = [0, 0, 0, 0]
    defer {
        for i in 0..<4 { acc[i] = 0; diff[i] = 0 }
    }

    for byte in bytes {
        for bit in stride(from: 7, through: 0, by: -1) {
            let incoming = UInt64((byte >> UInt8(bit)) & 1)
            let carry = acc[0] >> 63
            acc[0] = (acc[0] << 1) | (acc[1] >> 63)
            acc[1] = (acc[1] << 1) | (acc[2] >> 63)
            acc[2] = (acc[2] << 1) | (acc[3] >> 63)
            acc[3] = (acc[3] << 1) | incoming

            var borrow: UInt64 = 0
            for i in stride(from: 3, through: 0, by: -1) {
                let (d1, o1) = acc[i].subtractingReportingOverflow(m[i])
                let (d2, o2) = d1.subtractingReportingOverflow(borrow)
                diff[i] = d2
                borrow = (o1 || o2) ? 1 : 0
            }

            // Keep the difference when the 257-bit value was at least m:
            // a bit went out of the top, or the subtraction did not borrow.
            let useDiff = carry | (borrow ^ 1)
            let mask = 0 &- useDiff
            for i in 0..<4 {
                acc[i] = (diff[i] & mask) | (acc[i] & ~mask)
            }
        }
    }

    // + 1. The remainder is at most n - 2, so this never overflows 256 bits.
    var carryIn: UInt64 = 1
    for i in stride(from: 3, through: 0, by: -1) {
        let (sum, overflow) = acc[i].addingReportingOverflow(carryIn)
        acc[i] = sum
        carryIn = overflow ? 1 : 0
    }

    var out = [UInt8](repeating: 0, count: 32)
    for i in 0..<4 {
        for j in 0..<8 {
            out[i * 8 + j] = UInt8(truncatingIfNeeded: acc[i] >> UInt64(56 - j * 8))
        }
    }
    return out
}

/// Best-effort scrub of key material held in a byte array.
private func wipe(_ bytes: inout [UInt8]) {
    for i in bytes.indices { bytes[i] = 0 }
}

/// The signing key of a synced passkey. It lives in memory only for the
/// signature (or, at registration, for its public key); nothing is stored.
private func syncedPrivateKey(root: [UInt8], r: [UInt8], rpId: String) throws -> P256.Signing.PrivateKey {
    var scalar = derivePasskeyScalar(root: root, r: r, rpId: rpId)
    defer { wipe(&scalar) }
    return try P256.Signing.PrivateKey(rawRepresentation: scalar)
}

/// The passkey root from the shared keychain, or nil when the wallet has not
/// installed one (no profile yet, or a wallet older than synced passkeys).
private func loadPasskeyRoot() -> [UInt8]? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: kPasskeyRootService,
        kSecAttrAccount as String: kPasskeyRootAccount,
        kSecAttrAccessGroup as String: kKeychainGroupId,
        kSecReturnData as String: true
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let data = item as? Data, data.count == 32 else { return nil }
    return [UInt8](data)
}

/// Fresh random bytes from the system generator, or nil if it refuses.
private func randomBytes(_ count: Int) -> [UInt8]? {
    var bytes = [UInt8](repeating: 0, count: count)
    let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return status == errSecSuccess ? bytes : nil
}

/// Where a new passkey is kept.
private enum PasskeyKind {
    case local
    case synced
}

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
/// 4. On registration, ask where the passkey is kept: on this device only (a
///    Secure Enclave key) or backed up to the holder's devices (a key derived
///    from the passkey root).
/// 5. Biometric gate: the Secure Enclave key's access control for a local
///    passkey, an LAContext check made here for a synced one
/// 6. Sign the challenge and return the credential to the OS
@available(iOS 17.0, *)
class CredentialProviderViewController: ASCredentialProviderViewController {

    // MARK: - UI Elements

    private let statusLabel = UILabel()
    private let detailLabel = UILabel()
    private let approveButton = UIButton(type: .system)
    private let syncedButton = UIButton(configuration: .plain())
    private let localButton = UIButton(configuration: .plain())
    private let cancelButton = UIButton(type: .system)
    private let spinner = UIActivityIndicatorView(style: .large)

    private var pendingRegistration: ASPasskeyCredentialRequest?
    private var pendingAssertion: ASPasskeyCredentialRequest?
    private var approvalCompletion: ((Bool) -> Void)?
    private var kindCompletion: ((PasskeyKind?) -> Void)?

    /// "iPad" on an iPad, "iPhone" otherwise, for the wording of the choice.
    private var deviceWord: String {
        UIDevice.current.userInterfaceIdiom == .pad ? "iPad" : "iPhone"
    }

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
            self.chooseKind(for: passkeyRequest, rpId: rpId) { [weak self] kind in
                guard let self, let kind else {
                    self?.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
                    return
                }
                switch kind {
                case .local:
                    self.completeRegistration(passkeyRequest)
                case .synced:
                    self.completeSyncedRegistration(passkeyRequest)
                }
            }
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

        // Any record will do here: a synced one has no key tag, its key is
        // derived when it signs.
        guard lookupRecord(rpId: rpId, credentialId: [UInt8](credentialIdData)) != nil else {
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

    /// Password-style list request (no passkey parameters) — nothing we can
    /// serve; the wallet holds passkeys only.
    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier]
    ) {
        extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
    }

    /// Passkey list request (iOS 17+): the OS hands us the request parameters
    /// (rpId + clientDataHash), so we can complete an assertion directly for a
    /// stored credential instead of cancelling — this is the path taken when
    /// the user picks "Privasys Wallet" from the AutoFill key icon rather than
    /// tapping a suggested credential.
    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier],
        requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        let rpId = requestParameters.relyingPartyIdentifier
        let allowed = requestParameters.allowedCredentials
        let matching = loadAllCredentials()
            .filter { ($0["rpId"] as? String) == rpId }
            .compactMap { entry -> Data? in
                guard let b64 = entry["credentialId"] as? String,
                      let id = Data(base64Encoded: b64) else { return nil }
                return id
            }
            .filter { allowed.isEmpty || allowed.contains($0) }
        guard let credentialId = matching.first else {
            extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
            return
        }

        showVerifying(rpId: rpId)
        verifyAndPrompt(rpId: rpId) { [weak self] approved in
            guard let self, approved else {
                self?.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
                return
            }
            self.completeAssertionRaw(
                rpId: rpId,
                credentialId: [UInt8](credentialId),
                clientDataHash: requestParameters.clientDataHash
            )
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

                let hasMeasurements =
                    attestation?["mrenclave"] != nil || attestation?["mrtd"] != nil

                if let att = attestation, att["valid"] as? Bool == true, hasMeasurements {
                    // A Privasys enclave: show what was attested before approval.
                    self.showAttestationResult(att, rpId: rpId, completion: completion)
                } else if attestation?["valid"] as? Bool == true || attestation == nil {
                    // Not an enclave (a regular website/app using the wallet as
                    // its passkey provider), or RA-TLS is unavailable in the
                    // extension context. Attestation does not apply — show a
                    // plain consent prompt instead of failing, mirroring the
                    // main app's non-enclave FIDO2 support.
                    self.showPlainApproval(rpId: rpId, completion: completion)
                } else {
                    // The host IS an enclave whose attestation failed — hard stop.
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

        for button in [syncedButton, localButton] {
            button.translatesAutoresizingMaskIntoConstraints = false
            button.isHidden = true
        }
        syncedButton.addTarget(self, action: #selector(syncedTapped), for: .touchUpInside)
        localButton.addTarget(self, action: #selector(localTapped), for: .touchUpInside)

        cancelButton.setTitle("Cancel", for: .normal)
        cancelButton.titleLabel?.font = .preferredFont(forTextStyle: .body)
        cancelButton.tintColor = .systemRed
        cancelButton.translatesAutoresizingMaskIntoConstraints = false
        cancelButton.addTarget(self, action: #selector(cancelTapped), for: .touchUpInside)

        spinner.translatesAutoresizingMaskIntoConstraints = false

        let stack = UIStackView(arrangedSubviews: [
            spinner, statusLabel, detailLabel, approveButton, syncedButton, localButton, cancelButton
        ])
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
        finishChoice(nil)
    }

    @objc private func syncedTapped() {
        finishChoice(.synced)
    }

    @objc private func localTapped() {
        finishChoice(.local)
    }

    private func finishChoice(_ kind: PasskeyKind?) {
        syncedButton.isHidden = true
        localButton.isHidden = true
        let completion = kindCompletion
        kindCompletion = nil
        completion?(kind)
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
        if let hash = att["workload_code_hash"] as? String { lines.append("Code: \(hash.prefix(16))…") }
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

    /// Consent prompt for a relying party that is not a Privasys enclave —
    /// the wallet acting as a general-purpose OS passkey provider. No
    /// "verified" claim is made; the biometric gate on the Secure Enclave key
    /// still applies at signing time.
    private func showPlainApproval(rpId: String, completion: @escaping (Bool) -> Void) {
        spinner.stopAnimating()
        statusLabel.text = "Use your Privasys passkey?"
        detailLabel.text = rpId
        approveButton.isHidden = false
        approvalCompletion = completion
    }

    /// Where a new passkey is kept. The holder chooses, unless the site asks
    /// for a hardware-bound key or the wallet has not installed the passkey
    /// root yet: then the only offer is this device, with what that means.
    private func chooseKind(
        for request: ASPasskeyCredentialRequest,
        rpId: String,
        completion: @escaping (PasskeyKind?) -> Void
    ) {
        spinner.stopAnimating()
        approveButton.isHidden = true

        let device = deviceWord
        configureChoiceButton(
            syncedButton,
            title: "Save to your devices",
            subtitle: "Backed up to your other devices through your Privasys Wallet. Never to Apple or Google."
        )
        configureChoiceButton(
            localButton,
            title: "Save on this \(device) only",
            subtitle: "It stays on this \(device) and is lost with it."
        )

        // iOS does not hand a provider the site's attestation preference (only
        // the site's own request carries it), so on iOS the holder's choice
        // stands for every site. The attestation format is "none" either way.
        if loadPasskeyRoot() == nil {
            statusLabel.text = "Save a passkey on this \(device)"
            detailLabel.text = "\(rpId)\nTo back up new passkeys to your devices, open Privasys Wallet first."
            syncedButton.isHidden = true
        } else {
            statusLabel.text = "Where should this passkey be saved?"
            detailLabel.text = rpId
            syncedButton.isHidden = false
        }
        localButton.isHidden = false
        kindCompletion = completion
    }

    /// A choice button in the extension's plain style: the option as a
    /// headline, what it means underneath in secondary text.
    private func configureChoiceButton(_ button: UIButton, title: String, subtitle: String) {
        var config = UIButton.Configuration.plain()
        config.title = title
        config.subtitle = subtitle
        config.titleAlignment = .center
        config.titlePadding = 4
        config.titleTextAttributesTransformer = UIConfigurationTextAttributesTransformer { incoming in
            var outgoing = incoming
            outgoing.font = .preferredFont(forTextStyle: .headline)
            return outgoing
        }
        config.subtitleTextAttributesTransformer = UIConfigurationTextAttributesTransformer { incoming in
            var outgoing = incoming
            outgoing.font = .preferredFont(forTextStyle: .footnote)
            outgoing.foregroundColor = .secondaryLabel
            return outgoing
        }
        button.configuration = config
    }

    // MARK: - Holder Check

    /// The biometric (or device passcode) check for a synced passkey. A local
    /// key's Secure Enclave access control does this by itself; a derived key
    /// has no such guard, so the extension asks before it derives one.
    /// `.deviceOwnerAuthentication` tries the biometric first and falls back
    /// to the passcode. Calls back on the main queue.
    private func authenticateHolder(reason: String, completion: @escaping (Bool) -> Void) {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            DispatchQueue.main.async { completion(false) }
            return
        }
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
            DispatchQueue.main.async { completion(success) }
        }
    }

    // MARK: - Registration Completion

    /// A local passkey: a new Secure Enclave key, never leaving this device.
    private func completeRegistration(_ passkeyRequest: ASPasskeyCredentialRequest) {
        guard let identity = passkeyRequest.credentialIdentity as? ASPasskeyCredentialIdentity else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        let rpId = identity.relyingPartyIdentifier

        guard let keyPair = generateSecureEnclaveKey(rpId: rpId) else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }

        storeCredential(
            rpId: rpId,
            credentialId: keyPair.credentialId,
            keyTag: keyPair.keyTag,
            kind: kKindLocal,
            userName: identity.userName,
            userHandle: identity.userHandle
        )
        finishRegistration(
            identity: identity,
            clientDataHash: passkeyRequest.clientDataHash,
            credentialId: keyPair.credentialId,
            publicKeyData: keyPair.publicKeyData,
            flags: kFlagsLocalRegistration
        )
    }

    /// A synced passkey: credential id 0x01 || r, its key derived from the
    /// passkey root, r and the site, so every device of the holder can derive
    /// it again. Nothing secret is stored; the record says only that it exists.
    private func completeSyncedRegistration(_ passkeyRequest: ASPasskeyCredentialRequest) {
        guard let identity = passkeyRequest.credentialIdentity as? ASPasskeyCredentialIdentity else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        let rpId = identity.relyingPartyIdentifier

        // The UV flag says the holder was verified, and for a derived key that
        // is only true if the extension checked, so it checks here too.
        authenticateHolder(reason: "Save a passkey for \(rpId)") { [weak self] verified in
            guard let self else { return }
            guard verified else {
                self.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
                return
            }
            guard var root = loadPasskeyRoot(), let r = randomBytes(16) else {
                self.extensionContext.cancelRequest(withError: ASExtensionError(.failed))
                return
            }
            defer { wipe(&root) }

            guard let privateKey = try? syncedPrivateKey(root: root, r: r, rpId: rpId) else {
                self.extensionContext.cancelRequest(withError: ASExtensionError(.failed))
                return
            }
            let credentialId = [kSyncedCredentialVersion] + r
            // 04 || x || y, the same layout SecKeyCopyExternalRepresentation
            // gives for a Secure Enclave key, so buildCoseKey serves both.
            let publicKeyData = privateKey.publicKey.x963Representation

            self.storeCredential(
                rpId: rpId,
                credentialId: credentialId,
                keyTag: nil,
                kind: kKindSynced,
                userName: identity.userName,
                userHandle: identity.userHandle
            )
            self.finishRegistration(
                identity: identity,
                clientDataHash: passkeyRequest.clientDataHash,
                credentialId: credentialId,
                publicKeyData: publicKeyData,
                flags: kFlagsSyncedRegistration
            )
        }
    }

    /// The part of a registration both kinds share: the authenticator data,
    /// the "none" attestation, the identity store and the answer to the OS.
    private func finishRegistration(
        identity: ASPasskeyCredentialIdentity,
        clientDataHash: Data,
        credentialId: [UInt8],
        publicKeyData: Data,
        flags: UInt8
    ) {
        let rpId = identity.relyingPartyIdentifier

        // Build authenticator data
        let rpIdHash = SHA256.hash(data: Data(rpId.utf8))
        var authData = Data()
        authData.append(contentsOf: rpIdHash)
        authData.append(flags)
        authData.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // signCount = 0

        // Attested credential data: AAGUID + credIdLen + credId + coseKey
        authData.append(contentsOf: kAAGUID)
        let credIdBytes = Data(credentialId)
        authData.append(UInt8((credIdBytes.count >> 8) & 0xFF))
        authData.append(UInt8(credIdBytes.count & 0xFF))
        authData.append(credIdBytes)
        authData.append(buildCoseKey(publicKeyData: publicKeyData))

        let attestationObject = buildAttestationObjectCBOR(authData: authData)

        // Tell the OS which passkey we now hold: without this registration in
        // the credential identity store, AutoFill/QuickType never suggests the
        // wallet's passkeys for this RP again (the OS has no other way to know).
        let storedIdentity = ASPasskeyCredentialIdentity(
            relyingPartyIdentifier: rpId,
            userName: identity.userName,
            credentialID: credIdBytes,
            userHandle: identity.userHandle
        )
        ASCredentialIdentityStore.shared.saveCredentialIdentities([storedIdentity]) { _, error in
            if let error {
                // Non-fatal: the passkey works via the provider list; it just
                // won't be proactively suggested until the next save succeeds.
                NSLog("PasskeyProvider: identity-store save failed: %@", error.localizedDescription)
            }
        }

        let credential = ASPasskeyRegistrationCredential(
            relyingParty: rpId,
            clientDataHash: clientDataHash,
            credentialID: credIdBytes,
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
        completeAssertionRaw(
            rpId: identity.relyingPartyIdentifier,
            credentialId: [UInt8](identity.credentialID),
            clientDataHash: passkeyRequest.clientDataHash
        )
    }

    /// Assertion by raw (rpId, credentialId, clientDataHash), shared by the
    /// identity-routed path and the credential-list path. The record decides
    /// the kind; a local one signs in the Secure Enclave exactly as before.
    private func completeAssertionRaw(rpId: String, credentialId: [UInt8], clientDataHash: Data) {
        guard let record = lookupRecord(rpId: rpId, credentialId: credentialId) else {
            extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
            return
        }

        if isSyncedRecord(record, credentialId: credentialId) {
            completeSyncedAssertion(rpId: rpId, credentialId: credentialId, clientDataHash: clientDataHash)
            return
        }

        guard let keyTag = record["keyTag"] as? String else {
            extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
            return
        }

        guard let privateKey = loadSecureEnclaveKey(keyTag: keyTag) else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }

        let authData = buildAssertionAuthData(rpId: rpId, flags: kFlagsLocalAssertion)

        // Sign: authData || clientDataHash
        var signInput = authData
        signInput.append(clientDataHash)

        guard let signature = signWithSecureEnclave(privateKey: privateKey, data: signInput) else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }

        finishAssertion(
            rpId: rpId,
            credentialId: credentialId,
            clientDataHash: clientDataHash,
            authData: authData,
            signature: signature
        )
    }

    /// A synced passkey signs with a key derived for this one signature,
    /// after the holder check the extension makes itself.
    private func completeSyncedAssertion(rpId: String, credentialId: [UInt8], clientDataHash: Data) {
        guard isSyncedCredentialId(credentialId) else {
            // A record that says synced but whose id has another shape cannot
            // be derived; refuse rather than guess.
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        let r = Array(credentialId[1...])

        authenticateHolder(reason: "Sign in to \(rpId)") { [weak self] verified in
            guard let self else { return }
            guard verified else {
                self.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
                return
            }
            guard var root = loadPasskeyRoot() else {
                self.extensionContext.cancelRequest(withError: ASExtensionError(.failed))
                return
            }
            defer { wipe(&root) }

            let authData = self.buildAssertionAuthData(rpId: rpId, flags: kFlagsSyncedAssertion)
            var signInput = authData
            signInput.append(clientDataHash)

            // CryptoKit hashes with SHA-256 and signs (ES256); WebAuthn wants
            // the signature DER encoded.
            guard let privateKey = try? syncedPrivateKey(root: root, r: r, rpId: rpId),
                  let signature = try? privateKey.signature(for: signInput).derRepresentation else {
                self.extensionContext.cancelRequest(withError: ASExtensionError(.failed))
                return
            }

            self.finishAssertion(
                rpId: rpId,
                credentialId: credentialId,
                clientDataHash: clientDataHash,
                authData: authData,
                signature: signature
            )
        }
    }

    /// Authenticator data for an assertion: no attested credential data.
    /// signCount is always 0: neither kind keeps a counter.
    private func buildAssertionAuthData(rpId: String, flags: UInt8) -> Data {
        let rpIdHash = SHA256.hash(data: Data(rpId.utf8))
        var authData = Data()
        authData.append(contentsOf: rpIdHash)
        authData.append(flags)
        authData.append(contentsOf: [0, 0, 0, 0] as [UInt8])
        return authData
    }

    private func finishAssertion(
        rpId: String,
        credentialId: [UInt8],
        clientDataHash: Data,
        authData: Data,
        signature: Data
    ) {
        let userHandle = lookupUserHandle(rpId: rpId, credentialId: credentialId)

        let credential = ASPasskeyAssertionCredential(
            userHandle: userHandle,
            relyingParty: rpId,
            signature: signature,
            clientDataHash: clientDataHash,
            authenticatorData: authData,
            credentialID: Data(credentialId)
        )

        extensionContext.completeAssertionRequest(using: credential)
    }

    /// A record is synced when it says so. A record with no kind predates
    /// synced passkeys, but a 17-byte id starting 0x01 can only be a synced
    /// one (a local id is a 32-byte hash), so the id settles it.
    private func isSyncedRecord(_ record: [String: Any], credentialId: [UInt8]) -> Bool {
        if let kind = record["kind"] as? String {
            return kind == kKindSynced
        }
        return isSyncedCredentialId(credentialId)
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

    /// One record per passkey. A local record names its Secure Enclave key;
    /// a synced one has no key tag, its key is derived on use. createdAt is in
    /// milliseconds, as on Android, because synced records travel between the
    /// holder's devices; records from before this change hold seconds, and
    /// NativeKeysModule.listWebsitePasskeys tells the two apart.
    private func storeCredential(
        rpId: String,
        credentialId: [UInt8],
        keyTag: String?,
        kind: String,
        userName: String,
        userHandle: Data
    ) {
        var entry: [String: Any] = [
            "rpId": rpId,
            "credentialId": Data(credentialId).base64EncodedString(),
            "kind": kind,
            "userName": userName,
            "userHandle": userHandle.base64EncodedString(),
            "createdAt": Int64(Date().timeIntervalSince1970 * 1000)
        ]
        if let keyTag {
            entry["keyTag"] = keyTag
        }

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

    /// The stored record for one passkey, or nil when this device holds none.
    private func lookupRecord(rpId: String, credentialId: [UInt8]) -> [String: Any]? {
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

        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
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
