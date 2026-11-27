// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Passkey Provider — Expo config plugin that registers the wallet as a
 * system-level passkey provider (FIDO2 credential provider).
 *
 * iOS: Adds an ASCredentialProviderExtension target to the Xcode project.
 * Android: Registers a CredentialProviderService in AndroidManifest.xml.
 *
 * The extension/service answers passkey requests from browsers and apps for
 * any website, not only Privasys apps. When the relying party is a Privasys
 * enclave it verifies its attestation over RA-TLS first and shows what was
 * attested; any other website gets a plain approval. A website passkey is
 * either kept in this device's secure chip, or derived from the seed so the
 * holder's other devices derive the same one (see the wallet's
 * src/services/website-passkeys.ts).
 */

export { default as withPasskeyProvider } from './plugin';
