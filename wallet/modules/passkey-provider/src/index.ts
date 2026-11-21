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
 * attested; any other website gets a plain approval. Website passkeys are made
 * in the secure chip and stay on this device only: they are not derived from
 * the seed, so a new device makes its own on each website.
 */

export { default as withPasskeyProvider } from './plugin';
