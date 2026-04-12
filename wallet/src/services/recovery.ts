// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Account recovery — restore wallet identity after device loss or reinstall.
 *
 * Flow:
 * 1. User links a previously-used identity provider
 * 2. Provider's subject ID is used to prove continuity of identity
 * 3. New hardware key is generated on the new device
 * 4. New DID is derived from the new hardware key
 * 5. Profile is recreated from provider-seeded data
 * 6. FIDO2 credentials must be re-registered with each enclave app
 *
 * This does NOT recover the old private key — keys never leave the device's
 * secure hardware. Instead, recovery establishes a new cryptographic identity
 * that is provably linked to the same user via the external IdP.
 */

import * as NativeKeys from '../../modules/native-keys/src/index';

import { generateDid, generatePairwiseSeed, generateCanonicalDid } from '@/services/did';
import { linkIdentityProvider, type ProviderConfig, PROVIDERS } from '@/services/identity';
import { useProfileStore } from '@/stores/profile';

export interface RecoveryResult {
    /** Whether recovery succeeded. */
    success: boolean;
    /** The new DID on this device. */
    did: string;
    /** Display name recovered from provider. */
    displayName: string;
    /** Email recovered from provider. */
    email: string;
    /** Description of what was recovered. */
    summary: string;
}

/**
 * Execute the full account recovery flow:
 * 1. Generate a new hardware key
 * 2. Link the chosen provider
 * 3. Seed profile from provider data
 * 4. Generate DID from new key
 * 5. Create profile
 */
export async function recoverAccount(
    providerKey: string,
    clientId: string
): Promise<RecoveryResult> {
    const providerTemplate = PROVIDERS[providerKey];
    if (!providerTemplate) {
        throw new Error(`Unknown provider: ${providerKey}`);
    }

    // Step 1: Generate new hardware key
    const keyInfo = await NativeKeys.generateKey('privasys-wallet-default', true);
    if (!keyInfo.hardwareBacked) {
        console.warn('Recovery: key is not hardware-backed');
    }

    // Step 2: Link provider to verify identity
    const config: ProviderConfig = { ...providerTemplate, clientId };
    const linkResult = await linkIdentityProvider(config);

    // Step 3: Generate DID from new key
    const did = await generateDid();

    // Step 3b: Generate pairwise seed and canonical DID
    // TODO: In production, restore the pairwise seed from privasys.id enclave
    // using the linked provider's sub as an anchor. For now, generate a new one.
    const pairwiseSeed = await generatePairwiseSeed();
    const canonicalDid = await generateCanonicalDid(pairwiseSeed);

    // Step 4: Create profile from provider data
    const displayName = linkResult.userInfo.name || 'Recovered User';
    const email = linkResult.userInfo.email || '';
    const avatarUri = linkResult.userInfo.picture || '';

    useProfileStore.getState().createProfile({
        displayName,
        email,
        avatarUri,
        locale: '',
        did,
        canonicalDid,
        pairwiseSeed,
        linkedProviders: [linkResult.provider],
        attributes: linkResult.seedAttributes
    });

    return {
        success: true,
        did,
        displayName,
        email,
        summary: `Identity recovered via ${providerTemplate.displayName}. A new device key and DID have been created. You'll need to re-register with any previously connected enclave services.`
    };
}
