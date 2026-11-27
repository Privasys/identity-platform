// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Attribute proofs: what the Privasys Attribute Verifier signed about the
 * holder's attributes, kept on the attribute's verification record
 * (stores/profile VerificationRecord).
 *
 * - At import, the provider's raw token goes to the verifier, and each proof it
 *   returns is attached to the attribute with the same key and value.
 * - Proofs sync to the holder's other devices bound to the device that made
 *   them. A device rebinds one to itself only when it is about to disclose it,
 *   inside a sign-in the holder is already confirming: rebinding in the
 *   background would raise a biometric prompt out of nowhere, since the device
 *   key that signs every call asks for one.
 *
 * Failing to reach the verifier never fails an import: the attribute is kept as
 * before, without a proof, and can be checked again later.
 */

import { sha256 } from '@noble/hashes/sha2.js';

import { attest, disclose, type AttestKind, type AttributeProof } from '@/services/attribute-verifier';
import { useProfileStore, type ProfileAttribute, type VerificationRecord } from '@/stores/profile';
import { isDisclosableProof } from '@/services/attribute-verified';
import { base64urlToBytes, bytesToBase64url } from '@/utils/encoding';

import * as NativeKeys from '../../modules/native-keys/src/index';

const DEVICE_KEY_ID = 'privasys-wallet-default';

/** The providers the verifier checks a signed ID token for. */
const OIDC_PROVIDERS = new Set(['google', 'microsoft', 'linkedin']);

/** This device's binding: base64url(SHA-256(SEC1 device key)), as the verifier writes it. */
export async function thisDeviceBinding(): Promise<string> {
    const info = await NativeKeys.getPublicKey(DEVICE_KEY_ID);
    return bytesToBase64url(sha256(base64urlToBytes(info.publicKey)));
}

/** An attribute value as the verifier compares it: strings as they are, objects as JSON. */
function sameValue(proofValue: unknown, value: string): boolean {
    if (typeof proofValue === 'string') return proofValue.trim().toLowerCase() === value.trim().toLowerCase();
    try {
        return JSON.stringify(proofValue) === JSON.stringify(JSON.parse(value));
    } catch {
        return false;
    }
}

/**
 * The material a provider link returns, as the verifier takes it: the signed ID
 * token for an OIDC provider, GitHub's access token. Used once, for the proof,
 * and never kept. Null when there is nothing to check.
 */
export function linkMaterial(
    provider: string,
    idToken?: string,
    accessToken?: string,
): { kind: AttestKind; data: Record<string, unknown> } | null {
    if (OIDC_PROVIDERS.has(provider) && idToken) return { kind: 'oidc_id_token', data: { provider, id_token: idToken } };
    if (provider === 'github' && accessToken) return { kind: 'github', data: { access_token: accessToken } };
    return null;
}

/**
 * Have the verifier check a provider link's material and attach each proof it
 * signs to the matching attribute (same key, same value). Returns how many
 * attributes got a proof; 0 when the verifier could not be reached.
 */
export async function attachLinkProofs(
    attributes: ProfileAttribute[],
    material: { kind: AttestKind; data: Record<string, unknown> },
    salt: string,
    displayName: string,
): Promise<number> {
    let proofs: AttributeProof[];
    try {
        proofs = await attest(material.kind, material.data, salt);
    } catch (e: any) {
        console.warn('[attribute-proofs] the verifier did not check this link:', e?.message ?? e);
        return 0;
    }
    const device = await thisDeviceBinding();
    const now = Math.floor(Date.now() / 1000);
    let attached = 0;
    for (const p of proofs) {
        const attr = attributes.find((a) => a.key === p.attr && sameValue(p.value, a.value));
        if (!attr) continue;
        const record: VerificationRecord = {
            verifier: p.source,
            verifierDisplayName: displayName,
            method: 'oidc_claim',
            // Only a proven value is verified for apps; an observed one (what
            // a provider's API said, unsigned) is shown to the holder only.
            assurance: p.method === 'proven' ? 'provider' : 'none',
            verifiedAt: now,
            proof: p.proof,
            proofDevice: device,
            proofSalt: salt,
        };
        // The proof replaces the provider's bare claim for the same verifier.
        attr.verifications = [...(attr.verifications ?? []).filter((v) => v.verifier !== p.source || v.proof), record];
        attached++;
    }
    return attached;
}

/** The record holding a proof for this attribute value, if any. */
export function proofRecordFor(key: string, value: string): VerificationRecord | undefined {
    const profile = useProfileStore.getState().profile;
    const attr = profile?.attributes.find((a) => a.key === key && a.value.toLowerCase() === value.toLowerCase());
    return attr?.verifications?.find(isDisclosableProof);
}

/**
 * The proof, bound to this device: rebound through the verifier first when it
 * was made on another of the holder's devices, and the rebound proof kept.
 */
async function proofForThisDevice(key: string, value: string, record: VerificationRecord): Promise<string> {
    const device = await thisDeviceBinding();
    if (record.proofDevice === device) return record.proof!;
    if (!record.proofSalt) throw new Error('attribute proof: no salt to rebind with');
    const [rebound] = await attest('proof', { proof: record.proof }, record.proofSalt);
    if (!rebound) throw new Error('attribute proof: the verifier did not rebind it');
    const store = useProfileStore.getState();
    const attr = store.profile?.attributes.find((a) => a.key === key && a.value.toLowerCase() === value.toLowerCase());
    if (attr) {
        store.updateAttributeValue(key, attr.value, {
            verifications: (attr.verifications ?? []).map((v) =>
                v.proof === record.proof ? { ...v, proof: rebound.proof, proofDevice: device } : v,
            ),
        });
    }
    return rebound.proof;
}

/**
 * A fresh disclosure of the proof for `key` = `value`, addressed to one app
 * (its client id), for privasys.id to relay inside the sign-in. Undefined when
 * there is no proof, or it could not be disclosed: the sign-in goes on, the
 * value is then simply not verified for that app.
 */
export async function disclosureFor(key: string, value: string, clientId: string, sub: string, nonce: string): Promise<string | undefined> {
    const record = proofRecordFor(key, value);
    if (!record?.proof) {
        // Said out loud: the value then reaches the app unverified, and a
        // silent miss here is what hid a dropped proof (2026-11-21).
        console.warn(`[attribute-proofs] no proof for ${key}: disclosed without one`);
        return undefined;
    }
    try {
        const proof = await proofForThisDevice(key, value, record);
        return await disclose(proof, clientId, sub, nonce);
    } catch (e: any) {
        console.warn(`[attribute-proofs] ${key} not disclosed:`, e?.message ?? e);
        return undefined;
    }
}

const SOURCE_NAMES: Record<string, string> = {
    google: 'Google',
    microsoft: 'Microsoft',
    linkedin: 'LinkedIn',
    github: 'GitHub',
};

/** A verifier source's name for people: a known provider, or an OIDC issuer's host. */
function sourceName(source: string): string {
    if (SOURCE_NAMES[source]) return SOURCE_NAMES[source];
    if (source.startsWith('oidc:')) {
        try {
            return new URL(source.slice(5)).host;
        } catch {
            return source.slice(5);
        }
    }
    return source;
}

/**
 * Who proved a value, for the line under it: the proof's source when it has
 * one ("Verified by Google", "Verified by email code", the card's bank).
 * Undefined when nothing proved it, so the screen falls back to where the
 * value came from. The card's bank, which needs the card's label, is the
 * caller's.
 */
export function provedBy(
    attr: ProfileAttribute,
    t: (key: string, opts?: Record<string, unknown>) => string,
): { kind: 'card' } | { kind: 'text'; text: string } | undefined {
    const rec = attr.verifications?.find((v) => v.proof);
    if (!rec) return undefined;
    if (rec.verifier === 'card_bank') return { kind: 'card' };
    if (rec.verifier === 'privasys_mail') return { kind: 'text', text: t('personalData.verifiedByMail') };
    if (rec.assurance !== 'provider') return { kind: 'text', text: t('personalData.fromProviderAccount', { provider: sourceName(rec.verifier) }) };
    return { kind: 'text', text: t('personalData.verifiedByProvider', { provider: sourceName(rec.verifier) }) };
}
