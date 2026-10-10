// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What the holder does with their phones: add one, revoke one, remove this one,
 * and make every identity safe after a phrase recovery. The building blocks are
 * in services/devices.ts; the IdP side in idp/internal/recovery/devices.go.
 *
 * Adding a phone (no phrase needed):
 *   1. the new phone opens a pairing slot at privasys.id and shows a QR code
 *      naming it and an X25519 key it just made;
 *   2. the old phone scans it, the holder confirms with Face ID, and the old
 *      phone puts into the slot, sealed to that key, what makes the new phone
 *      the same wallet: the seed, the data root, the recovery epochs, the
 *      registry, the profile, and a one-time ticket to add a passkey to the
 *      main account;
 *   3. both phones show the same six digits; the holder checks them on the new
 *      phone, which then registers its own passkey on the main account and on
 *      each identity (enrolment, which keeps the old phone's), and its own push
 *      targets.
 *
 * Revoking a phone: for each identity, one request signed by its recovery key
 * removes that phone's passkey and push target and moves the key to a new
 * epoch; then the main account, with this phone's session; then the registry
 * records the phone as revoked, with the new epoch, which the revoked phone
 * never receives.
 */

import * as Crypto from 'expo-crypto';

import { profileName } from '@/services/attributes';
import {
    MAX_DEVICES,
    deviceTagFor,
    emptyRegistry,
    ensureDevice,
    loadEpochs,
    mainAccountUserId,
    mergeRegistries,
    myDeviceTag,
    openTransfer,
    pairingCode,
    pairingKeys,
    revokeMessage,
    saveLocalRegistry,
    sealTransfer,
    signWith,
    storeRegistry,
    syncRegistry,
    type RecoveryEpoch,
    type Registry,
    type RegistryDevice,
    type RegistryIdentity,
} from '@/services/devices';
import { generateCanonicalDid, generateDid, ensureDeviceKey } from '@/services/did';
import { getDeviceLocale } from '@/services/device-locale';
import * as fido2 from '@/services/fido2';
import {
    IDP_HOST,
    deriveRecoveryKey,
    epochCandidates,
    identityChallenge,
    recoverIdentity,
    restoreIdentityIndex,
    serverIdOf,
} from '@/services/identities';
import { identitySealPub } from '@/services/notify-seal';
import { ensurePrivasysSession } from '@/services/privasys-id';
import { collectContents, restoreContents, type BackupContents } from '@/services/profile-backup';
import { ensureDataRoot, installDataRoot } from '@/services/sovereign';
import { registerPushTokenWithIdp } from '@/services/vault-approval-api';
import { getAmbientPushToken } from '@/hooks/useExpoPushToken';
import { useAuthStore } from '@/stores/auth';
import { useProfileStore } from '@/stores/profile';
import { base64urlToBytes, bytesToBase64url } from '@/utils/encoding';
import * as SecureStore from '@/utils/storage';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';
const PRIVASYS_ORIGIN = 'privasys.id';
const SESSION_TTL_MS = 25 * 60 * 1000;
const PAIRING_POLL_MS = 2000;

export class DeviceError extends Error {
    constructor(
        public readonly reason: 'limit' | 'expired' | 'used' | 'network' | 'not-ours' | 'no-seed',
        message: string,
    ) {
        super(message);
    }
}

/** What the old phone sends the new one. */
interface Transfer {
    v: 1;
    seed: string;
    dataRoot: string;
    epochs: RecoveryEpoch[];
    registry: Registry;
    contents: BackupContents;
    ticket: string;
    from: string;
}

async function idp<T>(path: string, init: RequestInit = {}): Promise<{ status: number; body: T | null }> {
    let res: Response;
    try {
        res = await fetch(`${IDP_BASE}${path}`, init);
    } catch (e: any) {
        throw new DeviceError('network', e?.message ?? 'privasys.id could not be reached');
    }
    let body: T | null = null;
    try {
        body = (await res.json()) as T;
    } catch {
        body = null;
    }
    return { status: res.status, body };
}

const json = (session?: string): HeadersInit => ({
    'Content-Type': 'application/json',
    ...(session ? { Authorization: `Bearer wallet:${session}` } : {}),
});

function aliasFor(rpId: string): string {
    const raw = Crypto.getRandomBytes(4);
    let hex = '';
    for (const b of raw) hex += b.toString(16).padStart(2, '0');
    return `fido2-${rpId}-${hex}`;
}

// ---------------------------------------------------------------- the old phone

/**
 * Send this wallet to a new phone whose QR code was scanned. Asks for Face ID
 * (the main account's session). Returns the six digits to show.
 */
export async function sendToNewPhone(link: { slot: string; key: string }): Promise<string> {
    const profile = useProfileStore.getState().profile;
    if (!profile?.pairwiseSeed) throw new DeviceError('no-seed', 'this wallet is not set up');
    const { sessionToken } = await ensurePrivasysSession();
    const reg = await syncRegistry(sessionToken);
    if (reg.devices.length >= MAX_DEVICES) {
        throw new DeviceError('limit', `you already have ${MAX_DEVICES} phones`);
    }
    const ticket = await idp<{ ticket?: string; error?: string }>('/devices/enrol-ticket', {
        method: 'POST',
        headers: json(sessionToken),
    });
    if (ticket.status !== 200 || !ticket.body?.ticket) {
        throw new DeviceError('network', ticket.body?.error ?? `could not prepare the new phone (HTTP ${ticket.status})`);
    }
    const me = await ensureDevice();
    const payload: Transfer = {
        v: 1,
        seed: profile.pairwiseSeed,
        dataRoot: bytesToBase64url(await ensureDataRoot()),
        epochs: await loadEpochs(),
        registry: reg,
        contents: await collectContents(),
        ticket: ticket.body.ticket,
        from: me.name,
    };
    const { senderPub, blob } = sealTransfer(link.key, payload);
    const put = await idp<{ error?: string }>(`/devices/pair/${encodeURIComponent(link.slot)}`, {
        method: 'PUT',
        headers: json(sessionToken),
        body: JSON.stringify({ sender_public_key: senderPub, blob }),
    });
    if (put.status === 404) throw new DeviceError('expired', 'the code on the new phone has expired');
    if (put.status === 409) throw new DeviceError('used', 'that code was already used');
    if (put.status !== 200) throw new DeviceError('network', put.body?.error ?? `could not send (HTTP ${put.status})`);
    return pairingCode(link.key, senderPub);
}

// ---------------------------------------------------------------- the new phone

export interface PairingSession {
    slot: string;
    publicKey: string;
    secretKey: Uint8Array;
    expiresAt: number;
}

/** Open a slot and make the key the QR code carries. */
export async function openPairing(): Promise<PairingSession> {
    const keys = pairingKeys();
    const publicKey = bytesToBase64url(keys.publicKey);
    const res = await idp<{ slot?: string; expires_in?: number; error?: string }>('/devices/pair', {
        method: 'POST',
        headers: json(),
        body: JSON.stringify({ public_key: publicKey }),
    });
    if (res.status !== 200 || !res.body?.slot) {
        throw new DeviceError('network', res.body?.error ?? `could not start (HTTP ${res.status})`);
    }
    return {
        slot: res.body.slot,
        publicKey,
        secretKey: keys.secretKey,
        expiresAt: Date.now() + (res.body.expires_in ?? 600) * 1000,
    };
}

export interface ReceivedTransfer {
    code: string;
    from: string;
    payload: Transfer;
}

/** Wait for the old phone. Resolves with what it sent, or rejects on expiry or abort. */
export async function waitForTransfer(p: PairingSession, signal?: { aborted: boolean }): Promise<ReceivedTransfer> {
    while (!signal?.aborted) {
        if (Date.now() > p.expiresAt) break;
        const res = await idp<{ sender_public_key?: string; blob?: string }>(`/devices/pair/${encodeURIComponent(p.slot)}`);
        if (res.status === 200 && res.body?.sender_public_key && res.body.blob) {
            let payload: Transfer;
            try {
                payload = openTransfer<Transfer>(p.secretKey, res.body.sender_public_key, res.body.blob);
            } catch {
                throw new DeviceError('not-ours', 'what arrived does not open with this phone’s key');
            }
            if (payload?.v !== 1 || !payload.seed || !payload.dataRoot || !payload.ticket) {
                throw new DeviceError('not-ours', 'what arrived is not a Privasys Wallet');
            }
            return { code: pairingCode(p.publicKey, res.body.sender_public_key), from: payload.from, payload };
        }
        if (res.status === 404) break;
        await new Promise((r) => setTimeout(r, PAIRING_POLL_MS));
    }
    throw new DeviceError('expired', 'the code expired before the other phone sent anything');
}

export interface InstallProgress {
    identities: number;
    done: number;
    failed: number;
}

/**
 * Make this phone the holder's wallet, once they have checked the six digits.
 * Registers this phone's passkey on the main account and on every identity.
 */
export async function installTransfer(
    received: ReceivedTransfer,
    onProgress?: (p: InstallProgress) => void,
): Promise<InstallProgress> {
    const t = received.payload;
    const profiles = useProfileStore.getState();
    if (profiles.profile) throw new DeviceError('not-ours', 'this phone already has a wallet');

    // 1. The same wallet: seed, data root, epochs and registry, then the profile.
    await ensureDeviceKey();
    const did = await generateDid();
    profiles.createProfile({
        displayName: '',
        email: '',
        avatarUri: '',
        locale: getDeviceLocale(),
        did,
        canonicalDid: await generateCanonicalDid(t.seed),
        pairwiseSeed: t.seed,
        linkedProviders: [],
        attributes: [],
    });
    await installDataRoot(base64urlToBytes(t.dataRoot));
    await saveLocalRegistry(mergeRegistries(t.registry, { ...emptyRegistry(), epochs: t.epochs }));
    await restoreContents(t.contents);
    await ensureDevice();

    // 2. A passkey on the main account, with the old phone's ticket.
    const redeemed = await idp<{ user_id?: string; error?: string }>('/devices/enrol', {
        method: 'POST',
        headers: json(),
        body: JSON.stringify({ ticket: t.ticket }),
    });
    if (redeemed.status !== 200 || !redeemed.body?.user_id) {
        throw new DeviceError('expired', redeemed.body?.error ?? 'the other phone’s permission has expired');
    }
    const keyAlias = `privasys-id-account-${aliasFor('x').slice(-8)}`;
    const name = profileName(useProfileStore.getState().profile) ?? 'Privasys Wallet';
    const main = await fido2.register(PRIVASYS_ORIGIN, keyAlias, '', name, redeemed.body.user_id, undefined, { clientPhrase: true });
    if (!main.sessionToken) throw new DeviceError('network', 'privasys.id did not open a session');
    const auth = useAuthStore.getState();
    auth.setPrivasysId({
        userId: main.userId || redeemed.body.user_id,
        credentialId: main.credentialId,
        keyAlias,
        sessionToken: main.sessionToken,
        sessionExpiresAt: Date.now() + SESSION_TTL_MS,
    });
    // The account's phrase was made, and kept, on the other phone.
    auth.setRecoveryPhraseSaved(true);
    auth.setOnboarded();
    await registerPush(main.sessionToken, main.userId || redeemed.body.user_id);

    // 3. This phone in the registry, then a passkey on every identity.
    await restoreIdentityIndex(main.sessionToken);
    const reg = await syncRegistry(main.sessionToken);
    const targets = reg.identities.filter((i) => i.rpId);
    const progress: InstallProgress = { identities: targets.length, done: 0, failed: 0 };
    onProgress?.(progress);
    for (const entry of targets) {
        try {
            await claimIdentity(entry, 'enrol');
            progress.done++;
        } catch (e: any) {
            // It comes back at its next sign-in instead (connect enrols).
            console.warn('[devices] identity not added now:', e?.message ?? e);
            progress.failed++;
        }
        onProgress?.({ ...progress });
    }
    return progress;
}

async function registerPush(session: string, userId: string): Promise<void> {
    const token = getAmbientPushToken();
    if (!token) return;
    try {
        await registerPushTokenWithIdp(session, token, identitySealPub(userId), userId);
    } catch (e: any) {
        console.warn('[devices] push registration failed:', e?.message ?? e);
    }
}

/**
 * Put a passkey of this phone on one identity: prove it is the holder's
 * ('enrol' keeps the other phones' passkeys, 'recover' removes them), register,
 * and register this phone's push target.
 */
export async function claimIdentity(entry: RegistryIdentity, mode: 'enrol' | 'recover'): Promise<void> {
    await recoverIdentity(entry.userHandle, mode, entry.rpId);
    const keyAlias = aliasFor(entry.rpId);
    const name = profileName(useProfileStore.getState().profile) ?? entry.rpId;
    const r = await fido2.register(IDP_HOST, keyAlias, '', name, entry.userHandle, undefined, { clientPhrase: true });
    useAuthStore.getState().addCredential({
        credentialId: r.credentialId,
        rpId: entry.rpId,
        origin: IDP_HOST,
        keyAlias,
        userHandle: r.userHandle,
        userName: r.userName,
        registeredAt: Math.floor(Date.now() / 1000),
        serverRpId: r.serverRpId,
    });
    if (r.sessionToken) await registerPush(r.sessionToken, r.userId || entry.userHandle);
}

// ---------------------------------------------------------------- revoking

export interface RevokeOutcome {
    identities: number;
    failed: number;
}

/** This phone's passkey on an identity, if it has one. */
function myCredentialOn(userHandle: string): string {
    const c = useAuthStore.getState().credentials.find((x) => x.origin === IDP_HOST && serverIdOf(x) === userHandle);
    return c?.credentialId ?? '';
}

/**
 * Remove phones from every identity, and move every identity to a new epoch.
 * `tagsFor` names the phones to remove on one identity ('*': every phone but
 * this one's passkey). Updates the registry's epochs as identities move.
 */
async function revokeEverywhere(
    reg: Registry,
    tagsFor: (userHandle: string) => string[],
    keepMine: boolean,
    onProgress?: (p: InstallProgress) => void,
): Promise<{ reg: Registry; failed: number }> {
    const seed = useProfileStore.getState().profile?.pairwiseSeed;
    if (!seed) throw new DeviceError('no-seed', 'this wallet is not set up');
    const next: RecoveryEpoch = {
        n: Math.max(0, ...reg.epochs.map((e) => e.n)) + 1,
        secret: bytesToBase64url(new Uint8Array(Crypto.getRandomBytes(32))),
    };
    // The new epoch is kept before any identity moves, so a crash halfway
    // leaves keys this phone can still derive.
    let working = mergeRegistries(reg, { ...emptyRegistry(), epochs: [next] });
    await saveLocalRegistry(working);
    let failed = 0;
    const progress: InstallProgress = { identities: working.identities.length, done: 0, failed: 0 };
    for (const entry of working.identities) {
        try {
            const keep = keepMine ? myCredentialOn(entry.userHandle) : '';
            let moved = false;
            for (const [i, tag] of tagsFor(entry.userHandle).entries()) {
                // The first request moves the key; the rest are signed by the new one.
                const candidates = i === 0 ? await epochCandidates(entry.userHandle) : [next];
                let ok = false;
                for (const epoch of candidates) {
                    const challengeB64 = await identityChallenge(entry.userHandle);
                    const { secretKey } = deriveRecoveryKey(seed, entry.userHandle, epoch);
                    const newPub = i === 0 ? bytesToBase64url(deriveRecoveryKey(seed, entry.userHandle, next).publicKey) : '';
                    const res = await idp<{ error?: string }>('/recovery/identity/revoke-device', {
                        method: 'POST',
                        headers: json(),
                        body: JSON.stringify({
                            user_id: entry.userHandle,
                            device_tag: tag,
                            keep_credential_id: keep,
                            new_public_key: newPub,
                            challenge: challengeB64,
                            signature: signWith(secretKey, revokeMessage(entry.userHandle, base64urlToBytes(challengeB64), tag, newPub)),
                        }),
                    });
                    if (res.status === 200) {
                        ok = true;
                        break;
                    }
                    if (res.status !== 403) throw new Error(res.body?.error ?? `HTTP ${res.status}`);
                }
                if (!ok) throw new Error('no recovery key of this wallet opens this identity');
                if (i === 0) moved = true;
            }
            if (moved) {
                working = mergeRegistries(working, { ...emptyRegistry(), identities: [{ ...entry, epoch: next.n }] });
                await saveLocalRegistry(working);
            }
            progress.done++;
        } catch (e: any) {
            console.warn('[devices] an identity was not moved:', e?.message ?? e);
            failed++;
            progress.failed++;
        }
        onProgress?.({ ...progress });
    }
    return { reg: working, failed };
}

/** Revoke another phone of the holder. Asks for Face ID. */
export async function revokeDevice(target: RegistryDevice, onProgress?: (p: InstallProgress) => void): Promise<RevokeOutcome> {
    const me = await ensureDevice();
    if (target.id === me.id) throw new DeviceError('not-ours', 'use Remove this phone');
    const { sessionToken, userId } = await ensurePrivasysSession();
    const reg = await syncRegistry(sessionToken);
    const { reg: moved, failed } = await revokeEverywhere(reg, (h) => [deviceTagFor(target.secret, h)], true, onProgress);

    // The main account: the session's own passkey is always kept.
    const mainRes = await idp<{ error?: string }>('/devices/revoke', {
        method: 'POST',
        headers: json(sessionToken),
        body: JSON.stringify({ device_tag: deviceTagFor(target.secret, mainAccountUserId(userId)) }),
    });
    if (mainRes.status !== 200) throw new DeviceError('network', mainRes.body?.error ?? `HTTP ${mainRes.status}`);

    // A phone some identity still lets in stays listed, so the holder can try again.
    await storeRegistry(
        sessionToken,
        failed > 0 ? moved : { ...moved, revoked: [...moved.revoked, target.id], devices: moved.devices.filter((d) => d.id !== target.id) },
    );
    return { identities: moved.identities.length, failed };
}

/**
 * Take this phone off the holder's account: its passkeys and push targets on
 * every identity and on the main account. The caller then clears the wallet.
 * The other phones keep everything, so no epoch moves: a phone leaving of its
 * own accord is not one the holder lost.
 */
export async function removeThisPhone(): Promise<void> {
    const me = await ensureDevice();
    const { sessionToken } = await ensurePrivasysSession();
    const reg = await syncRegistry(sessionToken);
    const seed = useProfileStore.getState().profile?.pairwiseSeed;
    if (!seed) throw new DeviceError('no-seed', 'this wallet is not set up');
    for (const entry of reg.identities) {
        try {
            for (const epoch of await epochCandidates(entry.userHandle)) {
                const challengeB64 = await identityChallenge(entry.userHandle);
                const tag = deviceTagFor(me.secret, entry.userHandle);
                const res = await idp<{ error?: string }>('/recovery/identity/revoke-device', {
                    method: 'POST',
                    headers: json(),
                    body: JSON.stringify({
                        user_id: entry.userHandle,
                        device_tag: tag,
                        keep_credential_id: '*',
                        new_public_key: '',
                        challenge: challengeB64,
                        signature: signWith(
                            deriveRecoveryKey(seed, entry.userHandle, epoch).secretKey,
                            revokeMessage(entry.userHandle, base64urlToBytes(challengeB64), tag, ''),
                        ),
                    }),
                });
                if (res.status !== 403) break;
            }
        } catch (e: any) {
            console.warn('[devices] could not leave an identity:', e?.message ?? e);
        }
    }
    const own = useAuthStore.getState().privasysId?.credentialId;
    await storeRegistry(sessionToken, { ...reg, revoked: [...reg.revoked, me.id], devices: reg.devices.filter((d) => d.id !== me.id) });
    if (own) {
        await idp(`/devices?credential_id=${encodeURIComponent(own)}`, { method: 'DELETE', headers: json(sessionToken) });
    }
}

/**
 * After a phrase recovery: this phone is now the holder's only one. Every other
 * phone in the registry is revoked, every identity moves to a new epoch, and
 * this phone takes a passkey on each, so a lost phone is shut out of all of
 * them at once instead of one at a time as the holder signs in. The registry
 * must have been restored already (restoreIdentityIndex).
 */
export async function secureAfterRecovery(onProgress?: (p: InstallProgress) => void): Promise<RevokeOutcome> {
    const me = await ensureDevice();
    const { sessionToken } = await ensurePrivasysSession();
    const reg = await syncRegistry(sessionToken);
    const others = reg.devices.filter((d) => d.id !== me.id);
    const { reg: moved, failed } = await revokeEverywhere(reg, () => ['*'], false, onProgress);
    await storeRegistry(sessionToken, {
        ...moved,
        revoked: [...moved.revoked, ...others.map((d) => d.id)],
        devices: moved.devices.filter((d) => d.id === me.id),
    });
    let claimFailed = 0;
    for (const entry of moved.identities.filter((i) => i.rpId && !myCredentialOn(i.userHandle))) {
        try {
            await claimIdentity(entry, 'enrol');
        } catch (e: any) {
            console.warn('[devices] identity not taken now:', e?.message ?? e);
            claimFailed++;
        }
    }
    return { identities: moved.identities.length, failed: failed + claimFailed };
}

/** For the Devices screen: this phone's tag on the main account, to tell rows apart in logs. */
export async function thisPhoneMainTag(): Promise<string | null> {
    const account = useAuthStore.getState().privasysId;
    return account ? myDeviceTag(mainAccountUserId(account.userId)) : null;
}

const SECURE_PENDING_KEY = 'privasys.devices.secure-pending';

/** A phrase recovery happened before this phone had a profile: secure once it does. */
export async function markSecurePending(): Promise<void> {
    await SecureStore.setItemAsync(SECURE_PENDING_KEY, '1');
}

/**
 * Run the after-recovery securing now if a recovery asked for it and the
 * profile exists. Best effort: an identity left over comes back by enrolment at
 * its next sign-in.
 */
export async function runPendingSecure(): Promise<RevokeOutcome | null> {
    if ((await SecureStore.getItemAsync(SECURE_PENDING_KEY)) !== '1') return null;
    if (!useProfileStore.getState().profile?.pairwiseSeed) return null;
    try {
        const r = await secureAfterRecovery();
        await SecureStore.deleteItemAsync(SECURE_PENDING_KEY);
        return r;
    } catch (e: any) {
        console.warn('[devices] securing after recovery failed; will retry:', e?.message ?? e);
        return null;
    }
}

/** Part of Clear All Data. */
export async function clearDeviceFlowsLocalState(): Promise<void> {
    await SecureStore.deleteItemAsync(SECURE_PENDING_KEY);
}
