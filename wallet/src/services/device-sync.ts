// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Keeping the holder's phones in step: a change to the profile on one phone
 * reaches the others through the relay at privasys.id, which holds nothing.
 *
 * - A message is sealed under a key every phone of the holder derives from the
 *   shared data root, so privasys.id carries ciphertext for at most fifteen
 *   minutes and keeps none of it:
 *
 *     key = HKDF-SHA256(root, info = "privasys-device-relay/v1", 32)
 *
 * - Each phone reads at its own address (services/devices.ts relayAddressFor),
 *   and is woken by a silent push when something is sent to it.
 * - The sender keeps the newest profile message in an outbox, with the phones
 *   that have not confirmed it, and sends it again whenever it is opened until
 *   each has. A phone that was away asks the others for their profile when it
 *   comes back.
 * - The newest profile wins as a whole (details, linked providers); the
 *   identity-check records are added, never replaced.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as Crypto from 'expo-crypto';

import { deviceTagFor, ensureDevice, localRegistry, mainAccountUserId, relayAddressFor, type RegistryDevice } from '@/services/devices';
import { loadKycRecords, saveKycRecord, type KycRecord } from '@/services/kyc';
import { peekDataRoot } from '@/services/sovereign';
import { useAuthStore } from '@/stores/auth';
import { useProfileStore, type UserProfile } from '@/stores/profile';
import { base64urlToBytes, bytesToBase64url } from '@/utils/encoding';
import * as SecureStore from '@/utils/storage';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';
const KEY_INFO = 'privasys-device-relay/v1';
const AAD = 'privasys-device-relay';
const OUTBOX_KEY = 'privasys.devices.outbox';
const SEEN_KEY = 'privasys.devices.seen';

const utf8 = (s: string) => new TextEncoder().encode(s);

type SyncedProfile = Omit<UserProfile, 'pairwiseSeed' | 'did'>;

export type RelayMessage =
    | { kind: 'profile'; id: string; from: string; at: number; profile: SyncedProfile; kycRecords: KycRecord[] }
    | { kind: 'ack'; id: string; from: string }
    | { kind: 'sync-request'; id: string; from: string };

interface Outbox {
    message: RelayMessage | null;
    /** Device ids that have not confirmed it. */
    pending: string[];
}

function relayKey(root: Uint8Array): Uint8Array {
    return hkdf(sha256, root, undefined, utf8(KEY_INFO), 32);
}

/** Seal a message. Exported for tests. */
export function sealMessage(root: Uint8Array, m: RelayMessage): string {
    const nonce = new Uint8Array(Crypto.getRandomBytes(24));
    const ct = xchacha20poly1305(relayKey(root), nonce, utf8(AAD)).encrypt(utf8(JSON.stringify(m)));
    const out = new Uint8Array(24 + ct.length);
    out.set(nonce, 0);
    out.set(ct, 24);
    return bytesToBase64url(out);
}

/** Open a message, or null. Exported for tests. */
export function openMessage(root: Uint8Array, blob: string): RelayMessage | null {
    try {
        const raw = base64urlToBytes(blob);
        const pt = xchacha20poly1305(relayKey(root), raw.slice(0, 24), utf8(AAD)).decrypt(raw.slice(24));
        const m = JSON.parse(new TextDecoder().decode(pt)) as RelayMessage;
        return m && typeof m.kind === 'string' && typeof m.from === 'string' ? m : null;
    } catch {
        return null;
    }
}

async function readJson<T>(key: string, fallback: T): Promise<T> {
    try {
        const raw = await SecureStore.getItemAsync(key);
        return raw ? (JSON.parse(raw) as T) : fallback;
    } catch {
        return fallback;
    }
}

function newId(): string {
    return bytesToBase64url(new Uint8Array(Crypto.getRandomBytes(12)));
}

async function otherDevices(): Promise<RegistryDevice[]> {
    const me = await ensureDevice();
    return (await localRegistry()).devices.filter((d) => d.id !== me.id);
}

function account(): string | null {
    const a = useAuthStore.getState().privasysId;
    return a ? mainAccountUserId(a.userId) : null;
}

async function post(root: Uint8Array, to: RegistryDevice[], m: RelayMessage): Promise<void> {
    if (!to.length) return;
    const acct = account();
    const blob = sealMessage(root, m);
    const res = await fetch(`${IDP_BASE}/devices/relay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            items: to.map((d) => ({
                to: relayAddressFor(d.secret),
                blob,
                ...(acct ? { wake: { account: acct, tag: deviceTagFor(d.secret, acct) } } : {}),
            })),
        }),
    });
    if (!res.ok) throw new Error(`relay refused the update (HTTP ${res.status})`);
}

/** Messages applied by this phone, so a resend is not applied twice. */
async function seen(): Promise<Record<string, number>> {
    return readJson<Record<string, number>>(SEEN_KEY, {});
}

// ---------------------------------------------------------------- sending

let applying = false;

/** Send this phone's profile to the holder's other phones, and keep it until each confirms. */
export async function sendProfile(): Promise<void> {
    const profile = useProfileStore.getState().profile;
    const root = await peekDataRoot();
    const to = await otherDevices();
    if (!profile || !root || !to.length) return;
    const { pairwiseSeed: _s, did: _d, ...rest } = profile;
    const me = await ensureDevice();
    const message: RelayMessage = {
        kind: 'profile',
        id: newId(),
        from: me.id,
        at: profile.updatedAt,
        profile: rest,
        kycRecords: await loadKycRecords(),
    };
    await SecureStore.setItemAsync(OUTBOX_KEY, JSON.stringify({ message, pending: to.map((d) => d.id) } satisfies Outbox));
    await post(root, to, message);
}

/** Send again whatever another phone has not confirmed. */
async function resendOutbox(root: Uint8Array): Promise<void> {
    const box = await readJson<Outbox>(OUTBOX_KEY, { message: null, pending: [] });
    if (!box.message || !box.pending.length) return;
    const live = (await otherDevices()).filter((d) => box.pending.includes(d.id));
    if (!live.length) {
        await SecureStore.deleteItemAsync(OUTBOX_KEY);
        return;
    }
    await post(root, live, box.message);
}

// ---------------------------------------------------------------- receiving

/**
 * Read what the holder's other phones sent, apply it, confirm it, and send
 * again what they have not confirmed. Called when the wallet comes to the
 * foreground and when a silent push wakes it.
 */
export async function pullRelay(): Promise<number> {
    const root = await peekDataRoot();
    if (!root || !useProfileStore.getState().profile) return 0;
    const me = await ensureDevice();
    const res = await fetch(`${IDP_BASE}/devices/relay?to=${encodeURIComponent(relayAddressFor(me.secret))}`);
    if (!res.ok) return 0;
    const { items } = (await res.json()) as { items: string[] };
    const others = await otherDevices();
    const byId = new Map(others.map((d) => [d.id, d]));
    const applied = await seen();
    let changed = 0;
    for (const blob of items ?? []) {
        const m = openMessage(root, blob);
        if (!m || m.from === me.id || !byId.has(m.from)) continue;
        const sender = byId.get(m.from) as RegistryDevice;
        if (m.kind === 'ack') {
            const box = await readJson<Outbox>(OUTBOX_KEY, { message: null, pending: [] });
            if (box.message?.id === m.id) {
                box.pending = box.pending.filter((id) => id !== m.from);
                await SecureStore.setItemAsync(OUTBOX_KEY, JSON.stringify(box));
            }
        } else if (m.kind === 'sync-request') {
            await sendProfile();
        } else if (m.kind === 'profile') {
            if (!applied[m.id]) {
                await applyProfile(m);
                applied[m.id] = Math.floor(Date.now() / 1000);
                changed++;
            }
            await post(root, [sender], { kind: 'ack', id: m.id, from: me.id });
        }
    }
    // Keep the last hundred, which covers any resend.
    const trimmed = Object.fromEntries(Object.entries(applied).sort((a, b) => b[1] - a[1]).slice(0, 100));
    await SecureStore.setItemAsync(SEEN_KEY, JSON.stringify(trimmed));
    await resendOutbox(root);
    return changed;
}

async function applyProfile(m: Extract<RelayMessage, { kind: 'profile' }>): Promise<void> {
    const store = useProfileStore.getState();
    if (!store.profile) return;
    applying = true;
    try {
        if (m.at > store.profile.updatedAt) store.applySyncedProfile(m.profile);
        const held = new Set((await loadKycRecords()).map((r) => r.jti));
        for (const r of m.kycRecords ?? []) if (!held.has(r.jti)) await saveKycRecord(r);
    } finally {
        applying = false;
    }
}

/** A phone back after a while asks the others for their profile. */
export async function requestSync(): Promise<void> {
    const root = await peekDataRoot();
    const to = await otherDevices();
    if (!root || !to.length) return;
    await post(root, to, { kind: 'sync-request', id: newId(), from: (await ensureDevice()).id });
}

let watching = false;

/** Send the profile a few seconds after it last changed on this phone. Called once at start-up. */
export function watchProfileForDevices(): void {
    if (watching) return;
    watching = true;
    let timer: ReturnType<typeof setTimeout> | null = null;
    useProfileStore.subscribe((state, prev) => {
        if (!state.profile || state.profile === prev.profile || applying || !prev.profile) return;
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => {
            void sendProfile().catch((e: any) => console.warn('[device-sync] send failed:', e?.message ?? e));
        }, 5000);
    });
}

/** Part of Clear All Data. */
export async function clearDeviceSyncLocalState(): Promise<void> {
    await SecureStore.deleteItemAsync(OUTBOX_KEY);
    await SecureStore.deleteItemAsync(SEEN_KEY);
}
