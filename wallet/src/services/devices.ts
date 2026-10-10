// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * One holder, several phones.
 *
 * Every phone of a holder holds the same seed and data root, so the same
 * identities and the same encrypted data, and its own passkey on each identity.
 * A phone is:
 *
 *   - an id, a name the holder sees, and a secret that never leaves the holder's
 *     phones;
 *   - on each identity, a device tag, HMAC(secret, "privasys-device-tag/v1" ‖ 0 ‖
 *     user id), which the IdP stores beside that phone's passkey and push target.
 *     Tags of one phone on two identities are unrelated values, so the IdP still
 *     cannot tell which identities belong together. Any phone of the holder knows
 *     every phone's secret, so it can name another phone's passkey on any
 *     identity, which is how one phone revokes another.
 *
 * The registry is the holder's list of phones and identities, kept encrypted on
 * the main account (it replaces the identity index, which listed only the
 * identities a seed cannot re-derive). It also carries the recovery epochs: each
 * identity's recovery key derives from the seed and the current epoch's secret,
 * and revoking a phone moves every identity to a new epoch, whose secret the
 * revoked phone never receives. Without that, a revoked phone, which still holds
 * the seed, could re-enrol itself.
 *
 * Phrase recovery is still the last resort and still removes every other phone.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as Crypto from 'expo-crypto';
import * as Device from 'expo-device';

import { ensureDataRoot } from '@/services/sovereign';
import { useAuthStore } from '@/stores/auth';
import { useProfileStore } from '@/stores/profile';
import { base64urlToBytes, bytesToBase64url } from '@/utils/encoding';
import * as SecureStore from '@/utils/storage';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** How many phones one holder may have. The IdP enforces the same. */
export const MAX_DEVICES = 5;

const DEVICE_KEY = 'privasys.device';
const EPOCHS_KEY = 'privasys.recovery-epochs';
const REGISTRY_KEY = 'privasys.registry';
const REGISTRY_VERSION_KEY = 'privasys.registry.version';

const TAG_INFO = 'privasys-device-tag/v1';
const RELAY_ADDR_INFO = 'privasys-device-relay-addr/v1';
const REGISTRY_INFO = 'privasys-identity-index/v1';
const REGISTRY_AAD = 'privasys-identity-index';
const REGISTRY_FORMAT = 0x02;
const LEGACY_INDEX_FORMAT = 0x01;

const utf8 = (s: string) => new TextEncoder().encode(s);

function labelled(label: string, ...values: string[]): Uint8Array {
    return utf8([label, ...values].join('\x00'));
}

function random(n: number): Uint8Array {
    return new Uint8Array(Crypto.getRandomBytes(n));
}

async function readJson<T>(key: string, fallback: T): Promise<T> {
    try {
        const raw = await SecureStore.getItemAsync(key);
        return raw ? (JSON.parse(raw) as T) : fallback;
    } catch {
        return fallback;
    }
}

// ---------------------------------------------------------------- this phone

export interface LocalDevice {
    id: string;
    /** base64url, 32 bytes. */
    secret: string;
    name: string;
    createdAt: number;
}

let cachedDevice: LocalDevice | null = null;

/** This phone, made on first use. */
export async function ensureDevice(): Promise<LocalDevice> {
    if (cachedDevice) return cachedDevice;
    const held = await readJson<LocalDevice | null>(DEVICE_KEY, null);
    if (held?.id && held.secret) {
        cachedDevice = held;
        return held;
    }
    const device: LocalDevice = {
        id: bytesToBase64url(random(16)),
        secret: bytesToBase64url(random(32)),
        // The model, not Device.deviceName: that is often the owner's name.
        name: Device.modelName || 'Phone',
        createdAt: Math.floor(Date.now() / 1000),
    };
    await SecureStore.setItemAsync(DEVICE_KEY, JSON.stringify(device));
    cachedDevice = device;
    return device;
}

/** Rename this phone (shown on the holder's other phones after the next sync). */
export async function renameDevice(name: string): Promise<void> {
    const d = await ensureDevice();
    cachedDevice = { ...d, name: name.trim().slice(0, 40) || d.name };
    await SecureStore.setItemAsync(DEVICE_KEY, JSON.stringify(cachedDevice));
    const reg = await localRegistry();
    await saveLocalRegistry(upsertDevice(reg, cachedDevice));
}

/** A phone's tag on one identity. */
export function deviceTagFor(secretB64: string, userId: string): string {
    return bytesToBase64url(hmac(sha256, base64urlToBytes(secretB64), labelled(TAG_INFO, userId)).slice(0, 16));
}

/** This phone's tag on one identity. */
export async function myDeviceTag(userId: string): Promise<string> {
    return deviceTagFor((await ensureDevice()).secret, userId);
}

/** Where a phone reads what the holder's other phones send it. */
export function relayAddressFor(secretB64: string): string {
    return bytesToBase64url(hmac(sha256, base64urlToBytes(secretB64), utf8(RELAY_ADDR_INFO)).slice(0, 16));
}

// ---------------------------------------------------------------- recovery epochs

/** An epoch's secret; epoch 0 is the seed alone (keys made before devices). */
export interface RecoveryEpoch {
    n: number;
    secret: string;
}

export async function loadEpochs(): Promise<RecoveryEpoch[]> {
    return readJson<RecoveryEpoch[]>(EPOCHS_KEY, []);
}

async function saveEpochs(epochs: RecoveryEpoch[]): Promise<void> {
    await SecureStore.setItemAsync(EPOCHS_KEY, JSON.stringify(mergeEpochs(epochs, [])));
}

function mergeEpochs(a: RecoveryEpoch[], b: RecoveryEpoch[]): RecoveryEpoch[] {
    const byN = new Map<number, RecoveryEpoch>();
    for (const e of [...a, ...b]) if (e && typeof e.n === 'number' && e.secret) byN.set(e.n, e);
    return [...byN.values()].sort((x, y) => x.n - y.n);
}

/** The newest epoch this phone knows, or null (epoch 0). */
export async function currentEpoch(): Promise<RecoveryEpoch | null> {
    const all = await loadEpochs();
    return all.length ? all[all.length - 1] : null;
}

/** The epoch numbered n, null for 0 or unknown. */
export async function epochNumbered(n: number): Promise<RecoveryEpoch | null> {
    if (!n) return null;
    return (await loadEpochs()).find((e) => e.n === n) ?? null;
}

// ---------------------------------------------------------------- registry

export interface RegistryIdentity {
    rpId: string;
    /** The IdP's user id. */
    userHandle: string;
    /** The epoch its recovery key is on (0: the seed alone). */
    epoch: number;
}

export interface RegistryDevice {
    id: string;
    name: string;
    createdAt: number;
    secret: string;
}

export interface Registry {
    identities: RegistryIdentity[];
    devices: RegistryDevice[];
    /** Ids of revoked phones, so a stale copy cannot bring one back. */
    revoked: string[];
    epochs: RecoveryEpoch[];
}

export const emptyRegistry = (): Registry => ({ identities: [], devices: [], revoked: [], epochs: [] });

/** Combine two copies: union of everything, the newer epoch per identity, revocations win. */
export function mergeRegistries(a: Registry, b: Registry): Registry {
    const revoked = [...new Set([...a.revoked, ...b.revoked])];
    const identities = new Map<string, RegistryIdentity>();
    for (const i of [...a.identities, ...b.identities]) {
        const prev = identities.get(i.userHandle);
        if (!prev || i.epoch > prev.epoch) identities.set(i.userHandle, { ...i, rpId: i.rpId || prev?.rpId || '' });
    }
    const devices = new Map<string, RegistryDevice>();
    for (const d of [...a.devices, ...b.devices]) {
        if (revoked.includes(d.id)) continue;
        const prev = devices.get(d.id);
        devices.set(d.id, prev ? { ...prev, name: d.name || prev.name } : d);
    }
    return {
        identities: [...identities.values()],
        devices: [...devices.values()].sort((x, y) => x.createdAt - y.createdAt),
        revoked,
        epochs: mergeEpochs(a.epochs, b.epochs),
    };
}

function sameRegistry(a: Registry, b: Registry): boolean {
    const norm = (r: Registry) =>
        JSON.stringify({
            i: [...r.identities].sort((x, y) => x.userHandle.localeCompare(y.userHandle)),
            d: r.devices,
            r: [...r.revoked].sort(),
            e: r.epochs,
        });
    return norm(a) === norm(b);
}

function upsertDevice(reg: Registry, d: LocalDevice): Registry {
    return mergeRegistries(reg, { ...emptyRegistry(), devices: [{ id: d.id, name: d.name, createdAt: d.createdAt, secret: d.secret }] });
}

export async function localRegistry(): Promise<Registry> {
    const r = await readJson<Registry | null>(REGISTRY_KEY, null);
    return r ? mergeRegistries(emptyRegistry(), r) : emptyRegistry();
}

export async function saveLocalRegistry(reg: Registry): Promise<void> {
    await SecureStore.setItemAsync(REGISTRY_KEY, JSON.stringify(reg));
    if (reg.epochs.length) await saveEpochs(mergeEpochs(await loadEpochs(), reg.epochs));
}

/** Record an identity this phone uses, on the epoch its key was registered under. */
export async function noteIdentity(rpId: string, userHandle: string, epoch: number): Promise<void> {
    const reg = await localRegistry();
    if (reg.identities.some((i) => i.userHandle === userHandle && i.epoch >= epoch)) return;
    await saveLocalRegistry(mergeRegistries(reg, { ...emptyRegistry(), identities: [{ rpId, userHandle, epoch }] }));
}

async function registryKey(): Promise<Uint8Array> {
    return hkdf(sha256, await ensureDataRoot(), undefined, utf8(REGISTRY_INFO), 32);
}

/** Encrypt the registry. Exported for tests. */
export function sealRegistry(key: Uint8Array, reg: Registry): string {
    const nonce = random(24);
    const ct = xchacha20poly1305(key, nonce, utf8(REGISTRY_AAD)).encrypt(utf8(JSON.stringify({ v: 2, ...reg })));
    const blob = new Uint8Array(1 + 24 + ct.length);
    blob[0] = REGISTRY_FORMAT;
    blob.set(nonce, 1);
    blob.set(ct, 25);
    return bytesToBase64url(blob);
}

/**
 * Decrypt the registry, or null when it does not open. Reads the identity index
 * it replaces too: its entries are identities on epoch 0.
 */
export function openRegistry(key: Uint8Array, blobB64: string): Registry | null {
    try {
        const raw = base64urlToBytes(blobB64);
        if (raw.length < 1 + 24 + 16 || (raw[0] !== REGISTRY_FORMAT && raw[0] !== LEGACY_INDEX_FORMAT)) return null;
        const pt = xchacha20poly1305(key, raw.slice(1, 25), utf8(REGISTRY_AAD)).decrypt(raw.slice(25));
        const parsed = JSON.parse(new TextDecoder().decode(pt)) as any;
        const ids = (Array.isArray(parsed.identities) ? parsed.identities : []).filter(
            (e: any) => typeof e?.rpId === 'string' && typeof e?.userHandle === 'string',
        );
        if (parsed.v === 1) {
            return { ...emptyRegistry(), identities: ids.map((e: any) => ({ rpId: e.rpId, userHandle: e.userHandle, epoch: 0 })) };
        }
        if (parsed.v !== 2) return null;
        return mergeRegistries(emptyRegistry(), {
            identities: ids.map((e: any) => ({ rpId: e.rpId, userHandle: e.userHandle, epoch: Number(e.epoch) || 0 })),
            devices: (parsed.devices ?? []).filter((d: any) => d?.id && d?.secret),
            revoked: (parsed.revoked ?? []).filter((x: any) => typeof x === 'string'),
            epochs: (parsed.epochs ?? []).filter((e: any) => typeof e?.n === 'number' && e?.secret),
        });
    } catch {
        return null;
    }
}

function mainSession(): string | null {
    const a = useAuthStore.getState().privasysId;
    return a?.sessionToken && Date.now() < a.sessionExpiresAt ? a.sessionToken : null;
}

async function fetchRemote(session: string): Promise<{ reg: Registry | null; version: number }> {
    const res = await fetch(`${IDP_BASE}/recovery/identity-index`, { headers: { Authorization: `Bearer wallet:${session}` } });
    if (res.status === 404) return { reg: null, version: 0 };
    if (!res.ok) throw new Error(`the registry could not be read (HTTP ${res.status})`);
    const body = (await res.json()) as { blob: string; version?: number };
    const reg = openRegistry(await registryKey(), body.blob);
    if (!reg) throw new Error('the registry did not open with this data root');
    return { reg, version: body.version ?? 0 };
}

/**
 * Bring this phone's registry and the stored one together, and store the merge
 * when it adds anything. Uses the main account's session only if one is open,
 * unless `session` is given: this never asks for Face ID. Returns the merged
 * registry, or the local one when nothing could be reached.
 */
export async function syncRegistry(session: string | null = mainSession()): Promise<Registry> {
    let local = await localRegistry();
    if (useProfileStore.getState().profile) local = upsertDevice(local, await ensureDevice());
    if (!session) return local;
    for (let attempt = 0; attempt < 3; attempt++) {
        const { reg: remote, version } = await fetchRemote(session);
        const merged = remote ? mergeRegistries(remote, local) : local;
        await saveLocalRegistry(merged);
        await SecureStore.setItemAsync(REGISTRY_VERSION_KEY, String(version));
        if (remote && sameRegistry(merged, remote)) return merged;
        const res = await fetch(`${IDP_BASE}/recovery/identity-index`, {
            method: 'PUT',
            headers: { Authorization: `Bearer wallet:${session}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ blob: sealRegistry(await registryKey(), merged), version }),
        });
        if (res.ok) {
            const { version: next } = (await res.json()) as { version: number };
            await SecureStore.setItemAsync(REGISTRY_VERSION_KEY, String(next));
            return merged;
        }
        if (res.status !== 409) throw new Error(`the registry could not be stored (HTTP ${res.status})`);
        local = merged; // another phone wrote first: merge again
    }
    throw new Error('the registry kept changing; try again');
}

/** Replace the registry outright (after a revocation), keeping the merge rules. */
export async function storeRegistry(session: string, reg: Registry): Promise<void> {
    await saveLocalRegistry(reg);
    await syncRegistry(session);
}

/** The holder's phones, this one first. */
export async function listDevices(): Promise<{ device: RegistryDevice; isThis: boolean }[]> {
    const me = await ensureDevice();
    const reg = await localRegistry();
    const all = upsertDevice(reg, me).devices;
    return all
        .map((d) => ({ device: d, isThis: d.id === me.id }))
        .sort((a, b) => (a.isThis ? -1 : b.isThis ? 1 : a.device.createdAt - b.device.createdAt));
}

/** Part of Clear All Data. */
export async function clearDevicesLocalState(): Promise<void> {
    cachedDevice = null;
    for (const k of [DEVICE_KEY, EPOCHS_KEY, REGISTRY_KEY, REGISTRY_VERSION_KEY]) await SecureStore.deleteItemAsync(k);
}

// ---------------------------------------------------------------- pairing crypto

const PAIR_INFO = 'privasys-device-pairing/v1';
const PAIR_AAD = 'privasys-device-pairing';
const CODE_INFO = 'privasys-device-pairing-code/v1';

/** A fresh X25519 key pair for one pairing. */
export function pairingKeys(): { secretKey: Uint8Array; publicKey: Uint8Array } {
    const secretKey = random(32);
    return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
}

function pairingKey(shared: Uint8Array, receiverPub: Uint8Array, senderPub: Uint8Array): Uint8Array {
    const salt = new Uint8Array(64);
    salt.set(receiverPub, 0);
    salt.set(senderPub, 32);
    return hkdf(sha256, shared, salt, utf8(PAIR_INFO), 32);
}

/** Seal the transfer to the new phone's key. Returns the sender's public key and the blob. */
export function sealTransfer(receiverPubB64: string, payload: unknown): { senderPub: string; blob: string } {
    const receiverPub = base64urlToBytes(receiverPubB64);
    const mine = pairingKeys();
    const key = pairingKey(x25519.getSharedSecret(mine.secretKey, receiverPub), receiverPub, mine.publicKey);
    const nonce = random(24);
    const ct = xchacha20poly1305(key, nonce, utf8(PAIR_AAD)).encrypt(utf8(JSON.stringify(payload)));
    const blob = new Uint8Array(24 + ct.length);
    blob.set(nonce, 0);
    blob.set(ct, 24);
    return { senderPub: bytesToBase64url(mine.publicKey), blob: bytesToBase64url(blob) };
}

/** Open the transfer on the new phone. Throws when it does not open. */
export function openTransfer<T>(receiverSecret: Uint8Array, senderPubB64: string, blobB64: string): T {
    const senderPub = base64urlToBytes(senderPubB64);
    const receiverPub = x25519.getPublicKey(receiverSecret);
    const key = pairingKey(x25519.getSharedSecret(receiverSecret, senderPub), receiverPub, senderPub);
    const raw = base64urlToBytes(blobB64);
    const pt = xchacha20poly1305(key, raw.slice(0, 24), utf8(PAIR_AAD)).decrypt(raw.slice(24));
    return JSON.parse(new TextDecoder().decode(pt)) as T;
}

/**
 * The six digits both phones show, so the holder can see that the phone that
 * sent is the one in their hand.
 */
export function pairingCode(receiverPubB64: string, senderPubB64: string): string {
    const d = sha256(labelled(CODE_INFO, receiverPubB64, senderPubB64));
    const n = ((d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]) >>> 0;
    return String(n % 1_000_000).padStart(6, '0').replace(/^(\d{3})(\d{3})$/, '$1 $2');
}

/** The link the new phone's QR code carries. */
export function pairingLink(slot: string, receiverPubB64: string): string {
    return `privasys-wallet://pair?s=${encodeURIComponent(slot)}&k=${encodeURIComponent(receiverPubB64)}`;
}

/** Parse a pairing link, or null. */
export function parsePairingLink(text: string): { slot: string; key: string } | null {
    const m = /^privasys-wallet:\/\/pair\?(.*)$/.exec(text.trim());
    if (!m) return null;
    const q = new URLSearchParams(m[1]);
    const slot = q.get('s');
    const key = q.get('k');
    if (!slot || !key || !/^[A-Za-z0-9_-]{16,64}$/.test(slot) || !/^[A-Za-z0-9_-]{43}$/.test(key)) return null;
    return { slot, key };
}

// ---------------------------------------------------------------- signatures

/** Domain-separated messages for an identity's recovery key. Must match the IdP. */
export function enrolMessage(userId: string, challenge: Uint8Array): Uint8Array {
    return join(utf8('privasys-identity-enrol/v1\x00' + userId + '\x00'), challenge);
}

export function revokeMessage(userId: string, challenge: Uint8Array, deviceTag: string, newPublicKeyB64: string): Uint8Array {
    return join(join(utf8('privasys-identity-revoke/v1\x00' + userId + '\x00'), challenge), utf8('\x00' + deviceTag + '\x00' + newPublicKeyB64));
}

function join(a: Uint8Array, b: Uint8Array): Uint8Array {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
}

export function signWith(secretKey: Uint8Array, msg: Uint8Array): string {
    return bytesToBase64url(ed25519.sign(msg, secretKey));
}

/** The IdP's user id for the main account slot (which has held the raw 32-hex form too). */
export function mainAccountUserId(slotUserId: string): string {
    return /^[0-9a-f]{32}$/.test(slotUserId) ? bytesToBase64url(utf8(slotUserId)) : slotUserId;
}
