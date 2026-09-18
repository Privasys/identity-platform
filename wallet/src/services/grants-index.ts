// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Where the holder has standing capabilities, kept so a recovered wallet can
 * find them again.
 *
 * The grants themselves live at the services that enforce them, and every one
 * of those answers "what does this holder hold here" for an authenticated
 * holder (GET on its capabilities collection). So a wallet can rebuild its
 * Access rows, and the revoke button on each, from the services' own answers.
 * What it cannot rebuild on a new phone is WHICH services to ask. The grant
 * records are local, and without this a recovered holder would have standing
 * grants, an unattended holder folder among them, and nothing to tap.
 *
 * So the index holds the services, not the grants, and a rebuild asks each
 * service what it holds. Rows come back as the service's answer, confirmed,
 * rather than taken on trust from a backup.
 *
 * It is encrypted under a key derived from the sovereign data root and stored
 * as a blob beside the sovereign backup. Not inside that backup: the backup is
 * re-wrapped only while the wallet holds the recovery phrase, which is during a
 * phrase ceremony and never during an approval, while this changes at every
 * approval. The root is on the phone at approval time, and recovery restores
 * the root, so the chain is phrase, root, index key, index.
 *
 *   key  = HKDF-SHA256(root, info = "privasys-grants-index/v1", 32)
 *   blob = base64url( 0x01 || nonce(24) || XChaCha20-Poly1305(key, nonce,
 *                     AAD = "privasys-grants-index").encrypt(utf8(JSON)) )
 *
 * Everything here is best effort and never throws to a screen. An index that
 * failed to upload is retried the next time anything changes or the Access tab
 * opens; a failed rebuild leaves the rows the phone already had.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as Crypto from 'expo-crypto';

import { resolveApp } from '@/services/app-resolve';
import {
    CAPABILITY_KINDS,
    listCapabilities,
    PERMISSIONS,
    serviceUrlHost,
    type CapabilityKind,
    type HeldCapability,
    type Permission,
} from '@/services/capabilities';
import { getPlatformToken } from '@/services/platform-token';
import { ensureDataRoot } from '@/services/sovereign';
import { useCapabilitiesStore, type CapabilityRecord } from '@/stores/capabilities';
import * as SecureStore from '@/utils/storage';
import { base64urlToBytes, bytesToBase64url } from '@/utils/encoding';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';
const INDEX_INFO = 'privasys-grants-index/v1';
const INDEX_AAD = 'privasys-grants-index';
const BLOB_VERSION = 0x01;
/** Fingerprint of the last index this device uploaded, to skip no-op writes. */
const LAST_SYNCED_KEY = 'privasys.grants-index.synced';

const utf8 = (s: string) => new TextEncoder().encode(s);

/** One service the holder has something at. */
export interface IndexedService {
    /** The resource service's app id. Resolved again by identity on rebuild. */
    resourceAppId: string;
    /** For a capability minted at a service_url: exactly where. */
    serviceUrl?: string;
}

/**
 * What the service's list cannot say and the Access tab needs: whether the
 * holder typed a credential into it, which is what sorts a grant into
 * "connected accounts", and the service's own labels for those fields.
 * Labels only, never values.
 */
export interface GrantExtras {
    setupProvided?: boolean;
    secretLabels?: string[];
    unattended?: boolean;
}

export interface GrantsIndex {
    v: 1;
    services: IndexedService[];
    extras: Record<string, GrantExtras>;
}

// ---------------------------------------------------------------- building

/**
 * The index for the grants the holder currently has. Revoked grants and
 * denials drop out: there is nothing to rebuild for them, and a service no
 * longer holding a grant would not list it anyway.
 */
export function buildIndex(records: CapabilityRecord[]): GrantsIndex {
    const live = records.filter((r) => r.decision === 'approved' && !r.revokedAt && r.capabilityId);
    const seen = new Set<string>();
    const services: IndexedService[] = [];
    const extras: Record<string, GrantExtras> = {};
    for (const r of live) {
        const where = r.serviceUrl ?? `app:${r.resourceAppId}`;
        if (!seen.has(where)) {
            seen.add(where);
            services.push(r.serviceUrl
                ? { resourceAppId: r.resourceAppId, serviceUrl: r.serviceUrl }
                : { resourceAppId: r.resourceAppId });
        }
        const x: GrantExtras = {};
        if (r.setupProvided) x.setupProvided = true;
        if (r.secretLabels?.length) x.secretLabels = r.secretLabels;
        if (r.unattended) x.unattended = true;
        if (Object.keys(x).length > 0) extras[r.capabilityId!] = x;
    }
    // Stable order, so an unchanged set produces an unchanged fingerprint.
    services.sort((a, b) =>
        (a.serviceUrl ?? a.resourceAppId).localeCompare(b.serviceUrl ?? b.resourceAppId),
    );
    return { v: 1, services, extras: sortKeys(extras) };
}

function sortKeys<T>(o: Record<string, T>): Record<string, T> {
    const out: Record<string, T> = {};
    for (const k of Object.keys(o).sort()) out[k] = o[k];
    return out;
}

// ---------------------------------------------------------------- sealing

function indexKey(root: Uint8Array): Uint8Array {
    return hkdf(sha256, root, undefined, utf8(INDEX_INFO), 32);
}

export function sealIndex(root: Uint8Array, index: GrantsIndex, nonce?: Uint8Array): string {
    const n = nonce ?? new Uint8Array(Crypto.getRandomBytes(24));
    const ct = xchacha20poly1305(indexKey(root), n, utf8(INDEX_AAD)).encrypt(utf8(JSON.stringify(index)));
    const out = new Uint8Array(1 + n.length + ct.length);
    out[0] = BLOB_VERSION;
    out.set(n, 1);
    out.set(ct, 1 + n.length);
    return bytesToBase64url(out);
}

/**
 * The index, or null for a blob this root cannot open: another identity's, a
 * tampered one, or an unknown version. Null rather than a throw, because every
 * one of those means "nothing to rebuild", not "something broke".
 */
export function openIndex(root: Uint8Array, blob: string): GrantsIndex | null {
    try {
        const bytes = base64urlToBytes(blob);
        if (bytes[0] !== BLOB_VERSION || bytes.length < 1 + 24 + 16) return null;
        const pt = xchacha20poly1305(indexKey(root), bytes.slice(1, 25), utf8(INDEX_AAD)).decrypt(
            bytes.slice(25),
        );
        const parsed = JSON.parse(new TextDecoder().decode(pt)) as GrantsIndex;
        if (parsed?.v !== 1 || !Array.isArray(parsed.services)) return null;
        return { v: 1, services: parsed.services, extras: parsed.extras ?? {} };
    } catch {
        return null;
    }
}

// ---------------------------------------------------------------- transport

// The platform token, not the wallet session: it is cached for days, so a sync
// never prompts for Face ID, and the IdP keys it on the same user id.
async function getIndexBlob(): Promise<Response> {
    const token = await getPlatformToken();
    return fetch(`${IDP_BASE}/recovery/grants-index`, {
        headers: { Authorization: `Bearer ${token}` },
    });
}

async function putIndexBlob(blob: string): Promise<Response> {
    const token = await getPlatformToken();
    return fetch(`${IDP_BASE}/recovery/grants-index`, {
        method: 'PUT',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ blob }),
    });
}

// ---------------------------------------------------------------- sync

let syncing: Promise<void> | null = null;

/**
 * Upload the index if it changed since this device last uploaded it. Called
 * after every approval and revocation, and when the Access tab opens so a
 * failed upload catches up. Never throws.
 */
export function syncGrantsIndex(): Promise<void> {
    if (syncing) return syncing;
    syncing = (async () => {
        try {
            await useCapabilitiesStore.getState().hydrate();
            const index = buildIndex(useCapabilitiesStore.getState().records);
            const fingerprint = bytesToBase64url(sha256(utf8(JSON.stringify(index))));
            if ((await SecureStore.getItemAsync(LAST_SYNCED_KEY)) === fingerprint) return;

            const root = await ensureDataRoot();
            const res = await putIndexBlob(sealIndex(root, index));
            if (!res.ok) {
                console.warn(`[GRANTS-INDEX] upload refused: HTTP ${res.status}`);
                return;
            }
            await SecureStore.setItemAsync(LAST_SYNCED_KEY, fingerprint);
            console.log(`[GRANTS-INDEX] uploaded ${index.services.length} service(s)`);
        } catch (e) {
            console.warn('[GRANTS-INDEX] upload skipped:', e instanceof Error ? e.message : e);
        } finally {
            syncing = null;
        }
    })();
    return syncing;
}

// ---------------------------------------------------------------- rebuild

/** "app:<32 hex>", bare hex or dashed, to the dashed form the wallet keys on. */
export function dashedAppId(raw: string | undefined): string {
    const hex = (raw ?? '').replace(/^app:/, '').replace(/-/g, '').toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(hex)) return raw ?? '';
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * A record for a capability a service reports and this phone has no row for,
 * or null for one the wallet could not describe (an unknown kind or
 * permission, which it would refuse on an approval screen too).
 */
export function recordFromHeld(
    held: HeldCapability,
    service: IndexedService & { resourceAppName?: string },
    extras: GrantExtras | undefined,
    names: { appName?: string },
    nowSeconds: number,
): CapabilityRecord | null {
    const kind = held.kind as CapabilityKind;
    if (!(CAPABILITY_KINDS as readonly string[]).includes(kind)) return null;
    const permissions = (held.permissions ?? []).filter((p): p is Permission =>
        (PERMISSIONS as readonly string[]).includes(p),
    );
    if (permissions.length === 0 || permissions.length !== (held.permissions ?? []).length) return null;
    return {
        appId: dashedAppId(held.subject_app_id),
        appName: names.appName,
        resourceAppId: service.resourceAppId,
        resourceAppName: service.resourceAppName,
        kind,
        resourceLabel: held.resource_label ?? '',
        permissions,
        decision: 'approved',
        capabilityId: held.capability_id,
        grantedAt: held.created_unix || nowSeconds,
        expiresAt: held.expires_unix || undefined,
        setupProvided: extras?.setupProvided,
        secretLabels: extras?.secretLabels,
        unattended: held.unattended || extras?.unattended || undefined,
        serviceUrl: service.serviceUrl,
        lastCheckedAt: nowSeconds,
        checkResult: 'held',
    };
}

let rebuiltThisLaunch = false;

/**
 * Put back the rows this phone is missing, from the services the index names.
 *
 * Runs once per launch when the Access tab opens. Merges rather than replaces,
 * so it serves a recovered phone and a second phone alike, and it never
 * resurrects a revoked grant: a service does not list what it no longer holds.
 * Never throws.
 */
export async function rebuildFromGrantsIndex(): Promise<number> {
    if (rebuiltThisLaunch) return 0;
    rebuiltThisLaunch = true;
    try {
        const res = await getIndexBlob();
        if (res.status === 404) return 0;
        if (!res.ok) {
            rebuiltThisLaunch = false;
            return 0;
        }
        const { blob } = (await res.json()) as { blob?: string };
        if (!blob) return 0;
        const index = openIndex(await ensureDataRoot(), blob);
        if (!index) return 0;

        const store = useCapabilitiesStore.getState();
        await store.hydrate();
        const known = new Set(
            useCapabilitiesStore.getState().records.map((r) => r.capabilityId).filter(Boolean),
        );
        const now = Math.floor(Date.now() / 1000);
        let added = 0;

        for (const service of index.services) {
            try {
                // A service_url came from this holder's own encrypted index, and
                // was checked against the attested app host when it was minted.
                // Anything else is resolved by identity, as always.
                let host: string;
                let resourceAppName: string | undefined;
                if (service.serviceUrl) {
                    host = serviceUrlHost(service.serviceUrl);
                } else {
                    const resolved = await resolveApp(service.resourceAppId);
                    if (!resolved?.hostname) continue;
                    host = resolved.hostname;
                    resourceAppName = resolved.display_name || resolved.name;
                }
                const held = await listCapabilities(host, service.serviceUrl);
                if (!held) continue;
                for (const h of held) {
                    if (known.has(h.capability_id)) continue;
                    const subject = h.subject_app_id ? await resolveApp(dashedAppId(h.subject_app_id)) : null;
                    const record = recordFromHeld(
                        h,
                        { ...service, resourceAppName },
                        index.extras[h.capability_id],
                        { appName: subject?.display_name || subject?.name || undefined },
                        now,
                    );
                    if (!record) continue;
                    useCapabilitiesStore.getState().record(record);
                    known.add(h.capability_id);
                    added++;
                }
            } catch (e) {
                // One unreachable service must not cost the holder the rest.
                console.warn('[GRANTS-INDEX] a service could not be asked:', e instanceof Error ? e.message : e);
            }
        }
        if (added > 0) console.log(`[GRANTS-INDEX] restored ${added} grant(s) from the index`);
        return added;
    } catch (e) {
        rebuiltThisLaunch = false;
        console.warn('[GRANTS-INDEX] rebuild skipped:', e instanceof Error ? e.message : e);
        return 0;
    }
}

/**
 * Part of the wallet wipe. Forgets what this device last uploaded, so a fresh
 * identity on the phone uploads its own index rather than being told the last
 * one's is already there.
 *
 * The copy at the IdP is left alone and is unreadable without the root the
 * wipe deletes. If the holder later recovers the same account, the root comes
 * back and so does the index, and with it the revoke buttons.
 */
export async function clearGrantsIndexLocalState(): Promise<void> {
    rebuiltThisLaunch = false;
    syncing = null;
    await SecureStore.deleteItemAsync(LAST_SYNCED_KEY);
}

/** Test seam. */
export function __resetGrantsIndexForTests(): void {
    rebuiltThisLaunch = false;
    syncing = null;
}
