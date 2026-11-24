// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Renewing a threshold vault key (vault operation "reshare"): what the owner
 * approves, checked before it is shown.
 *
 * The key's old vaults deal fresh shares to new vaults, and the public key does
 * not change. The vault binds the approval to a digest of the resharing
 * context, which names the new vaults' build (MRENCLAVE). The approval context
 * carries that digest's inputs as display data, from the same control plane the
 * check guards against, so the wallet:
 *
 *   1. recomputes the digest from those inputs and refuses the card when it is
 *      not the measurement the approval binds (a label that is not what the
 *      passkey would sign is never shown);
 *   2. names the target build as a published Enclave Vault release, read from
 *      GitHub (never from the control plane), with the releases known when this
 *      wallet was built pinned in case GitHub cannot be reached. A build that is
 *      no published release cannot be approved.
 *
 * Digest, as the vault computes it (enclave-os-vault threshold.rs
 * reshare_context): SHA-256 over
 *   "privasys-vault-frost-reshare-v1"
 *   u64be(len) handle
 *   u64be(32) group public key
 *   u64be(count) helpers, each u16be (old indices that deal, ascending)
 *   u16be new threshold
 *   u64be(count) vaults, each u64be(len) "host:port" (new, in index order)
 *   target MRENCLAVE (32 bytes)
 */

import { sha256 } from '@noble/hashes/sha2.js';

const DOMAIN = 'privasys-vault-frost-reshare-v1';
const RELEASES_API = 'https://api.github.com/repos/Privasys/enclave-vaults/releases?per_page=30';
const RELEASE_TAG = /^vault-v\d+\.\d+\.\d+$/;
const HEX32 = /^[0-9a-f]{64}$/;

/** What a reshare approval carries, as the IdP passes it on. */
export interface ReshareSummaryFields {
    handle: string;
    measurement: string;
    target_mrenclave?: string;
    target_vaults?: string;
    threshold?: string;
    helpers?: string;
    public_key?: string;
}

/** A reshare whose display fields recompute to the bound measurement. */
export interface CheckedReshare {
    mrenclave: string;
    vaults: string[];
    threshold: number;
    helpers: number[];
}

/** A published Enclave Vault release. */
export interface VaultRelease {
    /** The release's version, e.g. "v0.39.0". */
    version: string;
    url: string;
}

/**
 * Releases known when this wallet was built, from the mrenclave.txt published
 * with each (checked 2026-11-24). Newer ones are read from GitHub.
 */
const PINNED: Record<string, VaultRelease> = {
    '6b516eab16067c519627e6fe26b636da861ccf5722f20ea37ef6559b8925b435': release('vault-v0.39.0'),
    '9ee403a6e3c42a16c3e6e940fdbfd77086aae505580ca35b8aaa20893b24171f': release('vault-v0.38.0'),
};

function release(tag: string): VaultRelease {
    return { version: tag.slice('vault-'.length), url: `https://github.com/Privasys/enclave-vaults/releases/tag/${tag}` };
}

const utf8 = (s: string) => new TextEncoder().encode(s);

function u64(n: number): Uint8Array {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(n));
    return b;
}

function u16(n: number): Uint8Array {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, n);
    return b;
}

function withLength(bytes: Uint8Array): Uint8Array[] {
    return [u64(bytes.length), bytes];
}

function hex(bytes: Uint8Array): string {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(s: string): Uint8Array {
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    return out;
}

function fromBase64url(s: string): Uint8Array | null {
    if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
    const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const out: number[] = [];
    let bits = 0;
    let acc = 0;
    for (const ch of s) {
        acc = (acc << 6) | abc.indexOf(ch);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push((acc >> bits) & 0xff);
        }
    }
    return new Uint8Array(out);
}

/** The resharing-context digest, lowercase hex, as the vault computes it. */
export function reshareDigest(args: {
    handle: string;
    groupKey: Uint8Array;
    helpers: number[];
    threshold: number;
    vaults: string[];
    mrenclave: Uint8Array;
}): string {
    const parts: Uint8Array[] = [
        utf8(DOMAIN),
        ...withLength(utf8(args.handle)),
        ...withLength(args.groupKey),
        u64(args.helpers.length),
        ...args.helpers.map(u16),
        u16(args.threshold),
        u64(args.vaults.length),
        ...args.vaults.flatMap((v) => withLength(utf8(v))),
        args.mrenclave,
    ];
    const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) {
        all.set(p, at);
        at += p.length;
    }
    return hex(sha256(all));
}

function index(s: string): number | null {
    if (!/^\d{1,5}$/.test(s)) return null;
    const n = Number(s);
    return n >= 1 && n <= 0xffff ? n : null;
}

/**
 * Read a reshare's display fields and check them against the measurement the
 * approval binds. Null when anything is missing, malformed, or recomputes to
 * another digest: the card then offers only Decline.
 */
export function checkReshare(s: ReshareSummaryFields): CheckedReshare | null {
    const mrenclave = (s.target_mrenclave ?? '').toLowerCase();
    if (!HEX32.test(mrenclave) || !HEX32.test((s.measurement ?? '').toLowerCase())) return null;
    const groupKey = fromBase64url(s.public_key ?? '');
    if (!groupKey || groupKey.length !== 32) return null;
    const threshold = index(s.threshold ?? '');
    const helpers = (s.helpers ?? '').split(',').map(index);
    const vaults = (s.target_vaults ?? '').split(',');
    if (threshold === null || helpers.some((h) => h === null) || vaults.some((v) => v === '')) return null;
    if (threshold > vaults.length) return null;
    const digest = reshareDigest({
        handle: s.handle,
        groupKey,
        helpers: helpers as number[],
        threshold,
        vaults,
        mrenclave: fromHex(mrenclave),
    });
    if (digest !== s.measurement.toLowerCase()) return null;
    return { mrenclave, vaults, threshold, helpers: helpers as number[] };
}

let published: Promise<Record<string, VaultRelease>> | null = null;

/** The published releases' MRENCLAVEs, read once per launch from GitHub. */
async function publishedReleases(): Promise<Record<string, VaultRelease>> {
    const res = await fetch(RELEASES_API, { headers: { Accept: 'application/vnd.github+json' } });
    if (!res.ok) throw new Error(`GitHub releases (${res.status})`);
    const list = (await res.json()) as Array<{
        tag_name?: string;
        draft?: boolean;
        prerelease?: boolean;
        assets?: Array<{ name?: string; browser_download_url?: string }>;
    }>;
    const out: Record<string, VaultRelease> = {};
    for (const r of Array.isArray(list) ? list : []) {
        if (!r.tag_name || !RELEASE_TAG.test(r.tag_name) || r.draft || r.prerelease) continue;
        const asset = r.assets?.find((a) => a.name === 'mrenclave.txt')?.browser_download_url;
        if (!asset?.startsWith('https://github.com/Privasys/enclave-vaults/releases/download/')) continue;
        try {
            const m = (await (await fetch(asset)).text()).trim().toLowerCase();
            if (HEX32.test(m) && !out[m]) out[m] = release(r.tag_name);
        } catch {
            // One unreadable asset leaves the others.
        }
    }
    return out;
}

/**
 * The published Enclave Vault release built as `mrenclave`, or null when no
 * release is. Throws when GitHub cannot be reached and the build is not one
 * pinned here, so the card can say it could not check rather than "unknown".
 */
export async function vaultReleaseFor(mrenclave: string): Promise<VaultRelease | null> {
    const m = mrenclave.toLowerCase();
    if (PINNED[m]) return PINNED[m];
    if (!published) {
        published = publishedReleases().catch((e) => {
            published = null;
            throw e;
        });
    }
    return (await published)[m] ?? null;
}

/** Forget what GitHub said, so a pull to refresh reads it again. */
export function forgetPublishedReleases(): void {
    published = null;
}
