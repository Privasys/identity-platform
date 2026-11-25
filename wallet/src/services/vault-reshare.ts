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

import * as SecureStore from '@/utils/storage';

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
 * with each (checked 2026-11-25). Newer ones are read from GitHub.
 */
const PINNED: Record<string, VaultRelease> = {
    '1f038cf275208d0146535ae268d6cbffe89ed39cb2dfd7e1c719d8f678b04f26': release('vault-v0.43.0'),
    '28b01b4b2de825bf19ed6a8622af95ecf61d3f759bf5ed0d8e6c8415acc6fa4b': release('vault-v0.42.0'),
    '434ca8138643088ffb8af3ac575e2ec76f6fcc65fbf6ef19c8435ff4d995c554': release('vault-v0.41.0'),
    '47c67a77fba9ac0f2092b49588abcbefb3ec4daf36637dce6f46e7d046665902': release('vault-v0.40.0'),
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

const RELEASE_BY_TAG = 'https://api.github.com/repos/Privasys/enclave-vaults/releases/tags/';
const DOWNLOAD_PREFIX = 'https://github.com/Privasys/enclave-vaults/releases/download/';
/** Where releases GitHub confirmed are kept, so each is looked up once. */
const STORE_KEY = 'privasys.vault-releases';

interface GitHubRelease {
    tag_name?: string;
    draft?: boolean;
    prerelease?: boolean;
    assets?: Array<{ name?: string; browser_download_url?: string }>;
}

/** The MRENCLAVE a published release states, or null when it states none. */
async function mrenclaveOf(r: GitHubRelease): Promise<string | null> {
    if (!r.tag_name || !RELEASE_TAG.test(r.tag_name) || r.draft || r.prerelease) return null;
    const asset = r.assets?.find((a) => a.name === 'mrenclave.txt')?.browser_download_url;
    // Only this release's own file, in this repository.
    if (asset !== `${DOWNLOAD_PREFIX}${r.tag_name}/mrenclave.txt`) return null;
    try {
        const res = await fetch(asset);
        if (!res.ok) return null;
        const m = (await res.text()).trim().toLowerCase();
        return HEX32.test(m) ? m : null;
    } catch {
        return null;
    }
}

let published: Promise<Record<string, VaultRelease>> | null = null;
/** Releases GitHub confirmed, this launch and earlier ones (MRENCLAVE to release). */
let confirmed: Record<string, VaultRelease> | null = null;

async function loadConfirmed(): Promise<Record<string, VaultRelease>> {
    if (confirmed) return confirmed;
    const out: Record<string, VaultRelease> = {};
    try {
        const raw = await SecureStore.getItemAsync(STORE_KEY);
        const tags = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
        for (const [m, tag] of Object.entries(tags)) {
            if (HEX32.test(m) && typeof tag === 'string' && RELEASE_TAG.test(tag)) out[m] = release(tag);
        }
    } catch {
        /* nothing kept, or storage unavailable */
    }
    confirmed = out;
    return out;
}

async function remember(found: Record<string, VaultRelease>): Promise<void> {
    const all = { ...(await loadConfirmed()), ...found };
    confirmed = all;
    const tags: Record<string, string> = {};
    for (const [m, r] of Object.entries(all)) tags[m] = `vault-${r.version}`;
    await SecureStore.setItemAsync(STORE_KEY, JSON.stringify(tags)).catch(() => {});
}

/** The published releases' MRENCLAVEs, read from GitHub, all files at once. */
async function publishedReleases(): Promise<Record<string, VaultRelease>> {
    const res = await fetch(RELEASES_API, { headers: { Accept: 'application/vnd.github+json' } });
    if (!res.ok) throw new Error(`GitHub releases (${res.status})`);
    const list = (await res.json()) as GitHubRelease[];
    const releases = Array.isArray(list) ? list : [];
    const stated = await Promise.all(releases.map(mrenclaveOf));
    const out: Record<string, VaultRelease> = {};
    releases.forEach((r, i) => {
        const m = stated[i];
        // The list is newest first: a build two releases share is named by the newer.
        if (m && !out[m]) out[m] = release(r.tag_name as string);
    });
    await remember(out);
    return out;
}

/**
 * Check one release named as a hint: whether the release `tag` is published
 * and built as `mrenclave`. The hint only says where to look. A draft, a
 * prerelease, a missing file or another build is no match, and a hint that is
 * not a release tag is never sent anywhere.
 */
async function releaseByHint(tag: string, mrenclave: string): Promise<VaultRelease | null> {
    if (!RELEASE_TAG.test(tag)) return null;
    try {
        const res = await fetch(`${RELEASE_BY_TAG}${tag}`, { headers: { Accept: 'application/vnd.github+json' } });
        if (!res.ok) return null;
        const r = (await res.json()) as GitHubRelease;
        if (r.tag_name !== tag || (await mrenclaveOf(r)) !== mrenclave) return null;
        const found = release(tag);
        await remember({ [mrenclave]: found });
        return found;
    } catch {
        return null;
    }
}

/**
 * The published Enclave Vault release built as `mrenclave`, or null when no
 * release is. Throws when GitHub cannot be reached and the build is not one
 * known here, so the card can say it could not check rather than "unknown".
 *
 * Known without asking: the releases pinned in this wallet, and those GitHub
 * confirmed before. `hint` is a release tag from whoever relays the request:
 * that one release is checked first, which is one lookup where the whole list
 * is many. It cannot make anything pass: the answer is GitHub's.
 */
export async function vaultReleaseFor(mrenclave: string, hint?: string): Promise<VaultRelease | null> {
    const m = mrenclave.toLowerCase();
    if (PINNED[m]) return PINNED[m];
    const kept = (await loadConfirmed())[m];
    if (kept) return kept;
    if (hint) {
        const hinted = await releaseByHint(hint, m);
        if (hinted) return hinted;
    }
    if (!published) {
        published = publishedReleases().catch((e) => {
            published = null;
            throw e;
        });
    }
    return (await published)[m] ?? null;
}

/** Forget what GitHub said this launch, so a pull to refresh reads it again. */
export function forgetPublishedReleases(): void {
    published = null;
}

/** Forget everything kept, on disk too (tests). */
export async function forgetVaultReleases(): Promise<void> {
    published = null;
    confirmed = null;
    await SecureStore.deleteItemAsync(STORE_KEY).catch(() => {});
}
