// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Attested cross-enclave dependencies (wallet side).
 *
 * An enclave that depends on other enclaves advertises its DIRECT dependencies
 * in the certificate extension OID 1.3.6.1.4.1.65230.6.1. This module decodes
 * that extension (the canonical, length-prefixed encoding shared with the RA-TLS
 * SDKs and the enclave runtime) so the wallet can show the user what a service
 * pulls in, and cache a per-dependency approval keyed by (app-id, identity).
 *
 * Consent granularity is the pinned identity. The wallet does not walk the whole
 * tree: approving a dependency at a specific identity transitively covers that
 * dependency's own pinned sub-dependencies (its identity folds them in). See
 * useDependencyApprovalsStore.
 */

/** OID carrying a workload's direct attested-dependency set. */
export const OID_ATTESTED_DEPENDENCY_SET = '1.3.6.1.4.1.65230.6.1';

export interface DependencyOid {
    oid: string;
    /** Lowercase hex of the required extension value. */
    valueHex: string;
}

/** One declared direct dependency, decoded from the OID 6.1 extension. */
export interface DeclaredDependency {
    /** Management app-id of the dependency (matches its OID 3.6). */
    appId: string;
    /** Any-of allowed measurements, in canonical string form ("sgx:.." / "tdx:..:..:.."). */
    measurements: string[];
    /** OID values the dependency's certificate must carry verbatim. */
    requiredOids: DependencyOid[];
    /** Lowercase-hex commitment to the dependency's own subtree (empty for a leaf). */
    foldedIdentity: string;
}

/** Reader for the canonical big-endian length-prefixed encoding. */
class Reader {
    private off = 0;
    constructor(private readonly buf: Uint8Array) {}

    u32(): number {
        if (this.off + 4 > this.buf.length) throw new Error('dependency set truncated');
        const v =
            (this.buf[this.off] << 24) |
            (this.buf[this.off + 1] << 16) |
            (this.buf[this.off + 2] << 8) |
            this.buf[this.off + 3];
        this.off += 4;
        return v >>> 0;
    }
    bytes(): Uint8Array {
        const n = this.u32();
        if (this.off + n > this.buf.length) throw new Error('dependency set truncated');
        const b = this.buf.subarray(this.off, this.off + n);
        this.off += n;
        return b;
    }
    str(): string {
        return new TextDecoder().decode(this.bytes());
    }
    get done(): boolean {
        return this.off === this.buf.length;
    }
}

function hexToBytes(hex: string): Uint8Array {
    const clean = hex.length % 2 === 0 ? hex : '0' + hex;
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
}

function bytesToHex(b: Uint8Array): string {
    let s = '';
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
}

/** Decode the canonical dependency-set bytes into declared dependencies. */
export function decodeDependencySet(bytes: Uint8Array): DeclaredDependency[] {
    const r = new Reader(bytes);
    const count = r.u32();
    const out: DeclaredDependency[] = [];
    for (let i = 0; i < count; i++) {
        const appId = r.str();
        const mCount = r.u32();
        const measurements: string[] = [];
        for (let j = 0; j < mCount; j++) measurements.push(r.str());
        const oCount = r.u32();
        const requiredOids: DependencyOid[] = [];
        for (let j = 0; j < oCount; j++) {
            const oid = r.str();
            const valueHex = bytesToHex(r.bytes());
            requiredOids.push({ oid, valueHex });
        }
        const foldedIdentity = r.str();
        out.push({ appId, measurements, requiredOids, foldedIdentity });
    }
    if (!r.done) throw new Error('trailing bytes in dependency set');
    return out;
}

/**
 * Read the declared dependency set from a certificate's custom OIDs (the shape
 * the native RA-TLS module returns). Returns [] when the extension is absent.
 */
export function dependenciesFromCustomOids(
    customOids?: Array<{ oid: string; value_hex: string }>
): DeclaredDependency[] {
    const ext = customOids?.find((o) => o.oid === OID_ATTESTED_DEPENDENCY_SET);
    if (!ext?.value_hex) return [];
    try {
        return decodeDependencySet(hexToBytes(ext.value_hex));
    } catch {
        // A malformed extension is treated as "no declared dependencies" for
        // display; enforcement is the enclave's job, not the wallet's.
        return [];
    }
}

/**
 * The stable identity a user consents to for a dependency. Prefer the folded
 * identity (it transitively commits to the dependency's own subtree); fall back
 * to the canonical measurement + required-OID set for a leaf that declares no
 * folded identity. This is the second half of the (app-id, identity) cache key.
 */
export function dependencyIdentity(dep: DeclaredDependency): string {
    if (dep.foldedIdentity) return dep.foldedIdentity.toLowerCase();
    const ms = [...dep.measurements].sort().join(',');
    const os = [...dep.requiredOids]
        .map((o) => `${o.oid}=${o.valueHex}`)
        .sort()
        .join(',');
    return `leaf:${ms}|${os}`;
}
