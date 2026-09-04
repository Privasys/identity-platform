// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * One spelling of a Privasys account id, whatever encoding it arrives in.
 *
 * The same account reaches the wallet in three different shapes, and until now
 * the Credentials screen printed whichever one it was handed:
 *
 *  - `credentials[].userHandle` is the WebAuthn user handle: base64url of the
 *    RAW BYTES, and those bytes are the ASCII of the account id. The canonical
 *    account therefore displayed as `TnpRMU1E…`.
 *  - `privasysId.userId` is the account id itself, `NzQ1MDQz…`, except on
 *    wallets old enough to have stored the raw 32-hex form, `7450432e…`.
 *  - Every other surface (the developer portal, the CLI, the `sub` claim) shows
 *    `NzQ1MDQz…`.
 *
 * So the one screen whose job is telling two accounts apart labelled them in an
 * encoding that matched nothing else. On 2026-09-04 that cost a round trip
 * while working out which account a device was actually bound to, on an issue
 * that was itself about being signed in as the wrong account.
 *
 * Everything here normalises to the `sub` spelling, because that is the one the
 * holder can compare against what a relying party shows them.
 */

import { bytesToBase64url, base64urlToBytes } from '@/utils/encoding';

/** 32 lowercase hex characters: the pre-encoding form of an account id. */
const RAW_HEX = /^[0-9a-f]{32}$/;

/** The base64url alphabet, at the length an account id decodes to. */
const SUB_SHAPED = /^[A-Za-z0-9_-]{40,48}$/;

/**
 * The value's bytes as text, or:
 *  - null when it decodes but the bytes are not printable ASCII (a per-app
 *    passkey's 32 random bytes), which is a definitive "not an account id";
 *  - undefined when it is not base64url at all.
 */
function decodeUtf8(value: string): string | null | undefined {
    let bytes: Uint8Array;
    try {
        bytes = base64urlToBytes(value);
    } catch {
        return undefined;
    }
    if (bytes.length === 0) return undefined;
    for (const byte of bytes) {
        if (byte < 0x20 || byte > 0x7e) return null;
    }
    return String.fromCharCode(...bytes);
}

/**
 * The account id in the spelling relying parties show, or undefined when the
 * value does not identify an account at all.
 */
export function accountId(value: string | undefined): string | undefined {
    const v = value?.trim();
    if (!v) return undefined;

    // Already the pre-encoding form: encode it the way the IdP publishes it.
    if (RAW_HEX.test(v)) return bytesToBase64url(new TextEncoder().encode(v));

    const decoded = decodeUtf8(v);
    // Non-printable bytes, or not base64url at all: the value is already as
    // resolved as it gets. A PAIRWISE account id is base64url of 32 RANDOM
    // bytes (only the canonical one encodes ASCII hex), so r2C7Km0L is a real
    // account id that decodes to nothing readable, and it is indistinguishable
    // from the random handle of a per-app passkey. Returning it unchanged is
    // right for the account and harmless for the passkey, whose row shows its
    // rpId rather than an account.
    if (decoded === null || decoded === undefined) return SUB_SHAPED.test(v) ? v : undefined;

    // Order matters. An account id is itself base64url and decodes to the
    // 32-hex form, so a value that decodes to hex was ALREADY the account id
    // and must come back unchanged rather than reduced to its hex.
    if (RAW_HEX.test(decoded)) return v;
    // A WebAuthn user handle: its bytes are the ASCII of the account id.
    if (SUB_SHAPED.test(decoded)) return decoded;
    return undefined;
}

/** A short, stable discriminator: the first characters of the account id. */
export function shortAccountId(value: string | undefined, length = 8): string | undefined {
    return accountId(value)?.slice(0, length);
}
