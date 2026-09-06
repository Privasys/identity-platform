// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Resolving a Privasys app to the host you can dial and the identity you should
 * find there.
 *
 * The wallet has always resolved apps by NAME, with the name hardcoded per
 * service (`drive.ts`, `kyc.ts`). That is fine when the client already knows
 * which service it wants. It is the wrong way round for anything driven by what
 * an enclave presented: a capability request names its resource service, and
 * the wallet must resolve it without the requesting app being able to point the
 * wallet somewhere of its choosing.
 *
 * Hence S5 of the capability spec: **the resource service is resolved by
 * identity through the control plane, never from a URL in the request.** If the
 * request could name a host, the wallet would be a confused deputy, posting a
 * user-authenticated call wherever it was told.
 *
 * The management endpoint takes an app id or a name and is public by design:
 * it returns only publicly verifiable deployment facts.
 */

import { publicApiGet, appIdFromOids } from '@/services/release-provenance';
import type { AttestationResult } from '../../modules/native-ratls/src/NativeRaTls.types';

/** The public deployment facts the control plane will tell anyone. */
export interface ResolvedApp {
    /** Management app id, dashed UUID. The same value the enclave stamps on its
     *  RA-TLS leaf as OID 1.3.6.1.4.1.65230.4.1. */
    app_id?: string;
    name: string;
    display_name: string;
    hostname: string;
    /** Bare lowercase hex, no "sha256:" prefix. */
    image_digest: string;
    is_enclave: boolean;
    tee_type?: string;
    version?: number;
}

/**
 * Resolve by app id (preferred) or name. Returns null when the app is unknown,
 * undeployed, or the control plane cannot be reached.
 */
export async function resolveApp(ref: string, appHost?: string): Promise<ResolvedApp | null> {
    const trimmed = ref?.trim();
    if (!trimmed) return null;
    // Both spellings run the same handler and both accept an id or a name; the
    // by-id path is the one that exists for this flow.
    return publicApiGet<ResolvedApp>(
        `/api/v1/apps/${encodeURIComponent(trimmed)}/resolve`,
        appHost,
    );
}

/**
 * The check that makes resolution worth anything: the host we dialled must be
 * the app we asked for.
 *
 * Resolution is a control-plane claim. Attestation is the enclave's own proof.
 * Comparing them is what turns "the control plane says Drive is here" into
 * "the thing answering here IS Drive", and it is the reason the resolve
 * endpoint had to start returning the app id at all.
 *
 * Fails CLOSED: an attestation with no app id, or a resolution with none, is
 * not a match. Both are present on any deployed app, so absence means something
 * is wrong rather than something is old.
 */
export function attestationMatchesResolution(
    att: AttestationResult | null | undefined,
    resolved: ResolvedApp | null | undefined,
): boolean {
    if (!att || !resolved?.app_id) return false;
    const attested = appIdFromOids(att.custom_oids);
    if (!attested) return false;
    return attested.toLowerCase() === resolved.app_id.toLowerCase();
}
