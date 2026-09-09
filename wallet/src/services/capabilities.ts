// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Capabilities: an attested app asking the holder for scoped, revocable
 * authority over a resource the holder owns.
 *
 * The wallet's job here is only ever four things: verify who is asking from
 * attestation rather than from the request, render what is being asked in plain
 * language, capture approve or deny, and bind a public key that was proved
 * inside the attested channel.
 *
 * Nothing here knows what a tenant, a folder or a vault key is. The resource
 * service does its own domain work from `request`, which the wallet forwards
 * verbatim and never interprets.
 *
 * Distinct from DataRequestConsent, which answers "what will this service LEARN
 * about me". This answers "what may this service DO to my data, until I revoke
 * it". Same device, different question.
 */

import { makeRaTlsFetch } from '../../modules/native-ratls/src/index';
import { getPlatformToken } from '@/services/platform-token';

/**
 * The closed permission vocabulary. The wallet renders only these and refuses
 * anything else, because an app that can author the words on the screen can
 * describe itself however it likes, and because prose supplied by a request
 * cannot be translated into the other 24 locales.
 */
export const PERMISSIONS = ['read', 'write', 'delete'] as const;
export type Permission = (typeof PERMISSIONS)[number];

/** The closed kind vocabulary. Each selects a wallet-owned explanation. */
export const CAPABILITY_KINDS = ['storage.folder'] as const;
export type CapabilityKind = (typeof CAPABILITY_KINDS)[number];

export interface CapabilityAsk {
    kind: CapabilityKind;
    permissions: Permission[];
    /** A value, never a format string: the wallet composes the sentence. */
    resource_label: string;
    /** Opaque to the wallet. Forwarded verbatim to the resource service, which
     *  must refuse anything in it that names an ownership boundary (S4). */
    request: Record<string, unknown>;
}

/** What the requesting app returns inside its attested channel. */
export interface PendingCapability {
    nonce: string;
    /** Base64 Ed25519. Proved HERE, in the attested response, never in the
     *  push: a key that rode the push could be anyone's while the identity on
     *  screen was genuine. */
    binding_pubkey: string;
    /** The resource service, named by identity so the WALLET resolves it. */
    resource_app: string;
    capability: CapabilityAsk;
}

export class CapabilityError extends Error {
    /** HTTP status of the refusing service, when the failure was an HTTP refusal. */
    status?: number;
    /** The service's machine-readable `code`, when its error body carried one. */
    code?: string;

    constructor(message: string, opts: { status?: number; code?: string } = {}) {
        super(message);
        this.status = opts.status;
        this.code = opts.code;
    }
}

/**
 * A resource service answering that the holder's own vault-held key is stale:
 * the service was upgraded (image or host) and this data owner has not yet
 * approved its new measurement for their key. Drive reports it as 409
 * `vault_key_stale`. It is the holder's key and the holder is right here, so
 * the wallet can approve in place, exactly as it does on a Drive login.
 */
export function isStaleTenantKey(e: unknown): e is CapabilityError {
    return e instanceof CapabilityError && e.status === 409 && e.code === 'vault_key_stale';
}

/** The `code` out of a JSON error body, or undefined for anything else. */
function errorCodeOf(body: string): string | undefined {
    try {
        const parsed = JSON.parse(body) as { code?: unknown };
        return typeof parsed.code === 'string' ? parsed.code : undefined;
    } catch {
        return undefined;
    }
}

function isPermission(v: unknown): v is Permission {
    return typeof v === 'string' && (PERMISSIONS as readonly string[]).includes(v);
}

/**
 * Validate a pending request. Refuses rather than repairs: every field here is
 * either something the wallet will show the holder or something it will act on,
 * and a request the wallet only half understands is one it cannot describe.
 */
export function parsePendingCapability(raw: unknown): PendingCapability {
    const o = raw as Record<string, unknown> | null;
    if (!o || typeof o !== 'object') throw new CapabilityError('malformed request');

    const nonce = typeof o['nonce'] === 'string' ? o['nonce'] : '';
    const key = typeof o['binding_pubkey'] === 'string' ? o['binding_pubkey'] : '';
    const resourceApp = typeof o['resource_app'] === 'string' ? o['resource_app'] : '';
    const cap = o['capability'] as Record<string, unknown> | undefined;
    if (!nonce) throw new CapabilityError('request has no nonce');
    if (!key) throw new CapabilityError('request carries no binding key');
    if (!resourceApp) throw new CapabilityError('request names no resource service');
    if (!cap || typeof cap !== 'object') throw new CapabilityError('request describes no capability');

    const kind = cap['kind'];
    if (typeof kind !== 'string' || !(CAPABILITY_KINDS as readonly string[]).includes(kind)) {
        // An unknown kind has no wallet-owned explanation, so there is no
        // honest screen to draw for it.
        throw new CapabilityError(`unsupported capability kind: ${String(kind)}`);
    }

    const perms = Array.isArray(cap['permissions']) ? cap['permissions'] : [];
    if (perms.length === 0) throw new CapabilityError('request asks for no permissions');
    if (!perms.every(isPermission)) {
        throw new CapabilityError('request asks for a permission the wallet cannot describe');
    }

    const label = typeof cap['resource_label'] === 'string' ? cap['resource_label'].trim() : '';
    if (!label) throw new CapabilityError('request names no resource');

    const request = cap['request'];
    return {
        nonce,
        binding_pubkey: key,
        resource_app: resourceApp,
        capability: {
            kind: kind as CapabilityKind,
            permissions: perms as Permission[],
            resource_label: label,
            request: (request && typeof request === 'object' ? request : {}) as Record<string, unknown>,
        },
    };
}

/**
 * Fetch the pending request from the REQUESTING app over RA-TLS. The push
 * carried only the nonce and where to fetch; everything that matters is learned
 * here, inside a channel whose far end the wallet has attested.
 */
export async function fetchPendingCapability(
    appHost: string,
    nonce: string,
): Promise<PendingCapability> {
    const raFetch = makeRaTlsFetch({ enclaveHost: appHost, platformFetch: fetch });
    const res = await raFetch(
        `https://${appHost}/.well-known/privasys/capability-request?nonce=${encodeURIComponent(nonce)}`,
    );
    if (!res.ok) {
        throw new CapabilityError(`the request could not be read (${res.status})`);
    }
    const parsed = parsePendingCapability(await res.json());
    // The nonce that comes back must be the one that was pushed, or the wallet
    // would be approving a request the holder was never shown.
    if (parsed.nonce !== nonce) {
        throw new CapabilityError('the request does not match the notification');
    }
    return parsed;
}

/** How long a capability of each kind may live. Chosen HERE, never by the
 *  requester, so nobody can ask for an unbounded one. */
const LIFETIME_SECONDS: Record<CapabilityKind, number> = {
    'storage.folder': 90 * 24 * 60 * 60,
};

export function expiryFor(kind: CapabilityKind, now = Date.now()): number {
    return Math.floor(now / 1000) + LIFETIME_SECONDS[kind];
}

export interface GrantedCapability {
    capability_id: string;
    expires_unix?: number;
    /** Opaque to the wallet; forwarded verbatim to the requesting app so it can
     *  address the resource service. Deliberately never interpreted here. */
    service_result?: Record<string, string>;
}

/**
 * Create the capability at the RESOURCE service, as the holder.
 *
 * `subjectAppId` is the id the wallet verified from the requesting app's
 * attestation, never a value out of the payload: a screen that echoes a
 * self-declared identity is a phishing surface, and on the data plane this
 * subject is matched against the attested peer.
 */
export async function createCapability(args: {
    resourceHost: string;
    subjectAppId: string;
    pending: PendingCapability;
    expiresUnix: number;
}): Promise<GrantedCapability> {
    const token = await getPlatformToken();
    const raFetch = makeRaTlsFetch({ enclaveHost: args.resourceHost, platformFetch: fetch });
    const res = await raFetch(`https://${args.resourceHost}/v1/capabilities`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({
            nonce: args.pending.nonce,
            subject_app_id: args.subjectAppId,
            binding_pubkey: args.pending.binding_pubkey,
            expires_unix: args.expiresUnix,
            // Exactly what was displayed, so the minted capability cannot be
            // wider than the one approved.
            permissions: args.pending.capability.permissions,
            kind: args.pending.capability.kind,
            request: args.pending.capability.request,
        }),
    });
    if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new CapabilityError(
            `the capability could not be created (${res.status})${body ? `: ${body.slice(0, 200)}` : ''}`,
            { status: res.status, code: errorCodeOf(body) },
        );
    }
    return (await res.json()) as GrantedCapability;
}

/**
 * Tell the requesting app the outcome, quoting the nonce. Deny is delivered
 * too, so the app can stop asking rather than re-prompting forever.
 *
 * Never carries a token or any credential of the holder's: the app receives the
 * outcome and the resource service's own opaque result, and nothing else.
 */
export async function deliverCapabilityOutcome(args: {
    appHost: string;
    nonce: string;
    status: 'approved' | 'denied';
    granted?: GrantedCapability;
}): Promise<void> {
    const raFetch = makeRaTlsFetch({ enclaveHost: args.appHost, platformFetch: fetch });
    const res = await raFetch(`https://${args.appHost}/.well-known/privasys/capability-result`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            nonce: args.nonce,
            status: args.status,
            capability_id: args.granted?.capability_id,
            service_result: args.granted?.service_result,
        }),
    });
    if (!res.ok) {
        throw new CapabilityError(`the app could not be told the outcome (${res.status})`);
    }
}
