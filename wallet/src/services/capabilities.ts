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
import {
    parseElicitation,
    parseSetupRequirement,
    SetupSchemaError,
    type SetupRequirement,
} from '@/services/capability-setup';
import { getPlatformToken } from '@/services/platform-token';
import { walletCallHeaders } from '@/services/wallet-call';

/**
 * The closed permission vocabulary. The wallet renders only these and refuses
 * anything else, because an app that can author the words on the screen can
 * describe itself however it likes, and because prose supplied by a request
 * cannot be translated into the other 24 locales.
 */
export const PERMISSIONS = ['read', 'write', 'delete'] as const;
export type Permission = (typeof PERMISSIONS)[number];

/**
 * The closed kind vocabulary. Each selects a wallet-owned explanation.
 *
 * A kind, not a permission verb, is what carries meaning here. That is why
 * turning on a provider's recording is its own kind rather than a fourth verb
 * on the transcript kind: reading what a meeting already produced and altering
 * how future meetings behave are different sentences, and a holder who agrees
 * to the first must not be taken to have agreed to the second.
 */
export const CAPABILITY_KINDS = [
    'storage.folder',
    'mail.mailbox',
    'calendar.events',
    'meeting.transcripts',
    'meeting.recording',
    // The holder's files at a cloud storage provider (a document library, a
    // personal drive elsewhere): read and searched on demand, with one folder
    // the service may write into. Distinct from storage.folder, which is the
    // holder's own Privasys Drive.
    'files.cloud',
    // The holder's files in the asking app's OWN storage, locked with a key the
    // wallet holds. Unlike every kind above, the resource service is the app
    // itself, reached at the `service_url` its ask names, and the wallet sends
    // the key with the mint.
    'app_storage',
] as const;
export type CapabilityKind = (typeof CAPABILITY_KINDS)[number];

/** Choices the asking app declares about a capability, rendered by the wallet. */
export interface CapabilityOptions {
    /**
     * The app works while the holder is away: it keeps a locked copy of the
     * folder key so it can carry on without the phone, until revoked. A real
     * difference in what is being agreed to, so it changes the screen's words.
     */
    unattended?: boolean;
}

export interface CapabilityAsk {
    kind: CapabilityKind;
    permissions: Permission[];
    /** A value, never a format string: the wallet composes the sentence. */
    resource_label: string;
    /** Opaque to the wallet. Forwarded verbatim to the resource service, which
     *  must refuse anything in it that names an ownership boundary (S4). */
    request: Record<string, unknown>;
    options: CapabilityOptions;
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
    /**
     * Where to mint, list and revoke, when the resource service is the asking
     * app itself rather than a service resolved from `resource_app`. Accepted
     * only on the host the wallet attested and read this ask from (see
     * fetchPendingCapability), so it cannot point a holder-authenticated call
     * anywhere else: the same guarantee S5 gives by resolving by identity.
     */
    service_url?: string;
    capability: CapabilityAsk;
    /**
     * What the resource service needs from the holder before this capability
     * can exist: approvals of its own, and values to be typed on the approval
     * screen. Absent when the holder is already set up, which is the common
     * case after the first grant.
     */
    setup?: SetupRequirement;
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

    // A setup block the wallet cannot draw is a refusal, not a form to skip:
    // minting without it would send the service an answer it never got.
    let setup: SetupRequirement | undefined;
    try {
        setup = parseSetupRequirement(o['setup']);
    } catch (e) {
        if (!(e instanceof SetupSchemaError)) throw e;
        throw new CapabilityError(e.message);
    }

    // Options change the words on the screen, so an option the wallet does not
    // understand is ignored rather than guessed at, and a known one must be the
    // right type: "unattended": "yes" is not a yes.
    const rawOptions = cap['options'] as Record<string, unknown> | undefined;
    const options: CapabilityOptions = {};
    if (rawOptions && typeof rawOptions === 'object' && rawOptions['unattended'] === true) {
        options.unattended = true;
    }

    const serviceUrl = parseServiceUrl(o['service_url']);

    const request = cap['request'];
    return {
        nonce,
        binding_pubkey: key,
        resource_app: resourceApp,
        service_url: serviceUrl,
        setup,
        capability: {
            kind: kind as CapabilityKind,
            permissions: perms as Permission[],
            resource_label: label,
            request: (request && typeof request === 'object' ? request : {}) as Record<string, unknown>,
            options,
        },
    };
}

/**
 * A `service_url` the wallet will dial, or a refusal. Absent is fine; present
 * and unusable is not, because an ask that names a service the wallet cannot
 * reach is an ask it cannot honour.
 */
function parseServiceUrl(raw: unknown): string | undefined {
    if (raw === undefined || raw === null || raw === '') return undefined;
    if (typeof raw !== 'string') throw new CapabilityError('request names its service in a form the wallet cannot use');
    let u: URL;
    try {
        u = new URL(raw);
    } catch {
        throw new CapabilityError('request names its service in a form the wallet cannot use');
    }
    // A user-authenticated call over anything but TLS is not one to make, and
    // credentials or a query in the URL have no business in a capability call.
    if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash) {
        throw new CapabilityError('request names its service in a form the wallet cannot use');
    }
    return `${u.origin}${u.pathname.replace(/\/+$/, '')}`;
}

/** The host a `service_url` points at, which must be the attested app host. */
export function serviceUrlHost(serviceUrl: string): string {
    return new URL(serviceUrl).host;
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
        throw new CapabilityError(`the request could not be read (${res.status})`, { status: res.status });
    }
    const parsed = parsePendingCapability(await res.json());
    // The nonce that comes back must be the one that was pushed, or the wallet
    // would be approving a request the holder was never shown.
    if (parsed.nonce !== nonce) {
        throw new CapabilityError('the request does not match the notification');
    }
    // A service_url is only acceptable on the host just attested and read from.
    // Anywhere else and the request would be choosing where the wallet posts a
    // holder-authenticated call, which is precisely what resolving by identity
    // (S5) exists to prevent. On the same host it is the attested app naming
    // its own storage, which it is entitled to do.
    if (parsed.service_url && serviceUrlHost(parsed.service_url) !== appHost) {
        throw new CapabilityError('the request names a service on a host other than the one that asked');
    }
    return parsed;
}

/** How long a capability of each kind may live. Chosen HERE, never by the
 *  requester, so nobody can ask for an unbounded one. */
const DAY = 24 * 60 * 60;
const LIFETIME_SECONDS: Record<CapabilityKind, number | null> = {
    'storage.folder': 90 * DAY,
    'mail.mailbox': 90 * DAY,
    'calendar.events': 90 * DAY,
    'meeting.transcripts': 90 * DAY,
    // Shorter deliberately. This one is a standing authority to change how
    // FUTURE meetings behave, not permission to read something that already
    // exists, so it should come back round for a fresh decision sooner.
    'meeting.recording': 30 * DAY,
    'files.cloud': 90 * DAY,
    // No expiry: it stands until revoked. An expiry here would not end the
    // app's access to anything the holder cares about; it would lock the
    // holder's own files away from the app they put them with, on a date they
    // never chose. Revocation is the way it ends.
    app_storage: null,
};

/**
 * When a capability of this kind ends, in epoch seconds, or 0 for one that
 * stands until revoked. 0 is also the wire value the service expects for that.
 */
export function expiryFor(kind: CapabilityKind, now = Date.now()): number {
    const lifetime = LIFETIME_SECONDS[kind];
    return lifetime === null ? 0 : Math.floor(now / 1000) + lifetime;
}

export interface GrantedCapability {
    capability_id: string;
    expires_unix?: number;
    /** Opaque to the wallet; forwarded verbatim to the requesting app so it can
     *  address the resource service. Deliberately never interpreted here. */
    service_result?: Record<string, string>;
    /**
     * Values the service asks THIS PHONE to hold for it, because it keeps
     * nothing at rest: a refresh token it exchanged, say. Kept beside the
     * holder's answers (services/setup-keep.ts) and sent back as `setup.kept`
     * on the next mint. Opaque here, never read, never logged.
     */
    keep?: Record<string, unknown>;
}

/**
 * The capabilities collection at a service: the `service_url` an ask named, or
 * the shared path on a host resolved by identity. Mint POSTs here, list GETs it,
 * revoke DELETEs `<this>/<id>`.
 */
export function capabilitiesUrl(resourceHost: string, serviceUrl?: string): string {
    return serviceUrl ?? `https://${resourceHost}/v1/capabilities`;
}

/**
 * The wallet-instance proof, for calls to a `service_url`.
 *
 * The enclave OS behind a `service_url` mints only for the wallet app itself,
 * proved per request. Signing that proof uses the biometric-gated device key,
 * so it prompts, and it is attached only where the service requires it and a
 * prompt makes sense: minting and revoking, each the holder's own deliberate
 * tap. Never to a list, which runs whenever a screen opens, and never to the
 * resolved services (Drive, the mail connector), which do not ask for it.
 *
 * Absent when the device has no usable attestation; the service then refuses
 * with its own sentence, which is the honest outcome.
 */
async function instanceProof(
    method: string,
    url: string,
    serviceUrl: string | undefined,
): Promise<Record<string, string>> {
    if (!serviceUrl) return {};
    return (await walletCallHeaders(method, new URL(url).pathname)) ?? {};
}

/**
 * The service's answer to a mint. Either the capability exists, or the service
 * has one more question for the holder before it can.
 */
export type MintOutcome =
    | { status: 'granted'; granted: GrantedCapability }
    | { status: 'incomplete'; requirement: SetupRequirement };

/**
 * The provider behind a resource service refused the setup details: a wrong
 * password, a mailbox that will not accept them. Not a wallet failure and not a
 * service failure, so the holder stays on the form, edits and retries.
 */
export function isProviderRefusal(e: unknown): e is CapabilityError {
    return e instanceof CapabilityError && e.status === 502;
}

/** The service's own sentence out of a 502 body, for the holder to read. */
function refusalMessage(body: string): string {
    try {
        const parsed = JSON.parse(body) as { error?: unknown };
        if (typeof parsed.error === 'string' && parsed.error.trim()) {
            return parsed.error.trim().slice(0, 300);
        }
    } catch {
        // Not JSON. Fall through: the holder gets the wallet's own wording
        // rather than a page of HTML.
    }
    return '';
}

/**
 * Create the capability at the RESOURCE service, as the holder.
 *
 * `subjectAppId` is the id the wallet verified from the requesting app's
 * attestation, never a value out of the payload: a screen that echoes a
 * self-declared identity is a phishing surface, and on the data plane this
 * subject is matched against the attested peer.
 *
 * `setup` carries what the holder typed on the approval screen. It goes to the
 * service and nowhere else: this is the only hop it makes, inside the attested
 * channel, and it is never logged here or held after the call returns.
 */
export async function createCapability(args: {
    resourceHost: string;
    subjectAppId: string;
    pending: PendingCapability;
    expiresUnix: number;
    setup?: Record<string, unknown>;
}): Promise<MintOutcome> {
    const token = await getPlatformToken();
    const url = capabilitiesUrl(args.resourceHost, args.pending.service_url);
    const raFetch = makeRaTlsFetch({ enclaveHost: args.resourceHost, platformFetch: fetch });
    const res = await raFetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
            ...(await instanceProof('POST', url, args.pending.service_url)),
        },
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
            setup: args.setup,
        }),
    });

    if (res.ok) {
        return { status: 'granted', granted: (await res.json()) as GrantedCapability };
    }

    const body = await res.text().catch(() => '');

    // 428: the service cannot finish from what it was given and says what else
    // it needs. A question, not a failure, so it does not go down the error
    // path and the holder does not see "access was not granted".
    if (res.status === 428) {
        try {
            return { status: 'incomplete', requirement: parseElicitation(JSON.parse(body)) };
        } catch (e) {
            throw new CapabilityError(
                e instanceof SetupSchemaError
                    ? e.message
                    : 'the service asked for more but did not say what',
                { status: 428 },
            );
        }
    }

    // 502: the provider refused the details themselves. Carry the service's own
    // sentence, which is the only party that knows why.
    if (res.status === 502) {
        throw new CapabilityError(refusalMessage(body), { status: 502 });
    }

    throw new CapabilityError(
        `the capability could not be created (${res.status})${body ? `: ${body.slice(0, 200)}` : ''}`,
        { status: res.status, code: errorCodeOf(body) },
    );
}

/** One capability as the resource service itself reports it. */
export interface HeldCapability {
    capability_id: string;
    kind?: string;
    permissions?: string[];
    resource_label?: string;
    subject_app_id?: string;
    created_unix?: number;
    expires_unix?: number;
    /** Holder folders only: the app keeps a locked copy of the key. */
    unattended?: boolean;
}

/**
 * What the resource service says the holder currently has with it.
 *
 * Returns null, distinctly from an empty list, when the service does not serve
 * this route. That difference is the whole point: an empty list means "you have
 * nothing here", and a missing route means "this service cannot be asked from
 * the wallet", and showing the first when the second is true would tell the
 * holder their access had gone when it had not.
 *
 * It also gates revocation. A DELETE returning 404 from a service that serves
 * the list means the capability really is not held; the same 404 from a service
 * that does not serve it means only that the route is absent.
 */
export async function listCapabilities(
    resourceHost: string,
    serviceUrl?: string,
): Promise<HeldCapability[] | null> {
    const token = await getPlatformToken();
    const raFetch = makeRaTlsFetch({ enclaveHost: resourceHost, platformFetch: fetch });
    // Bearer only, deliberately: this runs whenever a detail screen opens, and
    // a Face ID prompt to LOOK at your own grants would be hostile.
    const res = await raFetch(capabilitiesUrl(resourceHost, serviceUrl), {
        headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 404 || res.status === 405) return null;
    if (!res.ok) {
        throw new CapabilityError(`the service could not be asked (${res.status})`, {
            status: res.status,
        });
    }
    const body = (await res.json()) as { capabilities?: unknown };
    const list = Array.isArray(body?.capabilities) ? body.capabilities : [];
    return list.filter(
        (c): c is HeldCapability =>
            !!c && typeof c === 'object' && typeof (c as HeldCapability).capability_id === 'string',
    );
}

/**
 * Ask the resource service to revoke, as the holder.
 *
 * The wallet does not enforce anything. This carries the holder's instruction
 * over the same attested channel that minted the capability, and the caller
 * records the revocation only once this returns, never on the strength of the
 * tap alone.
 *
 * A service that sealed setup values for this capability drops them here too: a
 * credential kept after the grant that justified it is gone is a credential
 * nobody authorised.
 */
export async function revokeCapability(
    resourceHost: string,
    capabilityId: string,
    serviceUrl?: string,
): Promise<void> {
    const token = await getPlatformToken();
    const raFetch = makeRaTlsFetch({ enclaveHost: resourceHost, platformFetch: fetch });
    const url = `${capabilitiesUrl(resourceHost, serviceUrl)}/${encodeURIComponent(capabilityId)}`;
    const res = await raFetch(url, {
        method: 'DELETE',
        headers: {
            Authorization: `Bearer ${token}`,
            ...(await instanceProof('DELETE', url, serviceUrl)),
        },
    });
    // 410 is the service saying it was already gone, which is the outcome the
    // holder asked for. 404 is not: from a service that serves the list it
    // means the same thing, and the caller checks that before calling.
    if (res.ok || res.status === 410 || res.status === 404) return;
    const body = await res.text().catch(() => '');
    throw new CapabilityError(
        `the service refused to revoke (${res.status})${body ? `: ${body.slice(0, 200)}` : ''}`,
        { status: res.status, code: errorCodeOf(body) },
    );
}

/**
 * The capabilities collection the enclave OS serves on EVERY app host, under a
 * prefix the manager reserves for itself, so an app's own code cannot answer
 * on it. Holder folders mint here; for every other kind it is where the
 * calling app's record of a grant is kept.
 */
export const APP_CAPABILITIES_PATH = '/__privasys/v1/capabilities';

export function appCapabilitiesUrl(appHost: string): string {
    return `https://${appHost}${APP_CAPABILITIES_PATH}`;
}

/**
 * Tell the app that ASKED that the holder revoked, after the resource service
 * has confirmed it.
 *
 * Revoking at the resource service ends the access. It does not tell the app
 * that asked for it, which keeps its own record of the approval and goes on
 * saying "approved" (the harness did exactly that). The enclave OS on the
 * calling app's host drops that record for any kind and tells the app.
 *
 * Only after the resource service has confirmed, never instead of it: telling
 * an app "revoked" while its access still stands would be wrong the other way.
 * Skipped when the calling app IS the resource service, as for a holder
 * folder, where the one DELETE already did both. A grant from before the
 * runtime recorded subjects answers 404, which is fine: there is nothing there
 * to drop.
 *
 * Carries the wallet-instance proof, so it prompts. Never throws: the holder's
 * access is already gone, and a failure here is the app's view lagging, which
 * is logged rather than put in front of them.
 */
export async function revokeAtCallingApp(args: {
    callingAppId: string;
    capabilityId: string;
    resourceHost: string;
    resolve: (appId: string) => Promise<{ hostname?: string } | null>;
}): Promise<'told' | 'same-host' | 'skipped'> {
    try {
        const caller = await args.resolve(args.callingAppId);
        if (!caller?.hostname) return 'skipped';
        if (caller.hostname === args.resourceHost) return 'same-host';
        await revokeCapability(caller.hostname, args.capabilityId, appCapabilitiesUrl(caller.hostname));
        return 'told';
    } catch (e) {
        console.warn(
            `[CAPABILITY] revoked, but the calling app could not be told: ${e instanceof Error ? e.message : String(e)}`,
        );
        return 'skipped';
    }
}

/**
 * A holder folder cannot be closed while its files are in use. Nothing was
 * revoked and nothing is wrong: the holder tries again in a moment, and the
 * screen says that rather than showing a status code.
 */
export function isFolderBusy(e: unknown): e is CapabilityError {
    return e instanceof CapabilityError && e.status === 409 && e.code !== 'vault_key_stale';
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
