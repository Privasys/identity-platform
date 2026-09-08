// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Per-app session traces — the audit trail behind the Home screen.
 *
 * A trace is recorded every time the user is asked to authenticate against
 * something: an OIDC client sign-in, a direct enclave connection, a sealed
 * session-relay ceremony, a one-shot device-authorization approval, a KYC
 * identity check, a vault-operation approval. Traces are keyed by the APP the
 * user authenticated to (`serviceKey` = OIDC client_id when present), not by
 * the FIDO2 rpId — every IdP-brokered client shares the `privasys.id` rpId, so
 * rpId-keyed rows collapse "Privasys Chat", "Developer Platform", … into one
 * confusing card. The trusted-apps store keeps its rpId/appHost keying (it is
 * about enclave attestation continuity, not app identity); Home renders one
 * card per serviceKey and the service-detail page lists that app's traces.
 *
 * Each trace snapshots what the user actually shared: the requested attribute
 * keys, the approved/denied split, the VALUES as sent at that moment (gov
 * attributes are enclave-signed proofs — the raw value never leaves the
 * device, so only the proof marker is recorded), and the enclave attestations
 * verified during the ceremony.
 */

import { create } from 'zustand';

import * as SecureStore from '@/utils/storage';

const STORE_KEY = 'privasys.service-sessions.v1';

/** Keep the trail bounded; oldest traces fall off. */
const MAX_TRACES = 400;

/**
 * And bounded PER APP, which the global cap does not do.
 *
 * One app used daily accumulates a row per ceremony, so the service-detail
 * trail grew without limit: 33 entries for a single service, in a card the
 * holder has to scroll past to reach anything below it. The global cap of 400
 * only stops the store as a whole from growing, and would let one busy app
 * crowd out every other app's history entirely.
 *
 * Ten is what a person can actually read, and the trail answers "what has this
 * app been doing lately" rather than "everything it has ever done".
 */
const MAX_TRACES_PER_SERVICE = 10;

/**
 * Keep the newest MAX_TRACES_PER_SERVICE for each service. Input must be
 * newest-first, which is how the store holds it, so this is a single pass and
 * preserves order.
 */
function capPerService(traces: SessionTrace[]): SessionTrace[] {
    const seen = new Map<string, number>();
    const kept: SessionTrace[] = [];
    for (const t of traces) {
        const n = seen.get(t.serviceKey) ?? 0;
        if (n >= MAX_TRACES_PER_SERVICE) continue;
        seen.set(t.serviceKey, n + 1);
        kept.push(t);
    }
    return kept;
}

export type SessionKind =
    | 'sign-in' // plain OIDC / passkey sign-in (no enclave, no sealed relay)
    | 'enclave' // direct sign-in to an attested enclave app
    | 'relayed' // sealed session-relay (a browser rides the sealed transport)
    | 'device-auth' // one-shot delegated sign-in (CLI / agent device flow)
    | 'identity-check' // KYC verification against the identity-verifier enclave
    | 'approval'; // one-shot operation approval (e.g. vault promote/export)

export type IdentityKind = 'privasys-id' | 'external-idp' | 'passkey';

export type TeeType = 'sgx' | 'tdx' | 'sev-snp' | 'nvidia-gpu' | 'none';

/** One attribute as it was shared in a ceremony. */
export interface SharedAttributeTrace {
    key: string;
    /** Raw value as sent. Absent for gov proofs — the raw value never left. */
    value?: string;
    /** Shared as an enclave-signed disclosure proof, not the raw value. */
    gov?: boolean;
}

/** Snapshot of one enclave attestation verified during a ceremony. */
export interface AttestationTrace {
    host: string;
    teeType: TeeType;
    mrenclave?: string;
    mrtd?: string;
    codeHash?: string;
    configRoot?: string;
    imageRef?: string;
    quoteStatus?: string;
    /** Management-service app id (from OID 4.1), for release-provenance lookups. */
    appId?: string;
    /** Epoch ms of the verification. */
    verifiedAt: number;
}

/** One authentication ceremony (the user was asked to authenticate). */
export interface SessionTrace {
    id: string;
    /** Card identity: clientId > (session-relay appHost) > appName@rpId > rpId. */
    serviceKey: string;
    /** Human app label at the time (e.g. "Privasys Chat"). */
    displayName?: string;
    kind: SessionKind;
    identity: IdentityKind;
    clientId?: string;
    rpId: string;
    origin: string;
    appHost?: string;
    /** How the request reached the wallet. */
    channel?: 'qr' | 'push';
    /** UNVERIFIED agent label for device-auth delegations. */
    requestedBy?: string;
    /** Epoch ms the ceremony completed. */
    startedAt: number;
    /** Epoch ms a resulting sealed session expires (relayed only). */
    expiresAt?: number;
    /** The ceremony handed over a token and completed (no ongoing session). */
    oneShot?: boolean;
    /** Free-form context, e.g. the approved vault operation summary. */
    detail?: string;
    requestedAttributes?: string[];
    sharedAttributes?: SharedAttributeTrace[];
    deniedAttributes?: string[];
    /** Enclaves verified in this ceremony (primary + companions). */
    attestations?: AttestationTrace[];
    /** Sealed relay session id, when one was bootstrapped. */
    sessionId?: string;
}

/**
 * The stable per-app key. Mirrors the consent key (client identity first) and
 * falls back to the attested enclave host for non-OIDC enclave connections.
 */
export function serviceKeyFor(p: {
    clientId?: string;
    appHost?: string;
    rpId: string;
    appName?: string;
    mode?: string;
}): string {
    if (p.clientId) return p.clientId;
    if (p.mode === 'session-relay' && p.appHost) return p.appHost;
    if (p.appName) return `${p.appName}@${p.rpId}`;
    return p.rpId;
}

interface ServiceSessionsState {
    traces: SessionTrace[];

    /** Record a completed ceremony; returns the trace id. */
    record: (trace: Omit<SessionTrace, 'id'>) => string;
    /** Append a verified enclave to an existing trace (multi-app ceremonies). */
    attachAttestation: (traceId: string, att: AttestationTrace) => void;
    /** Drop every trace for a service (user removed the app). */
    removeService: (serviceKey: string) => void;
    /** Drop every trace. Part of the wallet wipe — see services/wipe.ts. */
    clearAll: () => void;
    hydrate: () => Promise<void>;
}

export const useServiceSessionsStore = create<ServiceSessionsState>((set, get) => ({
    traces: [],

    record: (trace) => {
        const id = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
        set((s) => ({
            traces: capPerService([{ ...trace, id }, ...s.traces]).slice(0, MAX_TRACES),
        }));
        persist(get());
        return id;
    },

    attachAttestation: (traceId, att) => {
        set((s) => ({
            traces: s.traces.map((t) =>
                t.id === traceId ? { ...t, attestations: [...(t.attestations ?? []), att] } : t
            )
        }));
        persist(get());
    },

    removeService: (serviceKey) => {
        set((s) => ({ traces: s.traces.filter((t) => t.serviceKey !== serviceKey) }));
        persist(get());
    },

    clearAll: () => {
        set({ traces: [] });
        persist(get());
    },

    hydrate: async () => {
        const raw = await SecureStore.getItemAsync(STORE_KEY);
        if (!raw) return;
        try {
            const data = JSON.parse(raw);
            const loaded = Array.isArray(data?.traces) ? (data.traces as SessionTrace[]) : [];
            // Trim on load as well as on write, so a wallet that already holds
            // an unbounded trail is tidied on its next launch rather than
            // staying long until each app happens to be used again.
            const traces = capPerService(loaded);
            set({ traces });
            if (traces.length !== loaded.length) persist(get());
        } catch {
            // Corrupted data — start fresh.
        }
    }
}));

function persist(state: ServiceSessionsState) {
    SecureStore.setItemAsync(STORE_KEY, JSON.stringify({ traces: state.traces })).catch(
        console.error
    );
}

/** Every host a service's traces touched — used to match live relay sessions
 *  and legacy (rpId-keyed) trusted-app rows to a service card. */
export function serviceHosts(traces: SessionTrace[]): Set<string> {
    const hosts = new Set<string>();
    for (const t of traces) {
        hosts.add(t.serviceKey);
        // Include rpId ONLY for a plain passkey RP (where the rpId IS the app
        // identity, so serviceKey === rpId). For an IdP-brokered app the rpId is
        // the SHARED privasys.id RP — adding it here would link every unrelated
        // app together, so signing into one (e.g. chat) would absorb another's
        // card (e.g. the Developer Platform).
        if (t.rpId && t.rpId === t.serviceKey) hosts.add(t.rpId);
        if (t.appHost) hosts.add(t.appHost);
        for (const a of t.attestations ?? []) hosts.add(a.host);
    }
    return hosts;
}

/**
 * Translation KEYS for the per-kind label, not the labels themselves.
 *
 * A zustand store has no React context and so no `t`; resolving here would
 * freeze the English string into state and survive a language change. Screens
 * call `t(KIND_LABEL_KEYS[kind])` at render instead.
 */
export const KIND_LABEL_KEYS: Record<SessionKind, string> = {
    'sign-in': 'sessionKind.signIn',
    enclave: 'sessionKind.enclave',
    relayed: 'sessionKind.relayed',
    'device-auth': 'sessionKind.deviceAuth',
    'identity-check': 'sessionKind.identityCheck',
    approval: 'sessionKind.approval'
};

/** Translation keys for the identity type. See KIND_LABEL_KEYS. */
export const IDENTITY_LABEL_KEYS: Record<IdentityKind, string> = {
    'privasys-id': 'identityKind.privasysId',
    'external-idp': 'identityKind.externalIdp',
    passkey: 'identityKind.passkey'
};
