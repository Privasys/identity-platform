// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Checking and answering an app form (services/app-form). Kept apart from the
 * parser so the stores that only read forms do not load the native modules
 * this needs.
 *
 * Before a form is shown, the wallet establishes that the app itself sent it,
 * without trusting the platform for that:
 *   1. the host is exactly `<app name>.apps[.test].privasys.org`, the app's own
 *      platform hostname (never a custom domain, whose TLS may end at the
 *      gateway);
 *   2. the enclave there attests the app id the notification named;
 *   3. its attestation is verified through the attestation service, in the
 *      holder's chosen mode;
 *   4. inside that channel the app confirms it has this exact form open (by
 *      its reference and the SHA-256 of the form string).
 * Only then are the buttons offered, and the answer goes to that same host.
 */

import { attestEnclave, inspectAttestation, type AttestationResult } from '@/services/attestation';
import { resolveStepUpCredential, type StepUpAssertionOptions } from '@/services/attribute-approval-api';
import { getAttestationServerToken } from '@/services/app-attest';
import { signVaultAssertion } from '@/services/fido2';
import { getCachedPlatformToken } from '@/services/platform-token';
import { appIdFromOids } from '@/services/release-provenance';
import { useSettingsStore } from '@/stores/settings';
import type { AppForm } from '@/services/app-form';
import { makeRaTlsFetch } from '../../modules/native-ratls/src/index';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';
const IDP_ORIGIN = new URL(IDP_BASE).hostname;

/** Why a form could not be shown or answered, in terms the screen can explain. */
export type AnswerFailure =
    | 'signed-out' // no privasys.id session on this phone
    | 'no-passkey' // this phone holds no passkey for the identity
    | 'mismatch' // what the IdP would bind is not what the holder saw
    | 'gone' // already answered, expired, or not this holder's
    | 'not-the-app' // the host is not this app's own, or attests another app
    | 'unverified' // the app's attestation did not verify
    | 'not-confirmed' // the attested app does not have this form open
    | 'unreachable' // the app could not be reached or refused the answer
    | 'cancelled'; // the holder did not complete the biometric

export class AnswerError extends Error {
    constructor(readonly reason: AnswerFailure, message?: string) {
        super(message ?? reason);
    }
}

/**
 * An app's own platform hostname: one label under the platform's enclave
 * zones, no port. Not a custom domain, not a deeper name.
 */
export const ANSWER_HOST = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.apps(\.test)?\.privasys\.org$/;

/** Whether `host` is exactly the platform hostname of the app named `slug`. */
export function hostIsApp(host: string | undefined, slug: string | undefined): boolean {
    if (!host || !slug || !ANSWER_HOST.test(host)) return false;
    return host === `${slug}.apps.privasys.org` || host === `${slug}.apps.test.privasys.org`;
}

/** Normalise an app id to its dashless lowercase form, for comparing. */
export function sameApp(a: string, b: string): boolean {
    const n = (s: string) => s.toLowerCase().replace(/-/g, '');
    return !!a && !!b && n(a) === n(b);
}

/** What the screen shows once a form is confirmed, and links to. */
export interface ConfirmedSource {
    host: string;
    attestation: AttestationResult;
    mode: 'deterministic' | 'challenge';
    challenged: boolean;
}

/**
 * Establish that the app named `appId`, at its own host, sent this form.
 * Resolves with the verified attestation for the screen to offer, or throws an
 * AnswerError saying which step failed.
 */
export async function confirmFormSource(args: {
    form: AppForm;
    appId: string;
    appSlug?: string;
    platformHost?: string;
}): Promise<ConfirmedSource> {
    const { form } = args;
    return confirmAppSource({
        ...args,
        confirmPath: `/.well-known/privasys/app-form?id=${encodeURIComponent(form.id)}&digest=${form.digest}`,
        confirms: (body) => body.open === true && body.form_id === form.id && body.form_digest === form.digest,
    });
}

/**
 * Steps 1 to 4 for anything an app sends for an answer (a form, an
 * approval): its own host, the app id attested there, a verified attestation
 * in the holder's mode, and the app confirming over that channel, at
 * `confirmPath`, that it is waiting on this exact thing.
 */
export async function confirmAppSource(args: {
    appId: string;
    appSlug?: string;
    platformHost?: string;
    confirmPath: string;
    confirms: (body: Record<string, unknown>) => boolean;
}): Promise<ConfirmedSource> {
    const { appId, appSlug, platformHost, confirmPath, confirms } = args;
    const host = platformHost ?? '';
    // 1. The app's own host, built from its own name.
    if (!hostIsApp(host, appSlug)) throw new AnswerError('not-the-app');
    // 2. The enclave there is the app the notification named.
    let inspected: AttestationResult;
    try {
        inspected = await inspectAttestation(host);
    } catch {
        throw new AnswerError('unreachable', 'the app could not be reached');
    }
    if (!sameApp(appIdFromOids(inspected.custom_oids) ?? '', appId)) throw new AnswerError('not-the-app');
    // 3. Its attestation verifies, in the holder's mode.
    const mode = useSettingsStore.getState().verificationMode;
    const outcome = await attestEnclave(host, {
        tee: inspected.tee_type ?? 'tdx',
        mode,
        attestationServerToken: await getAttestationServerToken(),
    });
    if (outcome.status !== 'verified' || !outcome.result) throw new AnswerError('unverified', outcome.message);
    // 4. The app confirms, inside that channel, that it is waiting on this.
    const raFetch = makeRaTlsFetch({ enclaveHost: host, platformFetch: fetch });
    let res: Response;
    try {
        res = await raFetch(`https://${host}${confirmPath}`);
    } catch {
        throw new AnswerError('unreachable', 'the app could not be reached');
    }
    if (!res.ok) throw new AnswerError('not-confirmed', `the app is not waiting on this (${res.status})`);
    let body: Record<string, unknown>;
    try {
        body = await res.json();
    } catch {
        throw new AnswerError('not-confirmed');
    }
    if (!body || typeof body !== 'object' || !confirms(body)) {
        throw new AnswerError('not-confirmed');
    }
    return { host, attestation: { ...inspected, ...outcome.result }, mode, challenged: outcome.challenged };
}

/**
 * Answer a form with one of its actions, to the host `confirmFormSource`
 * verified. `messageId` is the IdP's id for the sent form; `form` is the form
 * as the holder saw it; `appId` the app that confirmed it. Resolves once the
 * app has accepted the answer.
 */
export async function answerForm(args: {
    messageId: string;
    form: AppForm;
    appId: string;
    host: string;
    action: string;
}): Promise<void> {
    const { messageId, form, appId, host, action } = args;
    if (!form.actions.some((a) => a.id === action)) throw new AnswerError('mismatch');
    if (!ANSWER_HOST.test(host)) throw new AnswerError('not-the-app');
    const token = await getCachedPlatformToken();
    if (!token) throw new AnswerError('signed-out');
    const auth = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
    const base = `${IDP_BASE}/wallet/app-forms/${encodeURIComponent(messageId)}`;

    // 1. Begin: the IdP names what it will bind. It must be exactly this form.
    const beginRes = await fetch(`${base}/begin`, { method: 'POST', headers: auth, body: JSON.stringify({ action }) });
    if (beginRes.status === 404) throw new AnswerError('gone');
    if (!beginRes.ok) throw new AnswerError('unreachable', `begin failed (${beginRes.status})`);
    const begin = (await beginRes.json()) as {
        options: StepUpAssertionOptions;
        app_id: string;
        form_id: string;
        form_digest: string;
        action: string;
    };
    if (
        begin.form_digest !== form.digest ||
        begin.form_id !== form.id ||
        begin.action !== action ||
        !sameApp(begin.app_id, appId)
    ) {
        throw new AnswerError('mismatch');
    }

    // 2. The holder signs, behind the biometric, with this identity's passkey.
    const credential = resolveStepUpCredential(begin.options);
    if (!credential) throw new AnswerError('no-passkey');
    let assertion: Awaited<ReturnType<typeof signVaultAssertion>>;
    try {
        assertion = await signVaultAssertion(IDP_ORIGIN, credential.keyAlias, credential.credentialId, {
            ...begin.options.publicKey,
            rpId: begin.options.publicKey.rpId || credential.serverRpId,
        });
    } catch (e) {
        throw new AnswerError('cancelled', String(e));
    }

    // 3. The IdP verifies, takes the form once, and signs the answer.
    const answerRes = await fetch(`${base}/answer`, { method: 'POST', headers: auth, body: JSON.stringify({ action, assertion }) });
    if (answerRes.status === 404 || answerRes.status === 409) throw new AnswerError('gone');
    if (!answerRes.ok) throw new AnswerError('unreachable', `answer failed (${answerRes.status})`);
    const answered = (await answerRes.json()) as { answer: string; app_id: string; app_platform_host: string };
    // The answer goes where the form was confirmed, and nowhere the IdP names
    // instead.
    if (!sameApp(answered.app_id, appId) || answered.app_platform_host !== host) throw new AnswerError('mismatch');

    // 4. Over a fresh attested channel to the same host: the app id there is
    //    checked again, since the enclave may have changed since the form was
    //    confirmed.
    let attestedApp: string | undefined;
    try {
        attestedApp = appIdFromOids((await inspectAttestation(host)).custom_oids) ?? undefined;
    } catch {
        throw new AnswerError('unreachable', 'the app could not be reached');
    }
    if (!attestedApp || !sameApp(attestedApp, appId)) throw new AnswerError('not-the-app');
    const raFetch = makeRaTlsFetch({ enclaveHost: host, platformFetch: fetch });
    const res = await raFetch(`https://${host}${form.callback}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ form_id: form.id, action, answer: answered.answer }),
    });
    if (!res.ok) throw new AnswerError('unreachable', `the app refused the answer (${res.status})`);
}
