// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Answering an app form (services/app-form): begin at the IdP, sign with the
 * identity's passkey, take the answer token, and hand it to the attested app.
 * Kept apart from the parser so the stores that only read forms do not load
 * the native modules this needs.
 */

import { inspectAttestation } from '@/services/attestation';
import { resolveStepUpCredential, type StepUpAssertionOptions } from '@/services/attribute-approval-api';
import { signVaultAssertion } from '@/services/fido2';
import { getCachedPlatformToken } from '@/services/platform-token';
import { appIdFromOids } from '@/services/release-provenance';
import { makeRaTlsFetch } from '../../modules/native-ratls/src/index';
import type { AppForm } from '@/services/app-form';


const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';
const IDP_ORIGIN = new URL(IDP_BASE).hostname;

/** Why an answer did not reach the app, in terms the screen can explain. */
export type AnswerFailure =
    | 'signed-out' // no privasys.id session on this phone
    | 'no-passkey' // this phone holds no passkey for the identity
    | 'mismatch' // what the IdP would bind is not what the holder saw
    | 'gone' // already answered, expired, or not this holder's
    | 'not-the-app' // the attested host is not the app that asked
    | 'unreachable' // the app could not be reached or refused the answer
    | 'cancelled'; // the holder did not complete the biometric

export class AnswerError extends Error {
    constructor(readonly reason: AnswerFailure, message?: string) {
        super(message ?? reason);
    }
}

/** Normalise an app id to its dashless lowercase form, for comparing. */
function sameApp(a: string, b: string): boolean {
    const n = (s: string) => s.toLowerCase().replace(/-/g, '');
    return !!a && !!b && n(a) === n(b);
}

/**
 * Answer a form with one of its actions. `messageId` is the IdP's id for the
 * sent form; `form` is the form as the holder saw it; `appId` the app the
 * platform says sent it. Resolves once the app has accepted the answer.
 */
export async function answerForm(args: {
    messageId: string;
    form: AppForm;
    appId: string;
    action: string;
}): Promise<void> {
    const { messageId, form, appId, action } = args;
    if (!form.actions.some((a) => a.id === action)) throw new AnswerError('mismatch');
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
    if (!sameApp(answered.app_id, appId) || !answered.app_platform_host) throw new AnswerError('mismatch');

    // 4. Attest the app's own host and check it is the app that asked, then
    //    hand it the answer inside that channel.
    const host = answered.app_platform_host;
    let attestedApp: string | undefined;
    try {
        attestedApp = appIdFromOids((await inspectAttestation(host)).custom_oids) ?? undefined;
    } catch {
        throw new AnswerError('unreachable', 'the app could not be attested');
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
