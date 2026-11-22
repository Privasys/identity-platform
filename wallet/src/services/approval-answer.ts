// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Confirming and answering an approval (services/approval). Kept apart from
 * the parser so the stores that only read approvals do not load the native
 * modules this needs.
 *
 * Confirming is the form's check (services/app-form-answer): the app's own
 * host, the app id attested there, a verified attestation, and the app
 * confirming over that channel that it waits on this exact approval.
 *
 * Answering:
 *   1. the IdP begins, naming what it will bind; it must be exactly this
 *      approval, this act and this decision;
 *   2. a fresh biometric, never one reused from a moment ago (the signing
 *      key otherwise rides a recent unlock for up to a minute);
 *   3. the passkey signs; the IdP verifies (user verification required),
 *      takes the approval once, and returns the op-approval token;
 *   4. the token goes to the app's callback over a fresh attested channel to
 *      the same host.
 */

import * as LocalAuthentication from 'expo-local-authentication';
import { Platform } from 'react-native';

import {
    AnswerError,
    ANSWER_HOST,
    beginWithPlatformToken,
    bearerJson,
    confirmAppSource,
    sameApp,
    type ConfirmedSource,
} from '@/services/app-form-answer';
import { withPrompt } from '@/services/app-lock';
import { resolveStepUpCredential, type StepUpAssertionOptions } from '@/services/attribute-approval-api';
import { inspectAttestation } from '@/services/attestation';
import { demo, isDemo } from '@/services/demo/gate';
import { signVaultAssertion } from '@/services/fido2';
import { appIdFromOids } from '@/services/release-provenance';
import type { Approval, Decision } from '@/services/approval';
import { useAppLockStore } from '@/stores/app-lock';
import * as NativeKeys from '../../modules/native-keys/src/index';
import { makeRaTlsFetch } from '../../modules/native-ratls/src/index';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';
const IDP_ORIGIN = new URL(IDP_BASE).hostname;

/** Establish that the app named `appId`, at its own host, sent this approval. */
export function confirmApprovalSource(args: {
    approval: Approval;
    appId: string;
    appSlug?: string;
    platformHost?: string;
}): Promise<ConfirmedSource> {
    if (isDemo()) return demo().confirmSource(args);
    const { approval } = args;
    return confirmAppSource({
        ...args,
        confirmPath: `/.well-known/privasys/approval?id=${encodeURIComponent(approval.id)}&digest=${approval.digest}`,
        confirms: (body) => body.open === true && body.id === approval.id && body.approval_digest === approval.digest,
    });
}

/** A fresh biometric (or the phone's passcode where it has none), as vault
 *  approvals ask: the act is approved now, not by an unlock a minute ago. */
export async function freshBiometric(prompt: string, cancel: string): Promise<boolean> {
    const ok = await withPrompt(async () => {
        if (Platform.OS === 'ios') return NativeKeys.authenticateForSigning(prompt);
        const r = await LocalAuthentication.authenticateAsync({
            promptMessage: prompt,
            biometricsSecurityLevel: 'strong',
            cancelLabel: cancel,
        });
        return r.success;
    });
    // The holder was just verified: the app lock need not ask again.
    if (ok) useAppLockStore.getState().unlock();
    return ok;
}

/**
 * Answer an approval, to the host `confirmApprovalSource` verified. Resolves
 * once the app has accepted the answer.
 */
export async function answerApproval(args: {
    messageId: string;
    approval: Approval;
    appId: string;
    host: string;
    decision: Decision;
    prompt: string;
    cancel: string;
}): Promise<void> {
    const { messageId, approval, appId, host, decision } = args;
    if (approval.assurance !== 'device') throw new AnswerError('unverified', 'this approval needs a check this wallet cannot make yet');
    if (!ANSWER_HOST.test(host)) throw new AnswerError('not-the-app');
    const base = `${IDP_BASE}/wallet/approvals/${encodeURIComponent(messageId)}`;

    // 1. Begin: the IdP names what it will bind. It must be exactly this.
    const { res: beginRes, token } = await beginWithPlatformToken((t) =>
        fetch(`${base}/begin`, { method: 'POST', headers: bearerJson(t), body: JSON.stringify({ decision }) }),
    );
    const auth = bearerJson(token);
    if (beginRes.status === 404) throw new AnswerError('gone');
    if (!beginRes.ok) throw new AnswerError('unreachable', `begin failed (${beginRes.status})`);
    const begin = (await beginRes.json()) as {
        options: StepUpAssertionOptions;
        app_id: string;
        approval_id: string;
        approval_digest: string;
        act_digest: string;
        assurance: string;
        decision: string;
    };
    if (
        begin.approval_id !== approval.id ||
        begin.approval_digest !== approval.digest ||
        begin.act_digest !== approval.actDigest ||
        begin.assurance !== approval.assurance ||
        begin.decision !== decision ||
        !sameApp(begin.app_id, appId)
    ) {
        throw new AnswerError('mismatch');
    }

    // 2. A fresh biometric, then 3. the passkey.
    const credential = resolveStepUpCredential(begin.options);
    if (!credential) throw new AnswerError('no-passkey');
    if (!(await freshBiometric(args.prompt, args.cancel))) throw new AnswerError('cancelled');
    let assertion: Awaited<ReturnType<typeof signVaultAssertion>>;
    try {
        assertion = await signVaultAssertion(IDP_ORIGIN, credential.keyAlias, credential.credentialId, {
            ...begin.options.publicKey,
            rpId: begin.options.publicKey.rpId || credential.serverRpId,
        });
    } catch (e) {
        throw new AnswerError('cancelled', String(e));
    }
    const answerRes = await fetch(`${base}/answer`, {
        method: 'POST',
        headers: auth,
        body: JSON.stringify({ decision, assertion }),
    });
    if (answerRes.status === 404 || answerRes.status === 409) throw new AnswerError('gone');
    if (!answerRes.ok) throw new AnswerError('unreachable', `answer failed (${answerRes.status})`);
    const answered = (await answerRes.json()) as { token: string; app_id: string; app_platform_host: string };
    // The answer goes where the approval was confirmed, nowhere else.
    if (!sameApp(answered.app_id, appId) || answered.app_platform_host !== host) throw new AnswerError('mismatch');

    // 4. A fresh attested channel to the same host, the app id checked again.
    let attestedApp: string | undefined;
    try {
        attestedApp = appIdFromOids((await inspectAttestation(host)).custom_oids) ?? undefined;
    } catch {
        throw new AnswerError('unreachable', 'the app could not be reached');
    }
    if (!attestedApp || !sameApp(attestedApp, appId)) throw new AnswerError('not-the-app');
    const raFetch = makeRaTlsFetch({ enclaveHost: host, platformFetch: fetch });
    const res = await raFetch(`https://${host}${approval.callback}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approval_id: approval.id, decision, token: answered.token }),
    });
    if (!res.ok) throw new AnswerError('unreachable', `the app refused the answer (${res.status})`);
}
