// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Sending an error report to Privasys support.
 *
 * The report itself is built by {@link buildErrorReport} and shown to the
 * holder in full before any of this runs: nothing is collected in the
 * background and nothing is sent that they have not read. This module only
 * carries it.
 *
 * There is no ticketing system yet, so the endpoint mails a fixed support
 * inbox. It takes no credential, deliberately, because a holder who cannot
 * sign in is exactly the holder with something to report. Every failure here
 * is recoverable by hand: the modal keeps its copy button, so a report that
 * cannot be sent can still be pasted into an email.
 */

import Constants from 'expo-constants';
import { Platform } from 'react-native';

const IDP_BASE_URL = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** Where the report goes. Shown to the holder before they send it. */
export const REPORT_INBOX = 'support@privasys.org';

const REPORT_URL = `${IDP_BASE_URL}/wallet/report`;
const TIMEOUT_MS = 20000;

/**
 * Why a send failed, so the modal can say something more useful than "it did
 * not work". `unavailable` and `rateLimited` are both answered by copying the
 * report by hand, which is what the wallet did before this endpoint existed.
 */
export type ReportFailure = 'unavailable' | 'rateLimited' | 'network' | 'failed';

export class ReportSendError extends Error {
    constructor(readonly reason: ReportFailure, message: string) {
        super(message);
        this.name = 'ReportSendError';
    }
}

export interface ReportSubmission {
    /** The report text, exactly as the holder saw it. */
    message: string;
    /** Optional contact address the holder typed. */
    contact?: string;
    /** Where in the app the report was raised, for triage. */
    context?: string;
}

/**
 * Forward a report to support. Resolves once the server has accepted it;
 * throws {@link ReportSendError} otherwise.
 */
export async function sendErrorReport(submission: ReportSubmission): Promise<void> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

    let res: Response;
    try {
        res = await fetch(REPORT_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: submission.message,
                contact: submission.contact?.trim() || undefined,
                context: submission.context,
                platform: Platform.OS,
                version: Constants.expoConfig?.version ?? 'unknown',
            }),
            signal: controller.signal,
        });
    } catch (e) {
        throw new ReportSendError('network', e instanceof Error ? e.message : String(e));
    } finally {
        clearTimeout(timer);
    }

    if (res.ok) return;

    // 503 means the server has no mailer configured, 429 that too many reports
    // have gone out recently. Neither is worth a retry, and both leave the
    // holder with a report they can still copy.
    const reason: ReportFailure =
        res.status === 503 ? 'unavailable' : res.status === 429 ? 'rateLimited' : 'failed';
    throw new ReportSendError(reason, `report endpoint returned ${res.status}`);
}
