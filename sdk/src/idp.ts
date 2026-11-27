// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * IdpGate: the gate for the identity provider's own pages, which approve
 * something rather than sign the page in. The frame refuses it from any
 * other origin.
 *
 *  - `deviceRequest`: approve, in the wallet, a sign-in another device
 *    started (RFC 8628), named by the code that device shows. The tokens go
 *    to the device.
 *  - `deviceSignIn`: approve the same request by signing in to the identity
 *    provider (a passkey or another method) as `clientId`. The sign-in's
 *    token stays in the frame.
 *  - `operationApproval`: approve one operation someone started elsewhere,
 *    in the wallet or with a passkey the page runs itself.
 *
 * `run()` resolves with `approved: true`, or with `approved: false` and the
 * outcome when the person declined or the approval failed; the gate then
 * stays on screen saying so. It rejects with a {@link ConnectError}.
 */

import { openGate, type GateRun } from './client/gate-frame';
import { ConnectError, type GateAppearance, type GateOutcome } from './client/types';

export { ConnectError } from './client/types';
export type { GateAppearance, GateOutcome } from './client/types';

export interface IdpGateConfig extends GateAppearance {
    deviceRequest?: { userCode: string };
    deviceSignIn?: { userCode: string; clientId: string; methods?: readonly ('wallet' | 'passkey' | 'social')[] };
    /**
     * The gate shows that the wallet was notified, the QR code that opens the
     * approval in the wallet (`walletLink`), and a passkey button that calls
     * `onPasskey` when given. It polls `statusUrl` (`{ status }`: `approved`,
     * `declined` or `gone`) and its decline button POSTs to `declineUrl`
     * (204 when recorded); both on the identity provider's origin.
     * `messages` is what the gate says when it ends each way.
     */
    operationApproval?: {
        walletLink: string;
        statusUrl: string;
        declineUrl: string;
        messages?: { approved?: string; declined?: string; expired?: string };
        onPasskey?: () => void;
    };
}

export class IdpGate {
    private readonly config: IdpGateConfig;
    private gate: GateRun | null = null;

    constructor(config: IdpGateConfig) {
        const kinds = [config.deviceRequest, config.deviceSignIn, config.operationApproval].filter(Boolean).length;
        if (kinds !== 1) throw new Error('IdpGate: give exactly one of deviceRequest, deviceSignIn, operationApproval');
        this.config = config;
    }

    async run(): Promise<{ approved: boolean; outcome?: GateOutcome }> {
        if (this.gate) throw new ConnectError('failed', 'IdpGate: already running');
        const c = this.config;
        const op = c.operationApproval;
        const container = c.container ?? null;
        this.gate = openGate({
            authOrigin: c.authOrigin ?? globalThis.location.origin,
            container,
            onPasskey: op?.onPasskey,
            config: {
                appName: c.appName,
                presentation: c.presentation ?? (container ? 'inline' : 'modal'),
                ...(c.pitch ? { pitch: c.pitch } : {}),
                ...(c.app ? { app: c.app } : {}),
                ...(c.theme ? { theme: c.theme } : {}),
                ...(c.legal === false ? { legal: false } : {}),
                ...(c.timeout ? { timeout: c.timeout } : {}),
                ...(c.brokerUrl ? { brokerUrl: c.brokerUrl } : {}),
                ...(c.deviceRequest ? { deviceRequest: { userCode: c.deviceRequest.userCode } } : {}),
                ...(c.deviceSignIn ? {
                    deviceSignIn: { userCode: c.deviceSignIn.userCode },
                    clientId: c.deviceSignIn.clientId,
                    ...(c.deviceSignIn.methods ? { methods: [...c.deviceSignIn.methods] } : {}),
                } : {}),
                // A function cannot cross into the frame: the frame only
                // learns that a passkey is offered.
                ...(op ? {
                    operationApproval: {
                        walletLink: op.walletLink,
                        statusUrl: op.statusUrl,
                        declineUrl: op.declineUrl,
                        messages: op.messages,
                        passkey: !!op.onPasskey,
                    },
                } : {}),
            },
        });
        try {
            const result = await this.gate.done;
            return { approved: result.approved === true, ...(result.outcome ? { outcome: result.outcome } : {}) };
        } catch (err) {
            if (err instanceof ConnectError) throw err;
            const msg = err instanceof Error ? err.message : String(err);
            if (msg === 'Authentication cancelled') throw new ConnectError('cancelled', msg);
            if (/timeout|timed out/i.test(msg)) throw new ConnectError('timeout', msg);
            throw new ConnectError('failed', msg);
        } finally {
            this.gate = null;
        }
    }

    /** Close the gate: `run()` rejects with 'cancelled' while it runs. */
    cancel(): void {
        this.gate?.cancel();
    }
}
