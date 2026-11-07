/**
 * The headless gate: what the frame tells a page that renders its own
 * sign-in buttons, and what that page may ask the frame to start.
 *
 * The frame stays invisible. It still owns every credential and every
 * flow: Microsoft and Google open their popup on the identity provider's
 * origin, the wallet goes through the relay, and the page receives only
 * the token it receives from the visible gate. The page draws the buttons
 * in its own design system from {@link GateOptions}, starts a flow with a
 * {@link GateChoice}, and follows it through {@link GateState}.
 */

import type { OwnRegistration, SocialProvider } from './providers';

/** One of the platform's external identity providers, ready to draw. */
export interface GateProvider {
    id: SocialProvider;
    /** Brand-correct name for the label, e.g. "Microsoft". */
    name: string;
    /** The brand icon as inline SVG markup, sized by the page. */
    icon?: string;
}

/** The sign-in options for a client, as the frame offers them. */
export interface GateOptions {
    /** The client's own registrations, each a button of its own (an
     *  organisation's staff sign-in), with the organisation's name and the
     *  provider's brand icon; `iconUrl` when the organisation set one. */
    own: (OwnRegistration & { icon?: string })[];
    /** The platform's providers, in the adopter's order. */
    providers: GateProvider[];
    /** Whether a Privasys ID (wallet) sign-in is offered. */
    wallet: boolean;
    /** Whether this device holds a wallet push binding: a wallet sign-in
     *  then goes by notification, with the QR code as the alternative. */
    push: boolean;
}

/** What the page asks the frame to start. */
export type GateChoice =
    | { method: 'social'; provider: string; own?: boolean }
    | { method: 'wallet'; qr?: boolean };

/** Where a started sign-in is, for the page to narrate. */
export interface GateState {
    state: 'idle' | 'push-waiting' | 'qr-scanning' | 'wallet-connected' | 'authenticating'
        | 'approve-waiting' | 'passkey-requesting' | 'passkey-ceremony' | 'passkey-verifying' | 'success' | 'error';
    /** The wallet QR payload while `state` is `qr-scanning`. */
    qr?: string;
    /** The same QR code drawn as inline SVG, so the page needs no encoder. */
    qrSvg?: string;
    /** The message while `state` is `error`. */
    error?: string;
}

/** The page's handle on a headless gate. */
export interface GateControls {
    start(choice: GateChoice): void;
    cancel(): void;
}

/**
 * A choice as it arrives over postMessage, reduced to a well-formed one
 * or nothing. The gate still checks the choice against what it offers.
 */
export function sanitiseChoice(raw: unknown): GateChoice | null {
    if (!raw || typeof raw !== 'object') return null;
    const c = raw as Record<string, unknown>;
    if (c.method === 'wallet') return { method: 'wallet', ...(c.qr === true ? { qr: true } : {}) };
    if (c.method === 'social' && typeof c.provider === 'string' && /^[a-z]{1,32}$/.test(c.provider)) {
        return { method: 'social', provider: c.provider, ...(c.own === true ? { own: true } : {}) };
    }
    return null;
}

/**
 * The frame's state report, reduced to the fields a page may read. The
 * frame is a trusted origin, but the client still passes on only what the
 * contract names.
 */
export function sanitiseGateState(raw: unknown): GateState | null {
    if (!raw || typeof raw !== 'object') return null;
    const s = raw as Record<string, unknown>;
    const states: GateState['state'][] = ['idle', 'push-waiting', 'qr-scanning', 'wallet-connected', 'authenticating',
        'approve-waiting', 'passkey-requesting', 'passkey-ceremony', 'passkey-verifying', 'success', 'error'];
    if (typeof s.state !== 'string' || !(states as string[]).includes(s.state)) return null;
    const out: GateState = { state: s.state as GateState['state'] };
    if (typeof s.qr === 'string' && s.qr) out.qr = s.qr;
    if (typeof s.qrSvg === 'string' && s.qrSvg.startsWith('<svg')) out.qrSvg = s.qrSvg;
    if (typeof s.error === 'string' && s.error) out.error = s.error.slice(0, 300);
    return out;
}
