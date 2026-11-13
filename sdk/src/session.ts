// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

import type { AuthSession } from './types';

/** localStorage key for the session list. Exported so the frame-host
 *  can watch cross-document `storage` events for renewals performed in
 *  sibling iframes/tabs. */
export const SESSIONS_STORAGE_KEY = 'privasys_sessions';
const STORAGE_KEY = SESSIONS_STORAGE_KEY;
const HINTS_KEY = 'privasys_device_hints';
const PASSKEY_HINT_KEY = 'privasys_passkey';
/** More remembered wallets than this and the oldest is dropped. */
const MAX_DEVICES = 8;

/**
 * A wallet this browser remembers, so a returning person gets a notification
 * instead of a QR code. Persists across session expiry and sign-out. Several
 * can be remembered: two people on one computer, or one person's two phones.
 */
export interface DeviceHint {
    pushToken: string;
    brokerUrl: string;
    /** When it was last used here; the most recent leads. */
    updatedAt: number;
    /** When it was first remembered. */
    addedAt?: number;
    /** The name the wallet gave for it, when it gave one. */
    label?: string;
}

/** A wallet's name for its phone, as text of at most 80 characters, or nothing. */
export function cleanDeviceLabel(raw: unknown): string | undefined {
    if (typeof raw !== 'string') return undefined;
    // Holder-supplied text: no control characters, one line.
    const label = raw.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, 80);
    return label || undefined;
}

/** What to call a remembered wallet on the gate. */
export function deviceLabel(d: Pick<DeviceHint, 'label' | 'addedAt' | 'updatedAt'>): string {
    if (d.label) return d.label;
    const added = new Date(d.addedAt ?? d.updatedAt);
    return `Phone added ${added.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })}`;
}

type SessionListener = (sessions: AuthSession[]) => void;

/**
 * Manages authenticated sessions in localStorage.
 * Tracks sessions per rpId so a returning user can skip QR scanning.
 */
export class SessionManager {
    private listeners = new Set<SessionListener>();
    // The client every lookup is for, once a page has named one (forClient).
    private clientId: string | null = null;

    /**
     * Limit lookups to one client's sessions. Sessions are kept per rpId AND
     * client: two apps that share an rpId each have their own, and a page
     * speaking for one client is never given, and never replaces, a session
     * minted for another. A page that names no client (an older client
     * script) gets the most recent session for the rpId, as before.
     */
    forClient(clientId: string | null): void {
        this.clientId = clientId || null;
    }

    private mine(s: AuthSession, rpId: string): boolean {
        return s.rpId === rpId && (this.clientId === null || s.clientId === this.clientId);
    }

    /** Store a new session after successful authentication. */
    store(session: AuthSession): void {
        const sessions = this.getAll();
        // Replace the existing session for the same rpId and client
        const idx = sessions.findIndex((s) => s.rpId === session.rpId && (s.clientId ?? '') === (session.clientId ?? ''));
        if (idx >= 0) sessions[idx] = session;
        else sessions.push(session);
        this.persist(sessions);
        this.notify(sessions);
    }

    /** Get the session for a specific RP (and the named client), or undefined if none. */
    get(rpId: string): AuthSession | undefined {
        return this.getAll()
            .filter((s) => this.mine(s, rpId))
            .sort((a, b) => b.authenticatedAt - a.authenticatedAt)[0];
    }

    /** Get all stored sessions. */
    getAll(): AuthSession[] {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return [];
            return JSON.parse(raw) as AuthSession[];
        } catch {
            return [];
        }
    }

    /** Check if a session exists for an RP. */
    has(rpId: string): boolean {
        return this.get(rpId) !== undefined;
    }

    /**
     * Find a push token from any stored session, falling back to the
     * persisted device hint. The push token is device-global, so a
     * token from any rpId can notify the wallet for a different rpId.
     */
    findPushToken(): string | undefined {
        const sessions = this.getAll()
            .filter((s) => !!s.pushToken)
            .sort((a, b) => b.authenticatedAt - a.authenticatedAt);
        if (sessions[0]?.pushToken) return sessions[0].pushToken;
        return this.getDeviceHint()?.pushToken;
    }

    /** Remove a session by rpId (device hint is kept). */
    remove(rpId: string): void {
        const sessions = this.getAll().filter((s) => !this.mine(s, rpId));
        this.persist(sessions);
        this.notify(sessions);
    }

    /** Remove all sessions. */
    clear(): void {
        localStorage.removeItem(STORAGE_KEY);
        this.notify([]);
    }

    /** Subscribe to session changes. Returns an unsubscribe function. */
    subscribe(listener: SessionListener): () => void {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }

    // ── Device hints (survive session expiry) ─────────────────────────

    /** Every remembered wallet, the most recently used first. A single hint
     *  stored by an older version reads as a list of one. */
    getDevices(): DeviceHint[] {
        try {
            const raw = localStorage.getItem(HINTS_KEY);
            if (!raw) return [];
            const parsed = JSON.parse(raw) as DeviceHint | DeviceHint[];
            const list = Array.isArray(parsed) ? parsed : [parsed];
            return list
                .filter((d) => d && typeof d.pushToken === 'string' && d.pushToken)
                .sort((a, b) => (b.updatedAt ?? 0) - (a.updatedAt ?? 0));
        } catch {
            return [];
        }
    }

    private putDevices(devices: DeviceHint[]): void {
        try {
            if (devices.length) localStorage.setItem(HINTS_KEY, JSON.stringify(devices.slice(0, MAX_DEVICES)));
            else localStorage.removeItem(HINTS_KEY);
        } catch { /* storage full or unavailable */ }
    }

    /** Remember a wallet, or mark a remembered one as just used. Its label
     *  and first date are kept unless a new label is given. */
    saveDeviceHint(pushToken: string, brokerUrl: string, label?: string): void {
        const now = Date.now();
        const devices = this.getDevices();
        const known = devices.find((d) => d.pushToken === pushToken);
        const hint: DeviceHint = {
            pushToken,
            brokerUrl: brokerUrl || known?.brokerUrl || '',
            updatedAt: now,
            addedAt: known?.addedAt ?? known?.updatedAt ?? now,
            ...((label || known?.label) ? { label: (label || known?.label)!.slice(0, 80) } : {}),
        };
        this.putDevices([hint, ...devices.filter((d) => d.pushToken !== pushToken)]);
    }

    /** The most recently used remembered wallet, if any. */
    getDeviceHint(): DeviceHint | undefined {
        return this.getDevices()[0];
    }

    /** Forget one remembered wallet. */
    forgetDevice(pushToken: string): void {
        this.putDevices(this.getDevices().filter((d) => d.pushToken !== pushToken));
    }

    /** Forget every remembered wallet. */
    clearDeviceHint(): void {
        localStorage.removeItem(HINTS_KEY);
    }

    // ── Passkey hints (survive session expiry & sign-out) ─────────────

    /** Record that a discoverable passkey exists for this RP. */
    savePasskeyHint(): void {
        try {
            localStorage.setItem(PASSKEY_HINT_KEY, '1');
        } catch { /* storage full or unavailable */ }
    }

    /** Check if a discoverable passkey was previously registered. */
    hasPasskeyHint(): boolean {
        try {
            return localStorage.getItem(PASSKEY_HINT_KEY) === '1';
        } catch {
            return false;
        }
    }

    private persist(sessions: AuthSession[]): void {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(sessions));
    }

    private notify(sessions: AuthSession[]): void {
        for (const listener of this.listeners) {
            listener(sessions);
        }
    }
}
