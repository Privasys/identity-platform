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

/** The platform a page belongs to, as the identity provider's list places it. */
export interface PlatformScope {
    /** The platform audience of the page. */
    platform: string;
    /** The platform that claims every host no other one does. */
    defaultPlatform: string;
    /** Every platform audience the identity provider lists. */
    platforms: readonly string[];
}

/**
 * Which stored session a lookup is for: one client's session on one platform.
 * Pages of every platform under one registrable domain share this storage,
 * and two clients may share an rpId, so all three are needed to tell sessions
 * apart. The frame builds it from the page's origin and the client it names.
 */
export interface SessionKey {
    platform: string;
    rpId: string;
    clientId: string;
}

/** A string naming a session key, for maps and lock names. */
export function sessionKeyId(k: SessionKey): string {
    return `${k.platform}|${k.clientId}|${k.rpId}`;
}

function matches(s: AuthSession, k: SessionKey): boolean {
    return s.platform === k.platform && s.rpId === k.rpId && s.clientId === k.clientId;
}

/**
 * The sessions this origin holds, in localStorage, one per {@link SessionKey}.
 */
export class SessionManager {
    private listeners = new Set<SessionListener>();

    /** The session of a key, or undefined. */
    get(key: SessionKey): AuthSession | undefined {
        return this.getAll()
            .filter((s) => matches(s, key))
            .sort((a, b) => b.authenticatedAt - a.authenticatedAt)[0];
    }

    /** Store the session of a key, replacing the one it had. Throws when the
     *  key names no platform or client: a session nobody can find again would
     *  lose its refresh token. */
    store(key: SessionKey, session: AuthSession): void {
        if (!key.platform || !key.clientId || !key.rpId) {
            throw new Error('a session is stored for a platform, a client and an rpId');
        }
        const stored: AuthSession = { ...session, platform: key.platform, clientId: key.clientId, rpId: key.rpId };
        const sessions = this.getAll().filter((s) => !matches(s, key));
        sessions.push(stored);
        this.persist(sessions);
        this.notify(sessions);
    }

    /** Remove the session of a key (remembered wallets are kept). */
    remove(key: SessionKey): void {
        const sessions = this.getAll().filter((s) => !matches(s, key));
        this.persist(sessions);
        this.notify(sessions);
    }

    /** Every stored session. A record without its platform, client, rpId,
     *  scope or token is not a session this frame stored and is left out. */
    getAll(): AuthSession[] {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            const list: unknown = raw ? JSON.parse(raw) : [];
            if (!Array.isArray(list)) return [];
            return list.filter((s): s is AuthSession => !!s
                && typeof s.platform === 'string' && !!s.platform
                && typeof s.clientId === 'string' && !!s.clientId
                && typeof s.rpId === 'string' && !!s.rpId
                && typeof s.scope === 'string'
                && typeof s.token === 'string' && !!s.token);
        } catch {
            return [];
        }
    }

    /**
     * Find a push token from any stored session, falling back to the
     * persisted device hint. The push token is device-global, so a
     * token from any session can notify the wallet for another.
     */
    findPushToken(): string | undefined {
        const sessions = this.getAll()
            .filter((s) => !!s.pushToken)
            .sort((a, b) => b.authenticatedAt - a.authenticatedAt);
        if (sessions[0]?.pushToken) return sessions[0].pushToken;
        return this.getDeviceHint()?.pushToken;
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

    /** Every remembered wallet, the most recently used first. */
    getDevices(): DeviceHint[] {
        try {
            const raw = localStorage.getItem(HINTS_KEY);
            const list: unknown = raw ? JSON.parse(raw) : [];
            if (!Array.isArray(list)) return [];
            return (list as DeviceHint[])
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
