// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * The device popup: remembered wallets, read and written on this origin's
 * unpartitioned storage through a short popup.
 */

import { cleanDeviceLabel, deviceLabel, type DeviceHint } from '../session';
import { sessions } from './page-scope';

// ── The device popup ─────────────────────────────────────────────────────
//
// A browser gives this frame a separate storage on every site that embeds
// it, so on a site the person has never signed in to, the frame cannot tell
// that their phone is already known. A window on this origin that is NOT
// embedded sees one storage, the same whichever site opened it. So the phone
// is remembered there, and read through a short popup of this same page
// (DEVICE_POPUP_HASH), opened inside the click on the wallet button.
//
// The popup announces itself to the windows of this origin in its opener; the
// frame that is waiting answers with what it wants (read, or store this
// phone), the popup does it and closes. Every message is posted to this
// origin only, so the embedding page takes no part and learns nothing.
export const DEVICE_POPUP_HASH = '#device';
// The popup is this same frame page, wherever the identity provider serves it.
export const DEVICE_POPUP_URL = `${globalThis.location.origin}${globalThis.location.pathname}${DEVICE_POPUP_HASH}`;
export const DEVICE_POPUP_WAIT_MS = 5_000;
// Names of wallets the popup reported, kept so a wallet first used on this
// site is remembered here under the name it has everywhere else.
export const deviceLabels = new Map<string, string>();

export type DeviceAsk =
    | { op: 'read' }
    | { op: 'store'; pushToken: string; brokerUrl: string; label?: string }
    | { op: 'forget'; pushToken: string };
export type KnownDevice = { pushToken: string; brokerUrl: string; label: string };

/** A remembered wallet as the gate shows it. */
export function shown(d: DeviceHint): KnownDevice {
    return { pushToken: d.pushToken, brokerUrl: d.brokerUrl, label: deviceLabel(d) };
}

/**
 * Open the device popup and ask it one thing. `open` runs synchronously, so
 * a caller inside a click keeps the click's permission to open a window; it
 * resolves false when the popup could not open. Resolves the remembered
 * wallets for a read (none on any failure), and none for a store or a forget.
 */
export function askDevicePopup(open: () => boolean | Promise<boolean>, ask: DeviceAsk): Promise<KnownDevice[]> {
    return new Promise((resolve) => {
        const own = globalThis.location.origin;
        const id = Math.random().toString(36).slice(2);
        let done = false;
        const finish = (v: KnownDevice[]) => {
            if (done) return;
            done = true;
            window.removeEventListener('message', onMessage);
            clearTimeout(timer);
            resolve(v);
        };
        const onMessage = (ev: MessageEvent) => {
            if (ev.origin !== own || !ev.source || ev.source === window.parent) return;
            const d = ev.data;
            if (d?.type === 'privasys:device:hello') {
                (ev.source as Window).postMessage({ type: 'privasys:device:ask', id, ...ask }, own);
            } else if (d?.type === 'privasys:device:answer' && d.id === id) {
                const list: unknown[] = Array.isArray(d.devices) ? d.devices : [];
                finish(list.slice(0, 8).flatMap((h) => {
                    const k = h as Partial<KnownDevice> | null;
                    return k && typeof k.pushToken === 'string' && k.pushToken
                        ? [{
                            pushToken: k.pushToken,
                            brokerUrl: typeof k.brokerUrl === 'string' ? k.brokerUrl : '',
                            label: typeof k.label === 'string' && k.label ? k.label.slice(0, 80) : 'Phone',
                        }]
                        : [];
                }));
            }
        };
        window.addEventListener('message', onMessage);
        const timer = setTimeout(() => finish([]), DEVICE_POPUP_WAIT_MS);
        Promise.resolve(open()).then((opened) => { if (!opened) finish([]); }, () => finish([]));
    });
}

/** Opened as the device popup: do what the waiting frame asks, then close. */
export function runDevicePopup(): void {
    const own = globalThis.location.origin;
    window.addEventListener('message', (ev: MessageEvent) => {
        if (ev.origin !== own || !ev.source) return;
        const d = ev.data;
        if (d?.type !== 'privasys:device:ask' || typeof d.id !== 'string') return;
        let devices: KnownDevice[] = [];
        const token = typeof d.pushToken === 'string' && d.pushToken && d.pushToken.length <= 4096 ? d.pushToken : '';
        if (d.op === 'store') {
            if (token) {
                sessions.saveDeviceHint(token,
                    typeof d.brokerUrl === 'string' ? d.brokerUrl.slice(0, 512) : '',
                    cleanDeviceLabel(d.label));
            }
        } else if (d.op === 'forget') {
            if (token) sessions.forgetDevice(token);
        } else {
            devices = sessions.getDevices().map(shown);
        }
        (ev.source as Window).postMessage({ type: 'privasys:device:answer', id: d.id, devices }, own);
        window.close();
    });
    // The frame is the opener itself (a visible gate), or a frame inside it
    // (a headless page opened this window for its frame).
    const targets: Window[] = [];
    try {
        const opener = window.opener as Window | null;
        if (opener) {
            targets.push(opener);
            for (let i = 0; i < opener.length; i++) targets.push(opener[i] as unknown as Window);
        }
    } catch { /* an opener that cannot be walked: nothing to announce to */ }
    for (const t of targets) {
        try { t.postMessage({ type: 'privasys:device:hello' }, own); } catch { /* not ours */ }
    }
    // Nobody asked: do not leave an empty window behind.
    setTimeout(() => window.close(), DEVICE_POPUP_WAIT_MS);
}
