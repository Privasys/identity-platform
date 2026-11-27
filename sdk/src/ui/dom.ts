// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * DOM and device helpers for the gate.
 */

export function el(tag: string, attrs?: Record<string, any> | null, ...children: (Node | string | null | false)[]): HTMLElement {
    const e = document.createElement(tag);
    if (attrs != null) {
        for (const [k, v] of Object.entries(attrs)) {
            if (k === 'className') e.className = v as string;
            else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2).toLowerCase(), v as EventListener);
            else if (k === 'html') e.innerHTML = v as string;
            else if (v === false || v == null) { /* skip */ }
            else if (v === true) e.setAttribute(k, '');
            else e.setAttribute(k, String(v));
        }
    }
    for (const c of children.flat(Infinity) as (Node | string | null | false)[]) {
        if (c == null || c === false) continue;
        e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return e;
}

/** True on phones/tablets, where the wallet lives on THIS device and the
 *  QR is un-scannable (you cannot point a phone at its own screen). The
 *  ceremony then offers a direct wallet handoff instead. iPadOS 13+
 *  masquerades as macOS, hence the touch-point check. */
export function isMobileDevice(): boolean {
    if (typeof navigator === 'undefined') return false;
    const ua = navigator.userAgent || '';
    if (/iPhone|iPod|iPad|Windows Phone/i.test(ua)) return true;
    if (/Android/i.test(ua)) return true;
    return /Macintosh/.test(ua) && (navigator.maxTouchPoints ?? 0) > 1;
}

/** The wallet deep link as a custom-scheme URL. The QR payload is the
 *  universal link (https://privasys.id/scp?...), but iOS SUPPRESSES
 *  universal links on same-domain navigations — and this code runs in
 *  the privasys.id iframe, so the target IS same-domain. The custom
 *  scheme opens the app unconditionally (same fix as the IdP's /device
 *  page). The /scp route parses identical query params either way. */
export function walletSchemeUrl(qrPayload: string): string {
    return qrPayload.replace(/^https:\/\/privasys\.id\//, 'privasys-wallet://');
}
