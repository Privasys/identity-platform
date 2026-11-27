// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * The one message listener: only the page this frame serves may drive it,
 * and each message type goes to its handler.
 */

import { platformScopeOf } from '../platforms';
import type { PlatformScope, SessionKey } from '../session';
import { loadPlatforms, messageKey } from './page-scope';
import { onInit, onGateStart } from './ceremony';
import { onCheckSession, onRenewSession, onClearSession, onGetTokenForAudience } from './renewal';
import { onVoucherRequest, onSessionRequest, onSessionResume, onSessionStreamCancel, onSessionStreamRequest, onSessionWsOpen, onSessionWsSend, onSessionWsClose } from './sealed-bridge';

// The origin of the page this frame serves, fixed by its first message. A
// frame never changes pages without being reloaded.
let servedOrigin: string | null = null;

/**
 * Whether a message comes from the page this frame serves. Only that page may
 * drive the frame: any other window that can reach it (another frame on the
 * same page, through `parent.frames`) could otherwise act on the person's
 * session. The popups this frame opens answer on listeners of their own.
 */
export function fromServedPage(e: MessageEvent): boolean {
    if (window.parent === window || e.source !== window.parent) return false;
    if (servedOrigin === null) servedOrigin = e.origin;
    return e.origin === servedOrigin;
}

/** What every handler is given about the message it handles. */
export interface MessageContext {
    e: MessageEvent;
    data: any;
    /** The page's platform; null when it cannot be told. */
    pageScope: PlatformScope | null;
    /** The session the message names; null when it names none. */
    key: SessionKey | null;
}

const handlers: Record<string, (ctx: MessageContext) => Promise<void>> = {
    'privasys:init': onInit,
    'privasys:gate:start': onGateStart,
    'privasys:check-session': onCheckSession,
    'privasys:renew-session': onRenewSession,
    'privasys:clear-session': onClearSession,
    'privasys:get-token-for-audience': onGetTokenForAudience,
    'privasys:voucher-request': onVoucherRequest,
    'privasys:session:request': onSessionRequest,
    'privasys:session:resume': onSessionResume,
    'privasys:session:stream-cancel': onSessionStreamCancel,
    'privasys:session:stream-request': onSessionStreamRequest,
    'privasys:session:ws-open': onSessionWsOpen,
    'privasys:session:ws-send': onSessionWsSend,
    'privasys:session:ws-close': onSessionWsClose,
};

/** Listen for the served page's messages and hand each to its handler. */
export function startRouter(): void {
    window.addEventListener('message', async (e: MessageEvent) => {
        const data = e.data;
        if (!data || typeof data.type !== 'string' || !data.type.startsWith('privasys:')) return;
        if (!fromServedPage(e)) return;
        // The page's platform, from the origin the browser reports for it. A
        // platform that cannot be told matches no session.
        const list = await loadPlatforms();
        const pageScope = list ? platformScopeOf(list, e.origin) : null;
        // The session this message is about; an init names its client in its
        // config and builds its own below.
        const key = messageKey(pageScope, data);

        const handler = handlers[data.type];
        if (handler) await handler({ e, data, key, pageScope });
    });
}
