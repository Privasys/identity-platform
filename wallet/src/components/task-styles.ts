// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { StyleSheet } from 'react-native';

import type { Palette } from '@/components/Themed';

/**
 * The one look for a task: a screen that asks the holder to decide one thing
 * (an app's form, an app's approval, a list of vault operations).
 *
 * Shared because it drifted. The form and the approval screens each carried a
 * copy of these styles, and the first screen written without them (the vault
 * batch card) came out looking like another app: blue tiles, its own title
 * size, a footer of its own. A new task starts here and adds only what it has
 * that these do not.
 *
 * The parts, top to bottom:
 *  - `from` / `fromText` / `hostRow`: who is asking, and how the wallet knows;
 *  - `card`: what is being decided, with `title`, `lines` of `lineLabel` over
 *    `lineValue`, a `divider`, and `metaRow`s (an icon and a `meta` line) for
 *    the assurance and the time left; `cardDimmed` once it has expired;
 *  - `actions`: a `declineButton` beside a wider `affirmButton` (the buttons
 *    of components/AttestationView), `buttonIdle` for the one not pressed;
 *  - `note` under the buttons, `error` for a failure;
 *  - `refused` / `closed` for a request that cannot be answered, then a
 *    `doneButton`, or a `retryButton` beside a decline when trying again helps.
 *
 * Use it with the screen's own extras:
 *     const styles = useMemo(() => ({ ...taskStyles(p), ...makeStyles(p) }), [p]);
 */
export function taskStyles(p: Palette) {
    return StyleSheet.create({
        screen: { flex: 1, backgroundColor: p.screenBg },
        body: { padding: 20, gap: 14 },
        spinner: { marginTop: 40 },
        from: { gap: 4 },
        fromText: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
        hostRow: { flexDirection: 'row', alignItems: 'center', gap: 6, paddingVertical: 2 },
        card: { backgroundColor: p.card, borderRadius: 14, padding: 18, gap: 12, borderWidth: 1, borderColor: p.border },
        cardDimmed: { opacity: 0.55 },
        title: { fontSize: 18, fontWeight: '700', color: p.textPrimary },
        lines: { gap: 8 },
        line: { gap: 2 },
        lineLabel: { fontSize: 12.5, color: p.textSecondary },
        lineValue: { fontSize: 15, color: p.textPrimary },
        divider: { height: StyleSheet.hairlineWidth, backgroundColor: p.border },
        metaRow: { flexDirection: 'row', alignItems: 'center', gap: 8 },
        meta: { fontSize: 13, color: p.textSecondary, flexShrink: 1 },
        actions: { flexDirection: 'row', gap: 10 },
        declineButton: { flex: 1, paddingVertical: 15, borderRadius: 12, alignItems: 'center', backgroundColor: p.buttonNeutral },
        declineButtonText: { fontSize: 16, fontWeight: '600', color: p.textPrimary },
        affirmButton: { flex: 1.35, paddingVertical: 15, borderRadius: 12, alignItems: 'center', backgroundColor: p.green },
        affirmButtonText: { fontSize: 16, fontWeight: '600', color: p.onGreen },
        retryButton: { flex: 1.35, paddingVertical: 15, borderRadius: 12, alignItems: 'center', backgroundColor: p.action },
        buttonIdle: { opacity: 0.5 },
        // The Done of the other finished screens (device-add, verify-email).
        doneButton: { marginTop: 24, paddingVertical: 16, paddingHorizontal: 20, borderRadius: 14, alignItems: 'center', backgroundColor: p.action },
        doneButtonText: { fontSize: 16, fontWeight: '600', color: '#FFFFFF' },
        note: { fontSize: 12.5, lineHeight: 18, color: p.textMuted, textAlign: 'center' },
        error: { fontSize: 13.5, lineHeight: 19, color: p.danger, textAlign: 'center' },
        refused: { alignItems: 'center', gap: 12, paddingVertical: 24, paddingHorizontal: 8 },
        closed: { fontSize: 15, lineHeight: 21, color: p.textSecondary, textAlign: 'center' },
    });
}
