// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What a chained approval screen decided, read by the screen that pushed it.
 *
 * A resource service may need an approval of its own before it can hold what
 * the holder is about to type: a mail connector keeps the mailbox credential in
 * a folder of the holder's Drive, and that folder is an ordinary capability ask
 * with its own nonce. The wallet runs it first, on the same stack, and then
 * returns to the main ask.
 *
 * The outcome has to travel back up. `router.back()` carries nothing, and the
 * screen that pushed is not re-created but re-focused, so there are no new
 * params to read either. A module-level map keyed by the nonce is the smallest
 * thing that survives the round trip: the nonce is single-use and unguessable,
 * and the entry is consumed on read so a stale one can never be mistaken for a
 * fresh decision.
 */

export type ChainOutcome = 'approved' | 'denied';

const outcomes = new Map<string, ChainOutcome>();

/** Called by the chained screen as it leaves. */
export function recordChainOutcome(nonce: string, outcome: ChainOutcome): void {
    if (!nonce) return;
    outcomes.set(nonce, outcome);
}

/**
 * The decision for this nonce, consumed. Undefined means no decision was made:
 * the holder left that screen without approving or denying, which the caller
 * must treat as a refusal rather than as "still waiting".
 */
export function takeChainOutcome(nonce: string): ChainOutcome | undefined {
    const out = outcomes.get(nonce);
    outcomes.delete(nonce);
    return out;
}

/** Test seam, and part of the wallet wipe's clean slate. */
export function resetChainOutcomes(): void {
    outcomes.clear();
}
