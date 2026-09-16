// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * How a chained approval reports its decision to the approval that pushed it.
 *
 * The screen that pushed is re-focused rather than re-created, so there are no
 * params to read on the way back. This is the channel instead, and its rules
 * matter: a decision is consumed once, and the absence of one is not a wait.
 */

import {
    recordChainOutcome,
    resetChainOutcomes,
    takeChainOutcome,
} from '@/utils/capability-chain';

beforeEach(resetChainOutcomes);

it('reports a decision under its own nonce', () => {
    recordChainOutcome('nonce-a', 'approved');
    recordChainOutcome('nonce-b', 'denied');
    expect(takeChainOutcome('nonce-a')).toBe('approved');
    expect(takeChainOutcome('nonce-b')).toBe('denied');
});

// Consumed on read. A decision left behind could be picked up by a later
// approval and taken for a fresh one, which is the whole grant made silently.
it('yields a decision once', () => {
    recordChainOutcome('nonce-a', 'approved');
    expect(takeChainOutcome('nonce-a')).toBe('approved');
    expect(takeChainOutcome('nonce-a')).toBeUndefined();
});

// The caller reads this as a refusal, not as "still waiting": a holder who
// left without deciding has not approved anything.
it('has nothing to say about a nonce that never decided', () => {
    expect(takeChainOutcome('nonce-a')).toBeUndefined();
});

it('says nothing for an empty nonce, and never records one', () => {
    recordChainOutcome('', 'approved');
    expect(takeChainOutcome('')).toBeUndefined();
});
