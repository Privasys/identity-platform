// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { isAppLockSeconds, isTabPath, lockExempt, locksOnReturn, promptOpen, withPrompt } from '@/services/app-lock';

describe('locksOnReturn', () => {
    const away = 1_000_000;
    it('never locks while the lock is off', () => {
        expect(locksOnReturn(null, away, away + 3_600_000)).toBe(false);
    });
    it('does not lock a wallet that never went to the background', () => {
        expect(locksOnReturn(0, null, away)).toBe(false);
    });
    it('locks on every return when set to always', () => {
        expect(locksOnReturn(0, away, away)).toBe(true);
    });
    it('waits for the time chosen', () => {
        expect(locksOnReturn(60, away, away + 59_999)).toBe(false);
        expect(locksOnReturn(60, away, away + 60_000)).toBe(true);
        expect(locksOnReturn(300, away, away + 120_000)).toBe(false);
    });
});

describe('lockExempt', () => {
    it.each(['/vault-approvals', '/vault-approvals?batch_id=abc', '/approval', '/approval?id=1'])('opens %s without the unlock', (path) => {
        expect(lockExempt(path)).toBe(true);
    });
    it.each(['/', '/access', '/settings', '/connect', '/drive', '/personal-data', '/approvals-history', '/vault-approvalsx'])(
        'keeps %s behind the lock',
        (path) => {
            expect(lockExempt(path)).toBe(false);
        },
    );
});

describe('the one-time question', () => {
    it('is asked on a tab only', () => {
        expect(['/', '/access', '/settings'].every(isTabPath)).toBe(true);
        expect(['/secure-wallet', '/connect', '/app-lock', '/vault-approvals'].some(isTabPath)).toBe(false);
    });
});

describe('isAppLockSeconds', () => {
    it('takes only the offered choices', () => {
        expect([0, 60, 300].every(isAppLockSeconds)).toBe(true);
        expect([30, -1, '60', null, undefined].some(isAppLockSeconds)).toBe(false);
    });
});

describe('withPrompt', () => {
    it('holds the cover down while the prompt is open, and after a failure lets it go', async () => {
        expect(promptOpen()).toBe(false);
        let seen = false;
        await withPrompt(async () => {
            seen = promptOpen();
        });
        expect(seen).toBe(true);
        expect(promptOpen()).toBe(false);
        await expect(withPrompt(async () => Promise.reject(new Error('cancelled')))).rejects.toThrow('cancelled');
        expect(promptOpen()).toBe(false);
    });
});
