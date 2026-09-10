// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The registry that stops repeat pushes stacking a list screen.
 *
 * Approving several vault operations in a row pushed one screen per
 * notification, so the holder ended with a pile of identical views, each saying
 * "nothing left to approve" when its turn came, and one back press needed per
 * approval to reach home (2026-09-10). The same hook file already carries a note
 * about an earlier duplicate-push bug, which is why this is pinned by a test
 * rather than left to a comment.
 *
 * The hook is a thin wrapper over these functions; what matters is the registry.
 */

// The module imports useFocusEffect purely for the hook, which these tests do
// not exercise. Mocked so the suite does not pull an ESM package through the
// transform, which fails on Windows for the same reason fido2.test.ts does.
jest.mock('@react-navigation/native', () => ({ useFocusEffect: jest.fn() }));

import {
    isRouteActive,
    markRouteActive,
    markRouteInactive,
    resetActiveRoutes,
} from '@/utils/active-route';

beforeEach(() => {
    resetActiveRoutes();
});

describe('isRouteActive', () => {
    it('is false for a screen that was never focused', () => {
        expect(isRouteActive('/vault-approvals')).toBe(false);
    });

    it('is true only while the screen is registered', () => {
        markRouteActive('/vault-approvals');
        expect(isRouteActive('/vault-approvals')).toBe(true);

        markRouteInactive('/vault-approvals');
        expect(isRouteActive('/vault-approvals')).toBe(false);
    });

    // One screen being up must not suppress a push meant for a different one.
    it('does not confuse one screen for another', () => {
        markRouteActive('/vault-approvals');
        expect(isRouteActive('/drive-requests')).toBe(false);
    });

    it('survives a screen being registered twice', () => {
        markRouteActive('/drive-requests');
        markRouteActive('/drive-requests');
        markRouteInactive('/drive-requests');
        // A set, so one deregistration is enough: a screen cannot be focused
        // twice, and leaving it "half active" would suppress pushes forever.
        expect(isRouteActive('/drive-requests')).toBe(false);
    });

    it('forgets everything on reset', () => {
        markRouteActive('/vault-approvals');
        markRouteActive('/drive-requests');
        resetActiveRoutes();
        expect(isRouteActive('/vault-approvals')).toBe(false);
        expect(isRouteActive('/drive-requests')).toBe(false);
    });
});
