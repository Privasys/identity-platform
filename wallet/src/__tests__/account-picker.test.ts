// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Which account a sign-in uses, when one rpId carries several.
 *
 * This was decided entirely by registration order, and order got it wrong in
 * both directions on the same device: oldest-wins let a stale entry shadow a
 * freshly recovered account (2026-07-30), and newest-wins then handed every
 * ceremony to whichever account a later recovery happened to bind
 * (2026-09-04). Intent is not recoverable from a timestamp, so the holder can
 * now say. These tests pin the precedence and the ways a stale choice must not
 * survive.
 */

jest.mock('@/utils/storage', () => {
    const store: Record<string, string> = {};
    return {
        getItemAsync: jest.fn(async (key: string) => store[key] ?? null),
        setItemAsync: jest.fn(async (key: string, value: string) => {
            store[key] = value;
        }),
        deleteItemAsync: jest.fn(async (key: string) => {
            delete store[key];
        }),
    };
});

import { useAuthStore, type Credential } from '@/stores/auth';

const IDP = 'privasys.id';

const cred = (id: string, registeredAt: number, rpId = IDP): Credential => ({
    credentialId: id,
    rpId,
    origin: `https://${rpId}`,
    keyAlias: `alias-${id}`,
    userHandle: `handle-${id}`,
    registeredAt,
    userName: id,
    serverRpId: rpId,
});

// The real pair from the incident: the canonical account bound at 12:27 and
// the admin account rebound later the same day.
const CANONICAL = cred('canonical', 1000);
const ADMIN = cred('admin', 2000);

beforeEach(() => {
    useAuthStore.setState({ credentials: [], activeCredentialId: null });
});

describe('getCredentialForRp', () => {
    it('uses the newest registration when nobody has chosen', () => {
        useAuthStore.setState({ credentials: [CANONICAL, ADMIN] });
        expect(useAuthStore.getState().getCredentialForRp(IDP)?.credentialId).toBe('admin');
    });

    it('is unaffected by array order', () => {
        useAuthStore.setState({ credentials: [ADMIN, CANONICAL] });
        expect(useAuthStore.getState().getCredentialForRp(IDP)?.credentialId).toBe('admin');
    });

    // The point of the feature: an explicit choice beats the heuristic, even
    // when the chosen account is the older registration.
    it('honours the chosen account over the newest', () => {
        useAuthStore.setState({ credentials: [CANONICAL, ADMIN] });
        useAuthStore.getState().setActiveCredential('canonical');
        expect(useAuthStore.getState().getCredentialForRp(IDP)?.credentialId).toBe('canonical');
    });

    it('returns to newest-wins when the choice is cleared', () => {
        useAuthStore.setState({ credentials: [CANONICAL, ADMIN] });
        useAuthStore.getState().setActiveCredential('canonical');
        useAuthStore.getState().setActiveCredential(null);
        expect(useAuthStore.getState().getCredentialForRp(IDP)?.credentialId).toBe('admin');
    });

    // A pin naming a credential for a DIFFERENT rpId must not leak across:
    // every per-app passkey would otherwise be able to capture the IdP choice.
    it('ignores a choice belonging to another relying party', () => {
        const appCred = cred('app', 3000, 'drive.privasys.org');
        useAuthStore.setState({ credentials: [CANONICAL, ADMIN, appCred] });
        useAuthStore.getState().setActiveCredential('app');
        expect(useAuthStore.getState().getCredentialForRp(IDP)?.credentialId).toBe('admin');
        expect(useAuthStore.getState().getCredentialForRp('drive.privasys.org')?.credentialId).toBe('app');
    });

    it('has nothing to return for an rpId it holds no credential for', () => {
        useAuthStore.setState({ credentials: [CANONICAL] });
        expect(useAuthStore.getState().getCredentialForRp('unknown.example')).toBeUndefined();
    });
});

describe('a choice that can no longer be honoured', () => {
    // A dangling pin reads as a choice in the UI while behaving like no choice
    // at all, which is worse than either.
    it('is dropped when the chosen credential is removed', () => {
        useAuthStore.setState({ credentials: [CANONICAL, ADMIN] });
        useAuthStore.getState().setActiveCredential('canonical');
        useAuthStore.getState().removeCredential('canonical');

        expect(useAuthStore.getState().activeCredentialId).toBeNull();
        expect(useAuthStore.getState().getCredentialForRp(IDP)?.credentialId).toBe('admin');
    });

    it('survives the removal of a DIFFERENT credential', () => {
        useAuthStore.setState({ credentials: [CANONICAL, ADMIN] });
        useAuthStore.getState().setActiveCredential('canonical');
        useAuthStore.getState().removeCredential('admin');

        expect(useAuthStore.getState().activeCredentialId).toBe('canonical');
        expect(useAuthStore.getState().getCredentialForRp(IDP)?.credentialId).toBe('canonical');
    });

    it('is cleared by a wipe, along with everything else', () => {
        useAuthStore.setState({ credentials: [CANONICAL, ADMIN] });
        useAuthStore.getState().setActiveCredential('canonical');
        useAuthStore.getState().clearAll();

        expect(useAuthStore.getState().activeCredentialId).toBeNull();
        expect(useAuthStore.getState().credentials).toEqual([]);
    });
});
