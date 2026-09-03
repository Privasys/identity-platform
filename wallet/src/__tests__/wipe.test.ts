// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * "Clear All Data" must actually clear all data.
 *
 * The wipe used to be a hand-written list of store calls inside the Profile
 * screen's Alert handler, and it had fallen behind the wallet: sessions,
 * session traces, consent history, dependency approvals, Drive share requests,
 * the first-connect flag, the recovery-phrase acknowledgement, the KYC records,
 * the Wallet Instance Attestation, the platform token and the
 * notification-sealing key all survived it (2026-08-26).
 *
 * Two tests guard it. The behavioural one fills every store, wipes, and asserts
 * they are empty. The source-level one greps the tree for SecureStore keys and
 * fails when one appears that `wipe.ts` does not account for — so the next
 * feature to persist something cannot quietly reintroduce the bug.
 */

const storage: Record<string, string> = {};

jest.mock('@/utils/storage', () => ({
    getItemAsync: jest.fn(async (key: string) => storage[key] ?? null),
    setItemAsync: jest.fn(async (key: string, value: string) => {
        storage[key] = value;
    }),
    deleteItemAsync: jest.fn(async (key: string) => {
        delete storage[key];
    }),
}));

// The wipe pulls in kyc.ts, wia.ts and platform-token.ts, which reach through
// to native modules at import time. Only their clear functions matter here, so
// stub each to delete the key it owns — which is exactly the contract wipe.ts
// relies on.
jest.mock('@/services/kyc', () => ({
    clearKycRecords: jest.fn(async () => {
        delete storage['privasys.kyc.records'];
    }),
}));
jest.mock('@/services/wia', () => ({
    clearWia: jest.fn(async () => {
        delete storage['privasys.wia'];
    }),
}));
jest.mock('@/services/platform-token', () => ({
    clearPlatformToken: jest.fn(async () => {
        delete storage['privasys.platform-token'];
    }),
}));

// Hardware keys live outside SecureStore, so they get their own ledger.
const mockHardwareKeys = new Set<string>();
jest.mock('../../modules/native-keys/src/index', () => ({
    deleteKey: jest.fn(async (alias: string) => {
        mockHardwareKeys.delete(alias);
    }),
    sign: jest.fn(),
    generateKey: jest.fn(),
    getPublicKey: jest.fn(),
    keyExists: jest.fn(async () => true),
}));

// sovereign.ts is exercised for real (it owns two of the keys the wipe must
// clear), so give it the same test-only randomness sovereign.test.ts uses.
jest.mock('expo-crypto', () => ({
    getRandomBytes: jest.fn((n: number) => new Uint8Array(n)),
    getRandomBytesAsync: jest.fn(async (n: number) => new Uint8Array(n)),
}));

// The vault-approvals store holds nothing on disk (its pendings expire
// server-side in minutes), so it is out of scope for a storage wipe. It is
// stubbed rather than loaded because its API client drags in the FIDO2 stack
// and, through it, the whole React Native runtime.
jest.mock('@/stores/vaultApprovals', () => {
    const state = { knownOps: [] as string[], pending: [] as unknown[], clearAll: jest.fn() };
    return { useVaultApprovalsStore: { getState: () => state } };
});

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { wipeWallet } from '@/services/wipe';
import { useAuthStore } from '@/stores/auth';
import { useConsentStore } from '@/stores/consent';
import { useDependencyApprovalsStore } from '@/stores/dependency-approvals';
import { useDriveNotificationsStore } from '@/stores/drive-notifications';
import { useProfileStore } from '@/stores/profile';
import { useServiceSessionsStore } from '@/stores/service-sessions';
import { useSessionsStore } from '@/stores/sessions';
import { useSettingsStore } from '@/stores/settings';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

describe('wipeWallet', () => {
    it('empties every store the wallet persists', async () => {
        useAuthStore.getState().setOnboarded();
        useAuthStore.getState().addCredential({
            credentialId: 'cred-1',
            rpId: 'privasys.id',
            keyAlias: 'alias-1',
            userHandle: 'user-1',
            createdAt: 1,
        } as never);
        useAuthStore.getState().setRecoveryPhraseSaved(true);
        useProfileStore.getState().createProfile({
            displayName: 'Test',
            email: '',
            avatarUri: '',
            locale: 'en-GB',
            did: 'did:key:zTest',
            canonicalDid: 'did:web:privasys.id:u:test',
            pairwiseSeed: 'ff'.repeat(32),
            linkedProviders: [],
            attributes: [],
        } as never);
        useTrustedAppsStore.getState().addOrUpdate({
            rpId: 'app.example.org',
            teeType: 'tdx',
            credentialId: 'cred-1',
        } as never);
        useSessionsStore.getState().add({
            sessionId: 'sess-1',
            expiresAt: Date.now() + 600_000,
        } as never);
        useServiceSessionsStore.getState().record({
            serviceKey: 'app.example.org',
            kind: 'connect',
            at: 1,
        } as never);
        useConsentStore.getState().addRecord({ id: 'rec-1', rpId: 'app.example.org' } as never);
        useDependencyApprovalsStore.getState().record({
            appId: 'confidential-ai',
            identity: 'tdx:11',
            decision: 'approved',
            parentRpId: 'app.example.org',
        });
        useDriveNotificationsStore.getState().addRequest(
            { requestId: 'req-1', requesterSub: 'sub-1', nodeId: 'n1', nodeName: 'f', scope: [] } as never,
            {},
        );
        useSettingsStore.getState().setSeenFirstConnect(true);
        mockHardwareKeys.add('privasys-wallet-default');
        mockHardwareKeys.add('alias-1');

        await wipeWallet();

        expect(useAuthStore.getState().credentials).toEqual([]);
        expect(useAuthStore.getState().isOnboarded).toBe(false);
        expect(useAuthStore.getState().privasysId).toBeNull();
        // The nudge that sends a cleared wallet back through the recovery-phrase
        // step. Leaving this true is what made a wiped wallet claim the phrase
        // was already saved.
        expect(useAuthStore.getState().recoveryPhraseSaved).toBe(false);
        expect(useProfileStore.getState().profile).toBeNull();
        expect(useTrustedAppsStore.getState().apps).toEqual([]);
        expect(useSessionsStore.getState().sessions).toEqual([]);
        expect(useServiceSessionsStore.getState().traces).toEqual([]);
        expect(useConsentStore.getState().records).toEqual([]);
        expect(useDependencyApprovalsStore.getState().list()).toEqual([]);
        expect(useDriveNotificationsStore.getState().requests).toEqual([]);
        expect(useDriveNotificationsStore.getState().subjects).toEqual({});
        // The explainer must play again for the first connection of the next
        // identity on this device.
        expect(useSettingsStore.getState().seenFirstConnect).toBe(false);

        // The device signing key and every credential's key. This is the ONLY
        // action allowed to delete them, so a wipe that left them behind would
        // hand the next identity a key it never generated: on one tester's
        // iPhone an inherited key the hardware had retired made the identity
        // verifier permanently unreachable, and the device key's public half
        // travels in the WIA, linking two identities on one phone.
        expect([...mockHardwareKeys]).toEqual([]);
    });

    it('leaves nothing behind in secure storage', async () => {
        storage['privasys.kyc.records'] = '[{"jti":"kyc-1"}]';
        storage['privasys.wia'] = '{"jwt":"x"}';
        storage['privasys.platform-token'] = '{"token":"x"}';
        storage['v1-notify-seal-key'] = 'sealkey';
        storage['privasys.recovery-state'] = '{"requestId":"r"}';

        await wipeWallet();

        for (const key of Object.keys(storage)) {
            // Stores persist an empty shape rather than deleting their key;
            // what matters is that nothing still holds identity data.
            expect(storage[key]).not.toMatch(/kyc-1|sealkey|"jwt"|"token"|requestId/);
        }
        expect(storage['privasys.kyc.records']).toBeUndefined();
        expect(storage['privasys.wia']).toBeUndefined();
        expect(storage['privasys.platform-token']).toBeUndefined();
        expect(storage['v1-notify-seal-key']).toBeUndefined();
        expect(storage['privasys.recovery-state']).toBeUndefined();
    });
});

/**
 * Every SecureStore key in the tree must be accounted for by the wipe.
 *
 * `wipe.ts` clears stores through their `clearAll()` and services through their
 * own clear functions, so this cannot compare key strings directly. What it can
 * check is ownership: a module that both DECLARES a storage key and writes to
 * it must be imported by the wipe, or be on the documented keep-list. A module
 * that writes under a key declared elsewhere (the recovery screen, which takes
 * RECOVERY_STATE_KEY from services/recovery-api) is covered through the module
 * that owns the key.
 *
 * So a new persisted key in a new file fails this test until someone decides
 * whether it should survive a wipe.
 */
describe('wipe coverage', () => {
    /** Files whose persisted state deliberately survives a wipe. */
    const EXEMPT = new Set([
        // Names the hardware, not the person; the push token beside it is
        // device-scoped and a wipe does not change it either.
        'src/hooks/useDeviceUuid.ts',
        // A cache of allowed values for profile attributes. No personal data.
        'src/services/value-sets.ts',
        // The minimum-supported-version verdict. It describes the BUILD, not the
        // person, so it is not the user's to erase; and clearing it would let a
        // wipe lift a required-update wall on a device that is offline, which is
        // the one bypass the gate exists to close.
        'src/services/app-version.ts',
        // The generic SecureStore/localStorage shim itself.
        'src/utils/storage.ts',
    ]);

    function sourceFiles(dir: string, out: string[] = []): string[] {
        for (const entry of readdirSync(dir)) {
            const full = join(dir, entry);
            if (statSync(full).isDirectory()) {
                if (entry !== '__tests__') sourceFiles(full, out);
            } else if (/\.tsx?$/.test(entry)) {
                out.push(full);
            }
        }
        return out;
    }

    /** `const SOMETHING_KEY = 'literal';` — a module declaring its own key. */
    const DECLARES_KEY = /const\s+\w*(?:KEY|STORE)\w*\s*(?::[^=]+)?=\s*'[^']+'/;

    it('imports every module that owns a secure-storage key', () => {
        const root = join(__dirname, '..');
        const wipeSource = readFileSync(join(root, 'services/wipe.ts'), 'utf8');

        const unaccounted: string[] = [];
        for (const file of sourceFiles(root)) {
            const rel = `src/${file.slice(root.length + 1).split('\\').join('/')}`;
            if (EXEMPT.has(rel)) continue;
            const source = readFileSync(file, 'utf8');
            if (!/setItemAsync\s*\(/.test(source)) continue;
            if (!DECLARES_KEY.test(source)) continue;

            const moduleName = rel.replace(/^src\//, '@/').replace(/\.tsx?$/, '');
            if (!wipeSource.includes(`'${moduleName}'`)) unaccounted.push(rel);
        }

        expect(unaccounted).toEqual([]);
    });
});
