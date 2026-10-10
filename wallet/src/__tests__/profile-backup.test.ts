// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The profile backup.
 *
 * It must open only with this wallet's data root, carry no seed, and a restore
 * must add what is missing without overwriting what the holder has since.
 */

jest.mock('expo-crypto', () => ({
    getRandomBytes: (n: number) => new Uint8Array(n).map((_, i) => (i * 11 + 5) & 0xff),
}));
jest.mock('expo-file-system', () => ({ File: jest.fn(), Paths: { document: 'doc', cache: 'cache' } }));
jest.mock('@/utils/storage', () => {
    const mockStore: Record<string, string> = {};
    return {
        getItemAsync: jest.fn(async (k: string) => mockStore[k] ?? null),
        setItemAsync: jest.fn(async (k: string, v: string) => {
            mockStore[k] = v;
        }),
        deleteItemAsync: jest.fn(async (k: string) => {
            delete mockStore[k];
        }),
    };
});
const mockRecords: any[] = [];
jest.mock('@/services/kyc', () => ({
    loadKycRecords: jest.fn(async () => [...mockRecords]),
    saveKycRecord: jest.fn(async (r: any) => {
        mockRecords.unshift(r);
    }),
}));
const mockRoot = new Uint8Array(32).fill(3);
const ROOT = mockRoot;
jest.mock('@/services/sovereign', () => ({
    ensureDataRoot: jest.fn(async () => mockRoot),
    peekDataRoot: jest.fn(async () => mockRoot),
}));

// An in-memory Drive: folders and files by id.
const mockNodes: Array<{ id: string; parent?: string; kind: 'folder' | 'file'; name: string; body?: string }> = [];
const mockDrive = {
    listRoot: jest.fn(async () => mockNodes.filter((n) => !n.parent)),
    listFolder: jest.fn(async (_t: string, id: string) => mockNodes.filter((n) => n.parent === id)),
    createFolder: jest.fn(async (_t: string, name: string) => {
        const n = { id: `f${mockNodes.length}`, kind: 'folder' as const, name };
        mockNodes.push(n);
        return n;
    }),
    uploadFile: jest.fn(async (_t: string, name: string, body: string, o: { parentId: string }) => {
        const n = { id: `n${mockNodes.length}`, parent: o.parentId, kind: 'file' as const, name, body };
        mockNodes.push(n);
        return n;
    }),
    deleteNode: jest.fn(async (_t: string, id: string) => {
        mockNodes.splice(mockNodes.findIndex((n) => n.id === id), 1);
    }),
    downloadBytes: jest.fn(async (_t: string, id: string) =>
        new TextEncoder().encode(mockNodes.find((n) => n.id === id)!.body!),
    ),
};
jest.mock('@/services/drive', () => ({
    ensureDrive: jest.fn(async () => ({ drive: mockDrive, tenant: { id: 't' }, origin: 'drive' })),
    currentDrive: jest.fn(() => null),
}));

import { peekDataRoot } from '@/services/sovereign';
import {
    BackupError,
    collectContents,
    openContents,
    restoreContents,
    restoreFromDrive,
    restoreFromText,
    saveToDrive,
    sealContents,
} from '@/services/profile-backup';
import { useProfileStore, type UserProfile } from '@/stores/profile';

function profile(attrs: Array<{ key: string; value: string }>, extra: Partial<UserProfile> = {}): UserProfile {
    return {
        displayName: 'Alice',
        email: '',
        avatarUri: '',
        locale: 'en-GB',
        did: 'did:key:device',
        canonicalDid: 'did:web:privasys.id:users:x',
        pairwiseSeed: 'ab'.repeat(32),
        linkedProviders: [],
        attributes: attrs.map((a) => ({ ...a, source: 'manual', verified: false }) as any),
        createdAt: 1,
        updatedAt: 1,
        ...extra,
    };
}

beforeEach(() => {
    mockRecords.length = 0;
    useProfileStore.setState({ profile: profile([{ key: 'given_name', value: 'Alice' }]) });
});

it('carries the details and records but not the seed or the device id', async () => {
    mockRecords.push({ jti: 'r1', fields: { given_name: 'Alice' } });
    const contents = await collectContents();
    expect(contents.profile?.attributes.map((a) => a.key)).toEqual(['given_name']);
    expect(contents.kycRecords.map((r) => r.jti)).toEqual(['r1']);
    expect(JSON.stringify(contents)).not.toContain('ab'.repeat(32));
    expect(JSON.stringify(contents)).not.toContain('did:key:device');
});

it('is ciphertext, and opens only with the data root that sealed it', async () => {
    const text = sealContents(ROOT, await collectContents());
    expect(text).not.toContain('Alice');
    expect(openContents(ROOT, text).profile?.displayName).toBe('Alice');
    expect(() => openContents(new Uint8Array(32).fill(4), text)).toThrow(BackupError);
    try {
        openContents(new Uint8Array(32).fill(4), text);
    } catch (e: any) {
        expect(e.reason).toBe('wrong-wallet');
    }
});

it('refuses a file that is not a backup', () => {
    for (const junk of ['not json', '{"format":"something-else"}', '{}']) {
        try {
            openContents(ROOT, junk);
            throw new Error('opened');
        } catch (e: any) {
            expect(e.reason).toBe('not-a-backup');
        }
    }
});

it('adds what is missing on restore and keeps what the holder has now', async () => {
    const backup = sealContents(ROOT, {
        profile: (({ pairwiseSeed: _s, did: _d, ...rest }) => rest)(
            profile([
                { key: 'given_name', value: 'Alice' },
                { key: 'family_name', value: 'Smith' },
            ], { displayName: 'Old name', email: 'alice@example.org' }),
        ),
        kycRecords: [{ jti: 'r1' } as any],
    });
    useProfileStore.setState({ profile: profile([{ key: 'given_name', value: 'Alice' }], { displayName: 'New name' }) });

    const r = await restoreFromText(backup);
    const now = useProfileStore.getState().profile!;
    expect(r).toEqual({ attributes: 1, records: 1 });
    expect(now.displayName).toBe('New name');
    expect(now.email).toBe('alice@example.org');
    expect(now.attributes.map((a) => a.key).sort()).toEqual(['family_name', 'given_name']);

    // Restoring the same file again adds nothing.
    expect(await restoreFromText(backup)).toEqual({ attributes: 0, records: 0 });
});

it('asks for a recovery first, rather than restoring into a wallet with no root or no profile', async () => {
    const backup = sealContents(ROOT, await collectContents());
    (peekDataRoot as jest.Mock).mockResolvedValueOnce(null);
    await expect(restoreFromText(backup)).rejects.toMatchObject({ reason: 'no-root' });
    useProfileStore.setState({ profile: null });
    await expect(restoreContents(openContents(ROOT, backup))).rejects.toMatchObject({ reason: 'no-profile' });
});

it('keeps one encrypted copy in the Drive folder, replacing the old one only after the new one is in', async () => {
    mockNodes.length = 0;
    await saveToDrive();
    await saveToDrive();
    const files = mockNodes.filter((n) => n.kind === 'file');
    expect(mockNodes.filter((n) => n.kind === 'folder').map((n) => n.name)).toEqual(['Privasys Wallet']);
    expect(files).toHaveLength(1);
    expect(files[0].name).toBe('wallet-backup.json');
    expect(files[0].body).not.toContain('Alice');
    // The second upload landed before the first copy was deleted.
    const order = mockDrive.uploadFile.mock.invocationCallOrder[1];
    expect(order).toBeLessThan(mockDrive.deleteNode.mock.invocationCallOrder[0]);
});

it('restores from the Drive copy', async () => {
    mockNodes.length = 0;
    useProfileStore.setState({ profile: profile([{ key: 'family_name', value: 'Smith' }]) });
    await saveToDrive();
    useProfileStore.setState({ profile: profile([]) });
    await expect(restoreFromDrive()).resolves.toEqual({ attributes: 1, records: 0 });
    mockNodes.length = 0;
    await expect(restoreFromDrive()).rejects.toMatchObject({ reason: 'none-in-drive' });
});
