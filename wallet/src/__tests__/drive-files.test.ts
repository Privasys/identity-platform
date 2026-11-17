// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

jest.mock('expo-file-system', () => ({ Directory: jest.fn(), File: jest.fn(), Paths: { cache: 'cache' } }));
jest.mock('../services/drive', () => ({ ensureDrive: jest.fn() }));
jest.mock('../services/platform-token', () => ({
    getDriveToken: jest.fn(async () => 'tok'),
    isDriveHost: jest.fn(async (h: string) => h === 'drive-demo.apps.test.privasys.org'),
}));
jest.mock('../../modules/native-ratls/src/index', () => ({ makeRaTlsFetch: jest.fn(), requestBytes: jest.fn() }));
jest.mock('expo-modules-core', () => ({ requireNativeModule: () => ({}) }));
jest.mock('react-native', () => ({ Platform: { OS: 'ios' } }));

import { driveRouteFor, fileKind, parseDriveLink, safeFileName, sortItems } from '../services/drive-files';

describe('parseDriveLink', () => {
    it('reads the links Drive sends', () => {
        expect(parseDriveLink('/#shared')).toEqual({ shared: true });
        expect(parseDriveLink('/#shared/t-1/n-2')).toEqual({ shared: true, tenantId: 't-1', nodeId: 'n-2' });
    });
    it.each(['/#requests', '/#shared/', '/#shared/a', '/#shared/a/b/c', '/#shared/a b/c', '/#shared/a/../x', '/x#shared', undefined])(
        'ignores %s',
        (p) => {
            expect(parseDriveLink(p as string | undefined)).toBeNull();
        },
    );
});

describe('driveRouteFor', () => {
    it('opens the Drive screen for a link from the Drive host, naming the sender', async () => {
        await expect(driveRouteFor('drive-demo.apps.test.privasys.org', '/#shared/t-1/n-2', 'app-1')).resolves.toEqual({
            pathname: '/drive',
            params: { section: 'shared', tenant: 't-1', node: 'n-2', from: 'app-1' },
        });
    });
    it('leaves any other app to its page, even with the same path', async () => {
        await expect(driveRouteFor('globaml.apps.privasys.org', '/#shared/t-1/n-2', 'app-2')).resolves.toBeNull();
    });
});

describe('fileKind', () => {
    it.each([
        [{ name: 'a.PDF' }, 'pdf'],
        [{ name: 'x', mime: 'application/pdf' }, 'pdf'],
        [{ name: 'photo.heic' }, 'image'],
        [{ name: 'notes.md' }, 'markdown'],
        [{ name: 'data.csv' }, 'text'],
        [{ name: 'report.docx' }, 'other'],
    ])('%j is %s', (item, kind) => {
        expect(fileKind(item)).toBe(kind);
    });
});

describe('safeFileName', () => {
    it('keeps the extension and drops path characters', () => {
        expect(safeFileName('../../etc/pass:wd.pdf')).toBe('.._.._etc_pass_wd.pdf');
        expect(safeFileName('   ')).toBe('file');
    });
});

describe('sortItems', () => {
    it('puts folders first, then by name', () => {
        const base = { tenantId: 't', sizeBytes: 0 };
        const out = sortItems([
            { ...base, id: '1', kind: 'file' as const, name: 'b' },
            { ...base, id: '2', kind: 'folder' as const, name: 'z' },
            { ...base, id: '3', kind: 'file' as const, name: 'a' },
        ]);
        expect(out.map((x) => x.id)).toEqual(['2', '3', '1']);
    });
});

