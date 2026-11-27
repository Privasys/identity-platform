// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

jest.mock('../services/notify-seal', () => ({
    openSealedNotification: jest.fn(async (sealed: string) =>
        sealed === 'opens'
            ? { kind: 'request', path: '/requests/7', presented: { name: 'Ada Lovelace', favourite_colour: 'blue' } }
            : null,
    ),
}));
jest.mock('../services/platform-token', () => ({}));

import { appMessageLink, readAppMessage } from '../services/app-message';
import { readListed } from '../stores/app-messages';

describe('appMessageLink', () => {
    it('links to a path on the host the platform named', () => {
        expect(appMessageLink('app.example.org', '/rooms/1?x=2#y')).toBe('https://app.example.org/rooms/1?x=2#y');
    });

    it('refuses anything that could land on another host', () => {
        for (const path of ['//evil.example/x', 'https://evil.example/x', 'rooms/1', '/a\\@evil.example', '/a b', undefined]) {
            expect(appMessageLink('app.example.org', path)).toBeUndefined();
        }
        for (const host of ['', undefined, 'evil.example/x', 'user@evil.example', 'localhost', 'app.example.org:444']) {
            expect(appMessageLink(host, '/x')).toBeUndefined();
        }
    });
});

describe('readAppMessage', () => {
    it('keeps only referential keys, with the wallet drawing the labels', () => {
        const m = readAppMessage({ kind: 'invitation', presented: { name: 'Ada', email: 'ada@example.org', note: 'hi', age: 3 } });
        expect(m.kind).toBe('invitation');
        expect(m.presented).toEqual([
            ['name', 'Ada'],
            ['email', 'ada@example.org'],
        ]);
    });

    it('falls back to the listed kind, and drops an unknown one', () => {
        expect(readAppMessage(null, 'request').kind).toBe('request');
        expect(readAppMessage({ kind: 'update' }).kind).toBeUndefined();
    });
});

describe('readListed', () => {
    const now = 1_800_000_000;
    it('opens what it can and still lists what it cannot', async () => {
        const out = await readListed(
            {
                messages: [
                    { id: 'a', kind: 'request', app_name: 'Drive', app_host: 'drive.example.org', sealed: 'opens', created_at: now, expires_at: now + 60 },
                    { id: 'b', kind: 'invitation', app_name: 'Rooms', app_host: 'rooms.example.org', sealed: 'other-phone', created_at: now, expires_at: now + 60 },
                    { id: 'c', kind: 'request', expires_at: now - 1 },
                    { kind: 'request', expires_at: now + 60 },
                ],
            },
            now,
        );
        expect(out.map((m) => m.id)).toEqual(['a', 'b']);
        expect(out[0].link).toBe('https://drive.example.org/requests/7');
        expect(out[0].presented).toEqual([['name', 'Ada Lovelace']]);
        expect(out[1].kind).toBe('invitation');
        expect(out[1].link).toBeUndefined();
    });
});
