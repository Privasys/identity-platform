// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// The token helper pulls in the FIDO2 stack; only parsing is under test.
jest.mock('@/services/platform-token', () => ({ getCachedPlatformToken: jest.fn() }));

import { parseAsks } from '@/stores/capability-asks';

const NOW = 1_000_000;

describe('parseAsks', () => {
    it('keeps live, well-formed asks in the order given', () => {
        const got = parseAsks(
            {
                pending: [
                    { nonce: 'n2', app_host: 'b.example', app_name: 'B', created_at: 2, expires_at: NOW + 60 },
                    { nonce: 'n1', app_host: 'a.example', created_at: 1, expires_at: NOW + 1 },
                ],
            },
            NOW,
        );
        expect(got.map((a) => a.nonce)).toEqual(['n2', 'n1']);
    });

    it('drops an ask that has expired, or is missing its nonce or host', () => {
        const got = parseAsks(
            {
                pending: [
                    { nonce: 'old', app_host: 'a.example', expires_at: NOW },
                    { nonce: '', app_host: 'a.example', expires_at: NOW + 60 },
                    { nonce: 'n', app_host: '', expires_at: NOW + 60 },
                    { nonce: 'n', expires_at: NOW + 60 },
                    null,
                ],
            },
            NOW,
        );
        expect(got).toEqual([]);
    });

    it('reads anything that is not a list as nothing', () => {
        expect(parseAsks(null, NOW)).toEqual([]);
        expect(parseAsks({ pending: 'x' }, NOW)).toEqual([]);
        expect(parseAsks({}, NOW)).toEqual([]);
    });
});
