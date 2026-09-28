// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The two ways into the holder's grants: by provider, then account, product
 * and app; and by app. Both over the same records, and neither naming a
 * provider or a product the service did not declare.
 */

jest.mock('@/utils/storage', () => ({
    getItemAsync: jest.fn(async () => null),
    setItemAsync: jest.fn(async () => undefined),
    deleteItemAsync: jest.fn(async () => undefined),
}));

import { capabilityKey, type CapabilityRecord } from '@/stores/capabilities';
import { appTree, productNames, providerTree, recordsIn } from '@/utils/access-tree';

const NOW = 1_800_000_000;
const MAIL = 'mail-svc';
const CAL = 'cal-svc';

const grant = (over: Partial<CapabilityRecord> = {}): CapabilityRecord => ({
    appId: 'app-1',
    appName: 'Privasystant',
    resourceAppId: MAIL,
    resourceAppName: 'Privasys Mail Connector',
    kind: 'mail.mailbox',
    resourceLabel: 'Inbox',
    permissions: ['read'],
    decision: 'approved',
    capabilityId: `cap-${Math.random()}`,
    grantedAt: NOW - 1000,
    setupProvided: true,
    ...over,
});

const gmail = (account: string, over: Partial<CapabilityRecord> = {}) =>
    grant({ account, providerId: 'google', providerName: 'Google', product: 'Gmail', category: 'Mail', ...over });

describe('by provider', () => {
    it('puts one provider together, then its accounts, products and apps', () => {
        const records = [
            gmail('me@gmail.com'),
            gmail('me@gmail.com', { appId: 'app-2', appName: 'Inbox triage' }),
            gmail('work@corp.example'),
            grant({
                resourceAppId: CAL,
                kind: 'calendar.events',
                account: 'me@gmail.com',
                providerId: 'google',
                providerName: 'Google',
                product: 'Google Calendar',
                category: 'Calendar',
            }),
        ];
        const [google, ...rest] = providerTree(records);
        expect(rest).toEqual([]);
        expect(google.name).toBe('Google');
        expect(google.accounts.map((a) => a.account)).toEqual(['me@gmail.com', 'work@corp.example']);
        const me = google.accounts[0];
        expect(me.products.map((p) => p.product)).toEqual(['Gmail', 'Google Calendar']);
        expect(me.products[0].rows.map((r) => r.record.appName).sort()).toEqual(['Inbox triage', 'Privasystant']);
        expect(productNames(google)).toEqual(['Gmail', 'Google Calendar']);
        expect(recordsIn(google)).toHaveLength(4);
        expect(recordsIn(me)).toHaveLength(3);
    });

    it('keeps two providers apart', () => {
        const names = providerTree([
            gmail('me@gmail.com'),
            grant({ account: 'me@outlook.com', providerId: 'microsoft', providerName: 'Microsoft', product: 'Outlook' }),
        ]).map((p) => p.name);
        expect(names).toEqual(['Google', 'Microsoft']);
    });

    it('falls back to the service and the resource it described when nothing was declared', () => {
        const [p] = providerTree([grant()]);
        expect(p.name).toBe('Privasys Mail Connector');
        expect(p.accounts[0].account).toBe('Inbox');
        expect(p.accounts[0].products[0].product).toBe('Privasys Mail Connector');
    });

    it('leaves out grants over the holder’s own data, and denials', () => {
        expect(
            providerTree([
                grant({ setupProvided: false, kind: 'storage.folder' }),
                gmail('me@gmail.com', { decision: 'denied' }),
            ]),
        ).toEqual([]);
    });
});

describe('by app', () => {
    it('lists everything one app may use, whoever holds it', () => {
        const apps = appTree([
            gmail('me@gmail.com'),
            grant({ setupProvided: false, kind: 'storage.folder', resourceAppId: 'drive', resourceLabel: 'Harness' }),
            gmail('me@gmail.com', { appId: 'app-2', appName: 'Inbox triage' }),
        ]);
        expect(apps.map((a) => a.appName)).toEqual(['Inbox triage', 'Privasystant']);
        expect(apps[1].rows).toHaveLength(2);
    });
});

describe('the record key', () => {
    it('keeps two accounts of one app at one service apart, and leaves older keys as they were', () => {
        const base = grant();
        expect(capabilityKey(base)).toBe(`app-1|${MAIL}|mail.mailbox|Inbox`);
        expect(capabilityKey(gmail('a@x.org'))).not.toBe(capabilityKey(gmail('b@x.org')));
    });
});
