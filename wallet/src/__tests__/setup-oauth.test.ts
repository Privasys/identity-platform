// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The sign-in step of a service's setup: what the wallet accepts from the
 * schema, where it lets the browser go, and what it takes back.
 */

jest.mock('expo-web-browser', () => ({ openAuthSessionAsync: jest.fn() }));
jest.mock('expo-constants', () => ({ __esModule: true, default: { expoConfig: { scheme: 'privasys-wallet-test' } } }));
jest.mock('expo-crypto', () => ({
    getRandomBytesAsync: jest.fn(async (n: number) => new Uint8Array(n).fill(7)),
}));

import * as WebBrowser from 'expo-web-browser';

import { initialAnswers, parseSetupFields, SetupSchemaError } from '@/services/capability-setup';
import {
    grantFromCallback,
    runSetupOAuth,
    SetupOAuthError,
    setupCallbackUri,
    startUrlIsOn,
    startUrlWith,
} from '@/services/setup-oauth';

const HOST = 'calendar-connector.apps.test.privasys.org';
const START = `https://${HOST}/v1/oauth/start`;

describe('the schema', () => {
    it('reads an oauth field with its provider and start URL', () => {
        const [f] = parseSetupFields(
            {
                type: 'object',
                properties: {
                    grant: {
                        type: 'string',
                        title: 'Allow access to your calendar',
                        'x-privasys-oauth': { provider: 'Google', start_url: START },
                    },
                },
                required: ['grant'],
            },
            [],
        );
        expect(f.kind).toBe('oauth');
        expect(f.required).toBe(true);
        expect(f.oauth).toEqual({ provider: 'Google', startUrl: START });
    });

    it('refuses a sign-in it cannot follow', () => {
        for (const bad of [{}, { provider: 'Google' }, { provider: 'Google', start_url: 'http://x/y' }, { start_url: START }]) {
            expect(() =>
                parseSetupFields({ properties: { grant: { type: 'string', 'x-privasys-oauth': bad } } }, []),
            ).toThrow(SetupSchemaError);
        }
    });

    it('never carries a grant code into a later step', () => {
        const fields = parseSetupFields(
            { properties: { grant: { type: 'string', 'x-privasys-oauth': { provider: 'Google', start_url: START } } } },
            [],
        );
        expect(initialAnswers(fields, { previous: { grant: 'old-code' } })).toEqual({ grant: '' });
    });
});

describe('where the browser goes', () => {
    it('only to the service the wallet attested, over https', () => {
        expect(startUrlIsOn(START, HOST)).toBe(true);
        expect(startUrlIsOn(START, HOST.toUpperCase())).toBe(true);
        expect(startUrlIsOn(`http://${HOST}/v1/oauth/start`, HOST)).toBe(false);
        expect(startUrlIsOn('https://accounts.google.com/o/oauth2/auth', HOST)).toBe(false);
        expect(startUrlIsOn(`https://evil.${HOST}/start`, HOST)).toBe(false);
    });

    it('tells the service where to come back and with what', () => {
        const u = new URL(startUrlWith(`${START}?kind=calendar.events`, 'privasys-wallet://setup/callback', 'n1'));
        expect(u.searchParams.get('kind')).toBe('calendar.events');
        expect(u.searchParams.get('redirect_uri')).toBe('privasys-wallet://setup/callback');
        expect(u.searchParams.get('nonce')).toBe('n1');
    });

    it('comes back on the app scheme', () => {
        expect(setupCallbackUri()).toBe('privasys-wallet-test://setup/callback');
    });
});

describe('what comes back', () => {
    it('is the grant code, when the nonce matches', () => {
        expect(grantFromCallback('privasys-wallet://setup/callback?grant=abc.DEF-1&nonce=n1', 'n1')).toBe('abc.DEF-1');
    });
    it('is refused for another nonce, an error, or something odd', () => {
        expect(() => grantFromCallback('privasys-wallet://setup/callback?grant=abc&nonce=n2', 'n1')).toThrow(SetupOAuthError);
        expect(() => grantFromCallback('privasys-wallet://setup/callback?error=access_denied&nonce=n1', 'n1')).toThrow('access_denied');
        expect(() => grantFromCallback('privasys-wallet://setup/callback?grant=%3Cscript%3E&nonce=n1', 'n1')).toThrow(SetupOAuthError);
    });
});

describe('the whole step', () => {
    it('opens the start URL and returns the grant', async () => {
        (WebBrowser.openAuthSessionAsync as jest.Mock).mockImplementation(async (url: string, redirect: string) => {
            const u = new URL(url);
            expect(u.origin + u.pathname).toBe(START);
            expect(u.searchParams.get('redirect_uri')).toBe(redirect);
            return { type: 'success', url: `${redirect}?grant=g1&nonce=${u.searchParams.get('nonce')}` };
        });
        await expect(runSetupOAuth({ provider: 'Google', startUrl: START }, HOST)).resolves.toBe('g1');
    });

    it('refuses to start anywhere but the service', async () => {
        await expect(
            runSetupOAuth({ provider: 'Google', startUrl: 'https://accounts.google.com/x' }, HOST),
        ).rejects.toThrow(SetupOAuthError);
        expect(WebBrowser.openAuthSessionAsync).not.toHaveBeenCalledWith(
            expect.stringContaining('accounts.google.com'),
            expect.anything(),
        );
    });

    it('reports a cancel as cancelled, not as a failure', async () => {
        (WebBrowser.openAuthSessionAsync as jest.Mock).mockResolvedValue({ type: 'cancel' });
        await expect(runSetupOAuth({ provider: 'Google', startUrl: START }, HOST)).rejects.toMatchObject({
            cancelled: true,
        });
    });
});
