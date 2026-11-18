// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The demo build: off unless asked for, refused on production, and when on,
 * a seed the screens can read as if a real wallet had hydrated it.
 */

const mockWrites: string[] = [];
jest.mock('@/utils/storage', () => ({
    getItemAsync: jest.fn(async () => null),
    setItemAsync: jest.fn(async (key: string) => {
        mockWrites.push(key);
    }),
    deleteItemAsync: jest.fn(async () => undefined),
}));
jest.mock('../services/notify-seal', () => ({ openSealedNotification: jest.fn(async () => null) }));
jest.mock('../services/platform-token', () => ({ getCachedPlatformToken: jest.fn(async () => null) }));

import { formDigest } from '../services/app-form';
import { CANONICAL_KEYS, isGovVerified } from '../services/attributes';
import { assertDemoAllowed, demo, isDemo } from '../services/demo/gate';
import {
    APPROVAL_STRING,
    attestationFor,
    BANK,
    DEMO_APPS,
    DRIVE,
    FORM_STRING,
    MY_TENANT,
    REGISTER,
} from '../services/demo/fixtures';
import { appIdFromOids } from '../services/release-provenance';
import { useAppMessagesStore } from '../stores/app-messages';
import { useAuthStore } from '../stores/auth';
import { useCapabilitiesStore } from '../stores/capabilities';
import { useConsentStore } from '../stores/consent';
import { useProfileStore } from '../stores/profile';
import { useServiceSessionsStore } from '../stores/service-sessions';
import { useSessionsStore } from '../stores/sessions';
import { useTrustedAppsStore } from '../stores/trusted-apps';
import { buildSessionRows } from '../utils/session-rows';

const saved = process.env.EXPO_PUBLIC_DEMO;
afterEach(() => {
    if (saved === undefined) delete process.env.EXPO_PUBLIC_DEMO;
    else process.env.EXPO_PUBLIC_DEMO = saved;
});

describe('the gate', () => {
    it('is off when the variable is unset', () => {
        delete process.env.EXPO_PUBLIC_DEMO;
        expect(isDemo()).toBe(false);
        expect(() => demo()).toThrow();
    });

    it('is off for any value but 1', () => {
        for (const v of ['0', 'true', '', 'yes']) {
            process.env.EXPO_PUBLIC_DEMO = v;
            expect(isDemo()).toBe(false);
        }
    });

    it('refuses a demo on the production stage', () => {
        process.env.EXPO_PUBLIC_DEMO = '1';
        expect(() => assertDemoAllowed('production')).toThrow(/production/);
        expect(() => assertDemoAllowed('demo')).not.toThrow();
    });

    it('lets every normal build through', () => {
        delete process.env.EXPO_PUBLIC_DEMO;
        for (const stage of ['production', 'preview', 'development', undefined]) {
            expect(() => assertDemoAllowed(stage)).not.toThrow();
        }
    });

    it('will not seed outside a demo build', () => {
        process.env.EXPO_PUBLIC_DEMO = '1';
        const { seedDemo } = demo();
        delete process.env.EXPO_PUBLIC_DEMO;
        expect(() => seedDemo()).toThrow();
        expect(useProfileStore.getState().profile).toBeNull();
    });
});

describe('the seed', () => {
    const now = Date.UTC(2026, 10, 17, 9, 30) as number;

    beforeAll(() => {
        process.env.EXPO_PUBLIC_DEMO = '1';
        demo().seedDemo(now, 'en-GB');
    });

    beforeEach(() => {
        process.env.EXPO_PUBLIC_DEMO = '1';
    });

    it('writes nothing to storage', () => {
        expect(mockWrites).toEqual([]);
    });

    it('gives a complete holder, with passport attributes at gov assurance', () => {
        const profile = useProfileStore.getState().profile!;
        expect(profile.displayName).toBe('Alex Morgan');
        expect(profile.email).toBe('alex.morgan@example.com');
        expect(profile.canonicalDid).toMatch(/^did:web:privasys\.id:users:[0-9a-f]{32}$/);
        expect(profile.pairwiseSeed).toMatch(/^[0-9a-f]{64}$/);
        for (const a of profile.attributes) {
            expect(CANONICAL_KEYS.has(a.key)).toBe(true);
            expect(a.label).toBeTruthy();
            expect(a.value).toBeTruthy();
            if (a.verified) expect(a.verifications?.length).toBeGreaterThan(0);
        }
        for (const key of ['given_name_id', 'family_name_id', 'birthdate_id', 'nationality_id', 'age_over_18']) {
            const a = profile.attributes.find((x) => x.key === key)!;
            expect(isGovVerified(key)).toBe(true);
            expect(a.source).toBe('document');
            expect(a.verifications?.[0].assurance).toBe('gov');
        }
        const email = profile.attributes.find((a) => a.key === 'email')!;
        expect(email.verifications?.[0]).toMatchObject({ verifier: 'privasys.id', assurance: 'provider' });
        expect(profile.attributes.some((a) => a.key === 'phone_number')).toBe(true);
        expect(profile.attributes.find((a) => a.key === 'picture_id')?.value).toMatch(/^data:image\/png;base64,/);
    });

    it('is onboarded, with credentials that point at no real key', () => {
        const auth = useAuthStore.getState();
        expect(auth.isOnboarded).toBe(true);
        expect(auth.privasysId).toBeNull();
        expect(auth.getCredentialForRp('privasys.id')).toBeDefined();
        for (const c of auth.credentials) expect(c.keyAlias).toBe('demo-no-key');
    });

    it('trusts each app at exactly the attestation the demo serves', () => {
        const trusted = useTrustedAppsStore.getState();
        for (const app of DEMO_APPS) {
            const a = attestationFor(app, Math.floor(Date.now() / 1000));
            expect(appIdFromOids(a.custom_oids)).toBe(app.appId);
            expect(
                trusted.isAttestationMatch(app.host, {
                    mrtd: a.mrtd,
                    rtmr1: a.rtmr1,
                    rtmr2: a.rtmr2,
                    codeHash: a.workload_code_hash,
                    configRoot: a.workload_config_merkle_root,
                }),
            ).toBe(true);
        }
    });

    it('lists the three apps on Access, Drive live', () => {
        const rows = buildSessionRows(
            useServiceSessionsStore.getState().traces,
            useTrustedAppsStore.getState().apps,
            useSessionsStore.getState().sessions,
            now,
        );
        expect(rows.map((r) => r.name).sort()).toEqual([BANK.name, DRIVE.name, REGISTER.name].sort());
        expect(rows.find((r) => r.name === DRIVE.name)?.session).toBeDefined();
    });

    it('keeps a sharing history and a grant', () => {
        const consent = useConsentStore.getState();
        expect(consent.records.length).toBeGreaterThanOrEqual(3);
        for (const r of consent.records) {
            expect(r.approvedAttributes).toEqual((r.disclosed ?? []).map((d) => d.key));
        }
        expect(useCapabilitiesStore.getState().hydrated).toBe(true);
        expect(useCapabilitiesStore.getState().records).toHaveLength(1);
    });

    it('has a form, an approval and a message waiting, each as the app sent it', () => {
        const messages = useAppMessagesStore.getState().messages;
        const form = messages.find((m) => m.type === 'app-form');
        const approval = messages.find((m) => m.type === 'approval');
        const message = messages.find((m) => m.type === 'app-message');

        expect(form?.form?.digest).toBe(formDigest(FORM_STRING));
        expect(form?.form?.actions.map((a) => a.kind)).toEqual(['decline', 'confirm']);
        expect(form?.platformHost).toBe(`${form?.appSlug}.apps.privasys.org`);

        expect(approval?.approval?.digest).toBe(formDigest(APPROVAL_STRING));
        expect(approval?.approval?.assurance).toBe('device');
        expect(approval?.expiresAt).toBeGreaterThan(Math.floor(now / 1000));

        expect(message?.kind).toBe('invitation');
        expect(message?.link).toBe(`https://${REGISTER.host}/invitations/3f9c2a`);
        expect(message?.presented.length).toBe(2);
    });

    it('does not ask the IdP for waiting items', async () => {
        const fetchSpy = jest.spyOn(global, 'fetch' as never);
        await useAppMessagesStore.getState().refresh();
        expect(fetchSpy).not.toHaveBeenCalled();
        expect(useAppMessagesStore.getState().messages).toHaveLength(3);
        fetchSpy.mockRestore();
    });
});

describe('the demo Drive', () => {
    beforeEach(() => {
        process.env.EXPO_PUBLIC_DEMO = '1';
    });

    it('lists My files and Shared with me, with a PDF, a photo and Markdown shared', async () => {
        const api = demo();
        const top = await api.listFolder(await api.myTenant());
        expect(top.length).toBeGreaterThan(3);
        expect(top.every((i) => i.tenantId === MY_TENANT && !('content' in i))).toBe(true);

        const shared = await api.listSharedWithMe();
        const mimes = shared.map((s) => s.mime);
        expect(mimes).toEqual(expect.arrayContaining(['application/pdf', 'image/jpeg', 'text/markdown']));
        expect(shared.every((s) => s.grantId && s.scope)).toBe(true);

        const folder = shared.find((s) => s.kind === 'folder')!;
        expect((await api.listFolder(folder.tenantId, folder.id)).length).toBeGreaterThan(0);
    });

    it('answers the attestation checks as verified, for the app that asked', async () => {
        const api = demo();
        const drive = await api.attestDrive();
        expect(drive.appId).toBe(DRIVE.appId);
        expect(drive.attestation.valid).toBe(true);
        const source = await api.confirmSource({ platformHost: BANK.host });
        expect(source.host).toBe(BANK.host);
        expect(appIdFromOids(source.attestation.custom_oids)).toBe(BANK.appId);
        const outcome = await api.attestEnclave(REGISTER.host, { tee: 'tdx', mode: 'challenge' });
        expect(outcome).toMatchObject({ status: 'verified', challenged: true });
    });
});
