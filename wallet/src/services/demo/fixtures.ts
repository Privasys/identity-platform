// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Everything the demo shows, invented, in one place and in the wallet's own
 * types. No value here belongs to a real person, document, app or enclave:
 * the holder is made up, the apps other than Drive are fictional, and every
 * measurement is a hash of a label (fakeHex), so it looks like a measurement
 * and can never match a real one.
 *
 * Times are relative to `now`, so a screenshot taken on any day reads as
 * recent activity rather than as a date long past.
 */

import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import { parseApproval } from '@/services/approval';
import { attributeLabel } from '@/services/attributes';
import { appMessageLink, readAppMessage } from '@/services/app-message';
import { formDigest, parseForm } from '@/services/app-form';
import type { AttestationResult } from '@/services/attestation';
import type { RegistryDevice } from '@/services/devices';
import type { SharedItem, StoredItem } from '@/services/drive-files';
import type { WaitingAppMessage } from '@/stores/app-messages';
import type { Credential } from '@/stores/auth';
import type { CapabilityRecord } from '@/stores/capabilities';
import type { ConsentRecord, StandingConsent } from '@/stores/consent';
import type { ProfileAttribute, UserProfile, VerificationRecord } from '@/stores/profile';
import type { SessionTrace } from '@/stores/service-sessions';
import type { TrustedApp } from '@/stores/trusted-apps';

import { DEMO_NOTES } from './notes';
import { DEMO_PORTRAIT } from './portrait';

const OID_WORKLOAD_APP_ID = '1.3.6.1.4.1.65230.4.1';
const OID_WORKLOAD_IMAGE_DIGEST = '1.3.6.1.4.1.65230.4.2';

/** Hex that looks like a measurement: the first `bytes` of SHA-512 over a label. */
export function fakeHex(label: string, bytes: number): string {
    return bytesToHex(sha512(new TextEncoder().encode(`privasys-wallet-demo/${label}`))).slice(0, bytes * 2);
}

const DAY = 86_400;

// ── The apps ────────────────────────────────────────────────────────────

export interface DemoApp {
    /** The OIDC client id, which is also the app's short name on the platform. */
    slug: string;
    name: string;
    /** The management app id (OID 4.1). */
    appId: string;
    host: string;
}

export const DRIVE: DemoApp = {
    slug: 'privasys-drive',
    name: 'Privasys Drive',
    appId: '4f0c2a91-6d3e-4b7a-9e15-2c8d7b60a3f4',
    host: 'privasys-drive.apps.privasys.org',
};
export const BANK: DemoApp = {
    slug: 'northwind-bank',
    name: 'Northwind Bank',
    appId: '9b2e6d07-31c4-4a58-8f6b-e07a1d93c5b2',
    host: 'northwind-bank.apps.privasys.org',
};
export const REGISTER: DemoApp = {
    slug: 'civic-register',
    name: 'Civic Register',
    appId: 'c61a8f3e-0b97-4d2c-a5e4-58f2b9d0e716',
    host: 'civic-register.apps.privasys.org',
};
export const DEMO_APPS = [DRIVE, BANK, REGISTER];

export function appForHost(host: string): DemoApp {
    const bare = host.split(':')[0].toLowerCase();
    return DEMO_APPS.find((a) => a.host === bare) ?? DRIVE;
}

/** A verified TDX attestation for one of the demo apps. */
export function attestationFor(app: DemoApp, now: number): AttestationResult {
    const notBefore = new Date((now - 3 * DAY) * 1000).toISOString();
    const notAfter = new Date((now + 27 * DAY) * 1000).toISOString();
    const imageDigest = fakeHex(`${app.slug}/image`, 32);
    return {
        valid: true,
        tee_type: 'tdx',
        mrtd: fakeHex(`${app.slug}/mrtd`, 48),
        rtmr1: fakeHex(`${app.slug}/rtmr1`, 48),
        rtmr2: fakeHex(`${app.slug}/rtmr2`, 48),
        config_merkle_root: fakeHex(`${app.slug}/config`, 32),
        combined_workloads_hash: fakeHex(`${app.slug}/workloads`, 32),
        dek_origin: 'vault',
        attestation_servers_hash: fakeHex('attestation-servers', 32),
        workload_config_merkle_root: fakeHex(`${app.slug}/workload-config`, 32),
        workload_code_hash: fakeHex(`${app.slug}/code`, 32),
        workload_image_ref: `ghcr.io/example/${app.slug}@sha256:${imageDigest}`,
        workload_key_source: 'vault',
        quote_verification_status: 'UpToDate',
        advisory_ids: [],
        cert_subject: `CN=${app.host}`,
        cert_not_before: notBefore,
        cert_not_after: notAfter,
        custom_oids: [
            { oid: OID_WORKLOAD_APP_ID, label: 'App ID', value_hex: app.appId.replace(/-/g, '') },
            { oid: OID_WORKLOAD_IMAGE_DIGEST, label: 'Image digest', value_hex: imageDigest },
        ],
    };
}

/** The trusted-app row the wallet keeps once an app's attestation was approved. */
export function trustedAppFor(app: DemoApp, now: number, credentialId = ''): TrustedApp {
    const a = attestationFor(app, now);
    return {
        rpId: app.host,
        origin: app.host,
        appName: app.name,
        mrtd: a.mrtd,
        rtmr1: a.rtmr1,
        rtmr2: a.rtmr2,
        codeHash: a.workload_code_hash,
        configRoot: a.workload_config_merkle_root,
        teeType: 'tdx',
        lastVerified: now - 2 * 3600,
        credentialId,
    };
}

// ── The holder ──────────────────────────────────────────────────────────

const HOLDER_ID = fakeHex('holder/id', 16);

function govVerification(now: number): VerificationRecord {
    return {
        verifier: 'privasys-kyc',
        verifierDisplayName: 'Privasys identity verifier',
        method: 'kyc_enclave',
        assurance: 'gov',
        verifiedAt: now - 21 * DAY,
    };
}

function fromPassport(now: number, key: string, value: string): ProfileAttribute {
    const at = now - 21 * DAY;
    return {
        key,
        label: attributeLabel(key),
        value,
        source: 'document',
        sources: [{ source: 'document', displayName: 'Passport', addedAt: at }],
        acquiredAt: at,
        updatedAt: at,
        verifications: [govVerification(now)],
    };
}

function typed(now: number, key: string, value: string, daysAgo: number): ProfileAttribute {
    const at = now - daysAgo * DAY;
    return {
        key,
        label: attributeLabel(key),
        value,
        source: 'manual',
        sources: [{ source: 'manual', displayName: 'Manual', addedAt: at }],
        acquiredAt: at,
        updatedAt: at,
    };
}

export const HOLDER_EMAIL = 'alex.morgan@example.com';

export function holderProfile(now: number): UserProfile {
    const emailAt = now - 40 * DAY;
    const phoneAt = now - 38 * DAY;
    return {
        avatarUri: '',
        locale: 'en-GB',
        did: `did:key:z6Mk${fakeHex('holder/did', 22)}`,
        canonicalDid: `did:web:privasys.id:users:${HOLDER_ID}`,
        pairwiseSeed: fakeHex('holder/pairwise-seed', 32),
        linkedProviders: [],
        attributes: [
            typed(now, 'given_name', 'Alex', 45),
            typed(now, 'family_name', 'Morgan', 45),
            {
                key: 'email',
                label: attributeLabel('email'),
                value: HOLDER_EMAIL,
                source: 'manual',
                sources: [{ source: 'manual', displayName: 'Manual', addedAt: emailAt }],
                acquiredAt: emailAt,
                updatedAt: emailAt,
                verifications: [
                    {
                        verifier: 'privasys_mail',
                        verifierDisplayName: 'Privasys',
                        method: 'email_code',
                        assurance: 'provider',
                        verifiedAt: emailAt,
                        proof: 'demo-email-proof',
                    },
                ],
            },
            {
                key: 'phone_number',
                label: attributeLabel('phone_number'),
                value: '+44 7700 900123',
                source: 'manual',
                sources: [{ source: 'manual', displayName: 'Manual', addedAt: phoneAt }],
                acquiredAt: phoneAt,
                updatedAt: phoneAt,
            },
            fromPassport(now, 'given_name_id', 'ALEX JAMIE'),
            fromPassport(now, 'family_name_id', 'MORGAN'),
            fromPassport(now, 'birthdate_id', '1991-06-14'),
            fromPassport(now, 'nationality_id', 'GBR'),
            fromPassport(now, 'document_type', 'P'),
            fromPassport(now, 'issuing_state', 'GBR'),
            fromPassport(now, 'doc_expiry', '2034-03-18'),
            fromPassport(now, 'age_over_18', 'true'),
            fromPassport(now, 'age_over_21', 'true'),
            fromPassport(now, 'picture_id', DEMO_PORTRAIT),
        ],
        createdAt: now - 45 * DAY,
        updatedAt: now - 21 * DAY,
    };
}

// ── Sign-in credentials and phones ──────────────────────────────────────

export function credentials(now: number): Credential[] {
    return [
        {
            credentialId: `demo-${fakeHex('credential/privasys-id', 16)}`,
            rpId: 'privasys.id',
            origin: 'privasys.id',
            // Never a key that exists: the demo signs nothing.
            keyAlias: 'demo-no-key',
            userHandle: HOLDER_ID,
            userName: HOLDER_EMAIL,
            registeredAt: now - 45 * DAY,
            serverRpId: 'privasys.id',
        },
        {
            credentialId: `demo-${fakeHex('credential/northwind', 16)}`,
            rpId: BANK.host,
            origin: BANK.host,
            keyAlias: 'demo-no-key',
            userHandle: fakeHex('holder/northwind-sub', 16),
            userName: 'Alex Morgan',
            registeredAt: now - 30 * DAY,
        },
    ];
}

export const THIS_PHONE_ID = 'demo-phone-this';

export function devices(now: number): { device: RegistryDevice; isThis: boolean }[] {
    return [
        {
            device: { id: THIS_PHONE_ID, name: 'Alex’s iPhone', createdAt: now - 45 * DAY, secret: '' },
            isThis: true,
        },
        {
            device: { id: 'demo-phone-other', name: 'Alex’s Pixel', createdAt: now - 12 * DAY, secret: '' },
            isThis: false,
        },
    ];
}

// ── What the holder did with the apps ───────────────────────────────────

/** Sign-ins, newest first, as the session trail keeps them. */
export function traces(now: number): SessionTrace[] {
    const ms = now * 1000;
    const att = (app: DemoApp, minutesAgo: number) => {
        const a = attestationFor(app, now);
        return {
            host: app.host,
            teeType: 'tdx' as const,
            mrtd: a.mrtd,
            codeHash: a.workload_code_hash,
            configRoot: a.workload_config_merkle_root,
            imageRef: a.workload_image_ref,
            quoteStatus: 'UpToDate',
            appId: app.appId,
            verifiedAt: ms - minutesAgo * 60_000,
        };
    };
    return [
        {
            id: 'demo-trace-drive',
            serviceKey: DRIVE.slug,
            displayName: DRIVE.name,
            kind: 'enclave',
            identity: 'privasys-id',
            clientId: DRIVE.slug,
            rpId: 'privasys.id',
            origin: DRIVE.host,
            appHost: DRIVE.host,
            channel: 'qr',
            startedAt: ms - 12 * 60_000,
            requestedAttributes: ['email'],
            sharedAttributes: [{ key: 'email', value: HOLDER_EMAIL }],
            attestations: [att(DRIVE, 12)],
        },
        {
            id: 'demo-trace-bank',
            serviceKey: BANK.slug,
            displayName: BANK.name,
            kind: 'enclave',
            identity: 'privasys-id',
            clientId: BANK.slug,
            rpId: 'privasys.id',
            origin: BANK.host,
            appHost: BANK.host,
            channel: 'push',
            startedAt: ms - 3 * 3_600_000,
            requestedAttributes: ['given_name_id', 'family_name_id', 'birthdate_id', 'email'],
            sharedAttributes: [
                { key: 'given_name_id', gov: true },
                { key: 'family_name_id', gov: true },
                { key: 'birthdate_id', gov: true },
                { key: 'email', value: HOLDER_EMAIL },
            ],
            attestations: [att(BANK, 180)],
        },
        {
            id: 'demo-trace-register',
            serviceKey: REGISTER.slug,
            displayName: REGISTER.name,
            kind: 'enclave',
            identity: 'privasys-id',
            clientId: REGISTER.slug,
            rpId: 'privasys.id',
            origin: REGISTER.host,
            appHost: REGISTER.host,
            channel: 'qr',
            startedAt: ms - 2 * DAY * 1000,
            requestedAttributes: ['age_over_18', 'nationality_id'],
            sharedAttributes: [
                { key: 'age_over_18', gov: true },
                { key: 'nationality_id', gov: true },
            ],
            attestations: [att(REGISTER, 2 * 24 * 60)],
        },
    ];
}

export function consentRecords(now: number): ConsentRecord[] {
    const rec = (
        id: string,
        app: DemoApp,
        daysAgo: number,
        requested: string[],
        disclosed: { key: string; value?: string; proofOnly?: boolean }[],
        denied: string[] = [],
    ): ConsentRecord => {
        const a = attestationFor(app, now);
        return {
            id,
            rpId: app.host,
            origin: app.host,
            appName: app.name,
            requestedAttributes: requested,
            approvedAttributes: disclosed.map((d) => d.key),
            disclosed,
            deniedAttributes: denied,
            decision: denied.length === 0 ? 'approved' : disclosed.length === 0 ? 'denied' : 'partial',
            persistent: false,
            teeType: 'tdx',
            enclaveMeasurement: a.mrtd ?? '',
            codeHash: a.workload_code_hash ?? '',
            consentedAt: now - daysAgo * DAY,
            expiresAt: 0,
        };
    };
    return [
        rec('demo-consent-1', DRIVE, 0.01, ['email'], [{ key: 'email', value: HOLDER_EMAIL }]),
        rec('demo-consent-2', BANK, 0.12, ['given_name_id', 'family_name_id', 'birthdate_id', 'email'], [
            { key: 'given_name_id', proofOnly: true },
            { key: 'family_name_id', proofOnly: true },
            { key: 'birthdate_id', proofOnly: true },
            { key: 'email', value: HOLDER_EMAIL },
        ]),
        rec('demo-consent-3', REGISTER, 2, ['age_over_18', 'nationality_id', 'phone_number'], [
            { key: 'age_over_18', proofOnly: true },
            { key: 'nationality_id', proofOnly: true },
        ], ['phone_number']),
        rec('demo-consent-4', BANK, 30, ['email', 'phone_number'], [
            { key: 'email', value: HOLDER_EMAIL },
            { key: 'phone_number', value: '+44 7700 900123' },
        ]),
    ];
}

export function standingConsents(now: number): StandingConsent[] {
    const a = attestationFor(DRIVE, now);
    return [
        {
            rpId: DRIVE.host,
            attributes: ['email'],
            enclaveMeasurement: a.mrtd ?? '',
            codeHash: a.workload_code_hash ?? '',
            grantedAt: now - 10 * DAY,
        },
    ];
}

/** One app with access to a Drive folder, so Access lists an app and its grant. */
export function capabilityRecords(now: number): CapabilityRecord[] {
    return [
        {
            appId: BANK.appId,
            appName: BANK.name,
            resourceAppId: DRIVE.appId,
            resourceAppName: DRIVE.name,
            kind: 'storage.folder',
            resourceLabel: 'Statements',
            permissions: ['read', 'write'],
            decision: 'approved',
            capabilityId: 'demo-capability-statements',
            grantedAt: now - 9 * DAY,
            expiresAt: now + 81 * DAY,
            lastCheckedAt: now - 3600,
            checkResult: 'held',
        },
    ];
}

// ── Waiting on the holder ───────────────────────────────────────────────

/** The app form, exactly as an app sends it: its digest is over this string. */
export const FORM_STRING = JSON.stringify({
    v: 1,
    id: 'address-change-2041',
    title: 'Confirm your new address',
    blocks: [
        { type: 'text', text: 'We received a request to change the address on your current account. Please confirm it was you.' },
        {
            type: 'fields',
            items: [
                { label: 'New address', value: '4 Harbour Lane, Portbridge PB1 4QX' },
                { label: 'Effective from', value: '1 December' },
                { label: 'Account', value: 'Everyday current account ending 0417' },
            ],
        },
        { type: 'divider' },
        { type: 'attributes', values: { given_name: 'Alex', family_name: 'Morgan' } },
    ],
    actions: [
        { id: 'decline', kind: 'decline' },
        { id: 'confirm', kind: 'confirm' },
    ],
    callback: '/wallet/forms/answer',
    link: '/account/profile',
});

/** The act the approval commits; the app sends only its digest. */
const ACT = JSON.stringify({ act: 'parking-permit', zone: 'PB-East', vehicle: 'AB12 CDE', from: '2026-12-01' });

export const APPROVAL_STRING = JSON.stringify({
    v: 1,
    id: 'permit-88213',
    title: 'Apply for a residents’ parking permit',
    lines: [
        { label: 'Zone', value: 'Portbridge East' },
        { label: 'Vehicle', value: 'AB12 CDE' },
        { label: 'Valid from', value: '1 December, for 12 months' },
        { label: 'Fee', value: '£64.00, charged on approval' },
    ],
    act_digest: formDigest(ACT),
    assurance: 'device',
    callback: '/wallet/approvals/answer',
    ttl: 900,
});

export function waitingMessages(now: number): WaitingAppMessage[] {
    const form = parseForm(FORM_STRING) ?? undefined;
    const approval = parseApproval(APPROVAL_STRING) ?? undefined;
    const invitation = readAppMessage({
        kind: 'invitation',
        path: '/invitations/3f9c2a',
        presented: { given_name: 'Jordan', family_name: 'Rivers' },
    });
    return [
        {
            id: 'demo-approval',
            type: 'approval',
            appId: REGISTER.appId,
            appName: REGISTER.name,
            appHost: REGISTER.host,
            appSlug: REGISTER.slug,
            platformHost: REGISTER.host,
            kind: 'request',
            presented: [],
            approval,
            createdAt: now - 60,
            // Ten minutes, comfortably inside the approval's ttl, so the screen
            // still counts down when the screenshots are taken.
            expiresAt: now + 600,
        },
        {
            id: 'demo-form',
            type: 'app-form',
            appId: BANK.appId,
            appName: BANK.name,
            appHost: BANK.host,
            appSlug: BANK.slug,
            platformHost: BANK.host,
            kind: 'request',
            presented: [],
            form,
            link: form ? appMessageLink(BANK.host, form.link) : undefined,
            createdAt: now - 25 * 60,
            expiresAt: now + 3 * DAY,
        },
        {
            id: 'demo-message',
            type: 'app-message',
            appId: REGISTER.appId,
            appName: REGISTER.name,
            appHost: REGISTER.host,
            appSlug: REGISTER.slug,
            platformHost: REGISTER.host,
            ...invitation,
            link: appMessageLink(REGISTER.host, invitation.path),
            createdAt: now - 5 * 3600,
            expiresAt: now + 2 * DAY,
        },
    ];
}

// ── Drive ───────────────────────────────────────────────────────────────

/** Which bundled sample a demo file's bytes come from. */
export type DemoContent = 'pdf' | 'jpeg' | keyof typeof DEMO_NOTES;

export interface DemoNode extends StoredItem {
    /** The folder it sits in, or undefined at the top of its drive. */
    parent?: string;
    content?: DemoContent;
}

export interface DemoShared extends SharedItem {
    content?: DemoContent;
}

export const MY_TENANT = 'tenant-alex-morgan';
const JORDAN = 'tenant-jordan-rivers';
const SAM = 'tenant-sam-okafor';

const PDF_BYTES = 2310;
const JPEG_BYTES = 27603;
const textBytes = (k: keyof typeof DEMO_NOTES) => new TextEncoder().encode(DEMO_NOTES[k]).length;

export function myDrive(): DemoNode[] {
    const folder = (id: string, name: string, parent?: string): DemoNode => ({
        tenantId: MY_TENANT,
        id,
        kind: 'folder',
        name,
        sizeBytes: 0,
        parent,
    });
    const file = (id: string, name: string, content: DemoContent, mime: string, parent?: string): DemoNode => ({
        tenantId: MY_TENANT,
        id,
        kind: 'file',
        name,
        sizeBytes: content === 'pdf' ? PDF_BYTES : content === 'jpeg' ? JPEG_BYTES : textBytes(content),
        mime,
        parent,
        content,
    });
    return [
        folder('f-documents', 'Documents'),
        folder('f-photos', 'Photos'),
        folder('f-statements', 'Statements'),
        file('n-harbour-walk', 'Harbour walk notes.md', 'harbourWalk', 'text/markdown'),
        file('n-tenancy', 'Tenancy summary.pdf', 'pdf', 'application/pdf'),
        file('n-dusk', 'Harbour at dusk.jpg', 'jpeg', 'image/jpeg'),
        file('n-checklist', 'Passport renewal checklist.md', 'checklist', 'text/markdown', 'f-documents'),
        file('n-insurance', 'Home insurance schedule.pdf', 'pdf', 'application/pdf', 'f-documents'),
        file('n-quay', 'Boat at the quay.jpg', 'jpeg', 'image/jpeg', 'f-photos'),
        file('n-october', 'October statement.pdf', 'pdf', 'application/pdf', 'f-statements'),
    ];
}

export function sharedWithMe(): DemoShared[] {
    return [
        {
            tenantId: JORDAN,
            id: 's-minutes',
            kind: 'file',
            name: 'Residents meeting minutes.pdf',
            sizeBytes: PDF_BYTES,
            mime: 'application/pdf',
            grantId: 'g-minutes',
            scope: 'read',
            content: 'pdf',
        },
        {
            tenantId: SAM,
            id: 's-sunset',
            kind: 'file',
            name: 'Sunset from the pier.jpg',
            sizeBytes: JPEG_BYTES,
            mime: 'image/jpeg',
            grantId: 'g-sunset',
            scope: 'read',
            content: 'jpeg',
        },
        {
            tenantId: JORDAN,
            id: 's-weekend',
            kind: 'file',
            name: 'Weekend plans.md',
            sizeBytes: textBytes('weekendPlans'),
            mime: 'text/markdown',
            grantId: 'g-weekend',
            scope: 'write',
            content: 'weekendPlans',
        },
        {
            tenantId: SAM,
            id: 's-sailing',
            kind: 'folder',
            name: 'Sailing club',
            sizeBytes: 0,
            grantId: 'g-sailing',
            scope: 'read',
        },
    ];
}

/** What sits inside a folder someone shared. */
export function sharedFolderContents(): DemoNode[] {
    return [
        {
            tenantId: SAM,
            id: 's-sailing-schedule',
            kind: 'file',
            name: 'Race schedule.md',
            sizeBytes: textBytes('raceSchedule'),
            mime: 'text/markdown',
            parent: 's-sailing',
            content: 'raceSchedule',
        },
        {
            tenantId: SAM,
            id: 's-sailing-photo',
            kind: 'file',
            name: 'Club regatta.jpg',
            sizeBytes: JPEG_BYTES,
            mime: 'image/jpeg',
            parent: 's-sailing',
            content: 'jpeg',
        },
    ];
}
