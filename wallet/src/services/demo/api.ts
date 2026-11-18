// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What the demo build answers in place of the network, the RA-TLS module and
 * the phone's hardware. Each function stands in for one real service function
 * of the same name, with the same result type, and is reached only through
 * `demo()` in ./gate (see README.md for the list of switch points).
 *
 * Nothing here signs, mints a key or writes a credential: an answer the demo
 * cannot give honestly (answering a form, an approval) is left to fail the
 * way it would without a network.
 */

import type { ConfirmedSource } from '@/services/app-form-answer';
import type { AttestationOutcome, AttestOptions, AttestationResult } from '@/services/attestation';
import type { Registry, RegistryDevice } from '@/services/devices';
import type { DriveAttestation, RemoteShareRequest } from '@/services/drive';
import type { SharedItem, StoredItem } from '@/services/drive-files';
import { useSettingsStore, type VerificationMode } from '@/stores/settings';

import {
    appForHost,
    attestationFor,
    DRIVE,
    devices,
    myDrive,
    MY_TENANT,
    sharedFolderContents,
    sharedWithMe,
    type DemoApp,
    type DemoNode,
} from './fixtures';

export { seedDemo } from './seed';

const nowSeconds = () => Math.floor(Date.now() / 1000);

/** A short pause, so a spinner shows for a moment as it would for real. */
const settle = <T>(value: T, ms = 250): Promise<T> => new Promise((r) => setTimeout(() => r(value), ms));

// ── Attestation (services/attestation) ──────────────────────────────────

export function inspectAttestation(origin: string): Promise<AttestationResult> {
    return settle(attestationFor(appForHost(origin), nowSeconds()));
}

export function attestEnclave(origin: string, opts: AttestOptions): Promise<AttestationOutcome> {
    return settle({
        status: 'verified',
        mode: opts.mode,
        challenged: opts.mode === 'challenge',
        result: attestationFor(appForHost(origin), nowSeconds()),
    });
}

/** The check before a form or an approval is shown (services/app-form-answer). */
export function confirmSource(app: { platformHost?: string }): Promise<ConfirmedSource> {
    const host = app.platformHost ?? DRIVE.host;
    const mode = useSettingsStore.getState().verificationMode;
    return settle(
        { host, attestation: attestationFor(appForHost(host), nowSeconds()), mode, challenged: mode === 'challenge' },
        600,
    );
}

// ── Drive (services/drive, services/drive-files) ────────────────────────

export function attestDrive(forceMode?: VerificationMode): Promise<DriveAttestation> {
    const mode = forceMode ?? useSettingsStore.getState().verificationMode;
    return settle({
        origin: DRIVE.host,
        displayName: DRIVE.name,
        attestation: attestationFor(DRIVE, nowSeconds()),
        appId: DRIVE.appId,
        mode,
        challenged: mode === 'challenge',
    });
}

export function listShareRequests(): Promise<{ tenantId: string; requests: RemoteShareRequest[] }> {
    return settle({ tenantId: MY_TENANT, requests: [] });
}

export function myTenant(): Promise<string> {
    return settle(MY_TENANT, 0);
}

/** Strip the fixture-only fields, so a screen gets exactly what Drive would list. */
function asItem({ parent: _parent, content: _content, ...item }: DemoNode): StoredItem {
    return item;
}

export function listFolder(tenantId: string, folderId?: string): Promise<StoredItem[]> {
    const all = [...myDrive(), ...sharedFolderContents()];
    return settle(all.filter((n) => n.tenantId === tenantId && n.parent === folderId).map(asItem));
}

export function listSharedWithMe(): Promise<SharedItem[]> {
    return settle(sharedWithMe().map(({ content: _content, ...item }) => item));
}

export async function readFile(tenantId: string, fileId: string): Promise<Uint8Array> {
    const node = [...myDrive(), ...sharedFolderContents(), ...sharedWithMe()].find(
        (n) => n.tenantId === tenantId && n.id === fileId,
    );
    if (!node?.content) throw new Error('read failed (404)');
    // Loaded here so nothing else in the demo pulls in the asset system.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { contentBytes } = require('./files') as typeof import('./files');
    return contentBytes(node.content);
}

// ── Phones (services/devices) ───────────────────────────────────────────

export function listDevices(): Promise<{ device: RegistryDevice; isThis: boolean }[]> {
    return settle(devices(nowSeconds()), 0);
}

export function syncRegistry(): Promise<Registry> {
    return settle({ identities: [], devices: devices(nowSeconds()).map((d) => d.device), revoked: [], epochs: [] }, 0);
}

export type { DemoApp };
