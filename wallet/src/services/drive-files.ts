// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The wallet's storage, on Privasys Drive.
 *
 * Drive is where the holder keeps what does not fit on a phone: their files,
 * what others share with them, and (later) what the wallet itself stores
 * there. Every part of the wallet reads Drive through this service, so each
 * new use builds on one typed interface rather than on its own calls.
 *
 * Trust is the connection's: Drive is reached over RA-TLS, its release and
 * app id checked (services/drive, attestDrive), with Drive's own key. Files
 * arrive as plaintext from the enclave over that channel; a copy written for
 * a viewer lives in the wallet's cache and is deleted when the viewer closes.
 *
 * Drive knows the holder by one subject whichever way they reach it: the
 * wallet's `privasys-drive` client and Drive web's `privasys-platform` are
 * both legacy-shared today, and must move to their own subjects together.
 */

import { Directory, File, Paths } from 'expo-file-system';
import type { TFunction } from 'i18next';

import { ensureDrive } from '@/services/drive';
import { getDriveToken, isDriveAppId, isDriveHost } from '@/services/platform-token';
import { makeRaTlsFetch, requestBytes } from '../../modules/native-ratls/src/index';

/** A file or folder as the wallet lists it. */
export interface StoredItem {
    tenantId: string;
    id: string;
    kind: 'file' | 'folder';
    name: string;
    sizeBytes: number;
    mime?: string;
}

/** Something shared with the holder: where it lives, and the access given. */
export interface SharedItem extends StoredItem {
    grantId: string;
    /** "read" or "write". */
    scope: string;
}

/** Drive's ids, as Drive web also accepts them in a link. */
export const DRIVE_ID = /^[A-Za-z0-9-]{1,64}$/;

async function driveFetch(path: string, init?: RequestInit): Promise<Response> {
    const s = await ensureDrive();
    if (!s) throw new Error('Drive is unavailable');
    const token = await getDriveToken();
    const raFetch = makeRaTlsFetch({ enclaveHost: s.origin, platformFetch: fetch });
    return raFetch(`https://${s.origin}${path}`, {
        ...init,
        headers: { ...(init?.headers as Record<string, string> | undefined), Authorization: `Bearer ${token}` },
    });
}

async function json<T>(res: Response, what: string): Promise<T> {
    if (!res.ok) throw new Error(`${what} failed (${res.status})`);
    return (await res.json()) as T;
}

interface NodeJSON {
    id: string;
    tenant_id?: string;
    kind: string;
    name: string;
    size_bytes?: number;
    mime_hint?: string;
}

function toItem(n: NodeJSON, tenantId: string): StoredItem | null {
    if (typeof n?.id !== 'string' || typeof n.name !== 'string') return null;
    return {
        tenantId: n.tenant_id || tenantId,
        id: n.id,
        kind: n.kind === 'folder' ? 'folder' : 'file',
        name: n.name,
        sizeBytes: typeof n.size_bytes === 'number' ? n.size_bytes : 0,
        mime: n.mime_hint || undefined,
    };
}

/** Folders first, then by name. */
export function sortItems<T extends StoredItem>(items: T[]): T[] {
    return [...items].sort((a, b) =>
        a.kind !== b.kind ? (a.kind === 'folder' ? -1 : 1) : a.name.localeCompare(b.name),
    );
}

/** The holder's own drive: its tenant id, for listing from the top. */
export async function myTenant(): Promise<string> {
    const s = await ensureDrive();
    if (!s) throw new Error('Drive is unavailable');
    return s.tenant.id;
}

/** A folder's contents, in the holder's drive or in a share; the top of a
 *  drive when `folderId` is undefined. */
export async function listFolder(tenantId: string, folderId?: string): Promise<StoredItem[]> {
    const t = encodeURIComponent(tenantId);
    const path = folderId ? `/v1/tenants/${t}/folders/${encodeURIComponent(folderId)}` : `/v1/tenants/${t}/root`;
    const body = await json<NodeJSON[] | { nodes?: NodeJSON[] }>(await driveFetch(path), 'list');
    const rows = Array.isArray(body) ? body : body.nodes ?? [];
    return sortItems(rows.map((n) => toItem(n, tenantId)).filter((x): x is StoredItem => x !== null));
}

/** What others shared with the holder, across every drive. */
export async function listSharedWithMe(): Promise<SharedItem[]> {
    const body = await json<{ shared?: Record<string, unknown>[] }>(await driveFetch('/v1/shared'), 'shared');
    const out: SharedItem[] = [];
    for (const r of body.shared ?? []) {
        if (typeof r.tenant_id !== 'string' || typeof r.node_id !== 'string' || typeof r.name !== 'string' || !r.name) continue;
        out.push({
            tenantId: r.tenant_id,
            id: r.node_id,
            kind: r.kind === 'folder' ? 'folder' : 'file',
            name: r.name,
            sizeBytes: typeof r.size_bytes === 'number' ? r.size_bytes : 0,
            grantId: typeof r.grant_id === 'string' ? r.grant_id : '',
            scope: typeof r.scope === 'string' ? r.scope : 'read',
        });
    }
    return sortItems(out);
}

/** A file's plaintext, from the enclave over the attested channel, as bytes
 *  (the text calls cannot carry a binary body). */
export async function readFile(tenantId: string, fileId: string): Promise<Uint8Array> {
    const s = await ensureDrive();
    if (!s) throw new Error('Drive is unavailable');
    const token = await getDriveToken();
    const res = await requestBytes(
        'GET',
        s.origin,
        443,
        `/v1/tenants/${encodeURIComponent(tenantId)}/files/${encodeURIComponent(fileId)}`,
        '',
        { Authorization: `Bearer ${token}` },
    );
    if (res.status < 200 || res.status >= 300) throw new Error(`read failed (${res.status})`);
    return res.body;
}

/** The folder in the cache where viewer copies live. */
function viewerDir(): Directory {
    const d = new Directory(Paths.cache, 'drive-view');
    if (!d.exists) d.create({ intermediates: true });
    return d;
}

/** A name safe for the file system, keeping the extension viewers use. */
export function safeFileName(name: string): string {
    const cleaned = name.replace(/[/\\:*?"<>|\u0000-\u001f]/g, '_').trim();
    return (cleaned || 'file').slice(-120);
}

/** Write a file's plaintext to the cache for a viewer. The caller deletes it
 *  (`discardCopy`) when the viewer closes. */
export async function copyForViewing(item: StoredItem): Promise<File> {
    const bytes = await readFile(item.tenantId, item.id);
    const dir = new Directory(viewerDir(), `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
    dir.create();
    const f = new File(dir, safeFileName(item.name));
    f.write(bytes);
    return f;
}

/** Delete a viewer copy and anything drawn from it beside it. */
export function discardCopy(f: File): void {
    try {
        const parent = f.parentDirectory;
        if (parent.exists) parent.delete();
    } catch {
        // The cache is the OS's to clear in the end.
    }
}

/** Clear every viewer copy, for a wipe or an app start. */
export function clearViewerCopies(): void {
    try {
        const d = new Directory(Paths.cache, 'drive-view');
        if (d.exists) d.delete();
    } catch {
        // as above
    }
}

export type FileKind = 'image' | 'pdf' | 'markdown' | 'text' | 'other';

/** What kind of viewer a file needs, from its MIME hint or its name. */
export function fileKind(item: { name: string; mime?: string }): FileKind {
    const mime = (item.mime ?? '').toLowerCase();
    const ext = item.name.toLowerCase().split('.').pop() ?? '';
    if (mime.startsWith('image/') || ['png', 'jpg', 'jpeg', 'gif', 'webp', 'heic', 'heif'].includes(ext)) return 'image';
    if (mime === 'application/pdf' || ext === 'pdf') return 'pdf';
    if (mime === 'text/markdown' || ['md', 'markdown'].includes(ext)) return 'markdown';
    if (mime.startsWith('text/') || ['txt', 'csv', 'json', 'log'].includes(ext)) return 'text';
    return 'other';
}

/** A Drive link the wallet opens in its own screens: `/#shared/<tenant>/<node>`
 *  (an approved access request) or `/#shared`. Anything else is not Drive's
 *  to open here. */
export function parseDriveLink(path: string | undefined): { shared: true; tenantId?: string; nodeId?: string } | null {
    if (!path) return null;
    const m = /^\/#shared(?:\/([^/]+)\/([^/]+))?$/.exec(path);
    if (!m) return null;
    if (m[1] === undefined) return { shared: true };
    if (!DRIVE_ID.test(m[1]) || !DRIVE_ID.test(m[2])) return null;
    return { shared: true, tenantId: m[1], nodeId: m[2] };
}

/** File size for a list row: the unit translated, the number not localised
 *  (thousands separators inside a technical value only invite mistakes). */
export function formatSize(bytes: number, t: TFunction): string {
    if (!bytes) return '';
    if (bytes < 1024) return t('drive.sizeBytes', { value: bytes });
    if (bytes < 1024 * 1024) return t('drive.sizeKb', { value: (bytes / 1024).toFixed(0) });
    return t('drive.sizeMb', { value: (bytes / (1024 * 1024)).toFixed(1) });
}

/**
 * Where in the wallet a Drive link opens, or null for a link the wallet does
 * not open itself. Only a link from Drive (its attested app id, or the host
 * the wallet resolved for it), with a path the wallet knows. The Drive screen then checks that `from` (the app
 * id the platform named) is the app id Drive's attestation carries.
 */
export async function driveRouteFor(
    appHost: string | undefined,
    path: string | undefined,
    appId: string | undefined,
): Promise<{ pathname: '/drive'; params: Record<string, string> } | null> {
    const link = parseDriveLink(path);
    if (!link) return null;
    // Drive is known by the app id its attestation carried (a push's host may
    // be Drive's custom domain), or by the platform host the wallet resolved.
    const fromDrive = (!!appId && (await isDriveAppId(appId))) || (!!appHost && (await isDriveHost(appHost)));
    if (!fromDrive) return null;
    const params: Record<string, string> = { section: 'shared' };
    if (link.tenantId && link.nodeId) {
        params.tenant = link.tenantId;
        params.node = link.nodeId;
    }
    if (appId) params.from = appId;
    return { pathname: '/drive', params };
}
