// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The holder's profile, backed up as a file they own.
 *
 * The key backup at privasys.id brings back the data root and the seed after a
 * recovery, and with them every identity and every key the wallet derives. It
 * does not bring back what the holder put IN the wallet: their details, and the
 * records of an identity check. Those live only on the phone. This file is
 * them, encrypted under a key derived from the data root, so it opens only on a
 * phone that has recovered with the phrase:
 *
 *   key  = HKDF-SHA256(root, info = "privasys-profile-backup/v1", 32)
 *   file = { format, version, createdAt, nonce, data }   (JSON)
 *   data = base64url( XChaCha20-Poly1305(key, nonce, AAD = format).encrypt(JSON) )
 *
 * Where it goes:
 *
 * - Automatically, to the app's Documents folder, which the phone's own backup
 *   carries: iCloud Backup on an iPhone, Android's app backup to the holder's
 *   Google account. A new phone restored from that backup has the file before
 *   the wallet first runs. On by default; the holder can turn it off, which
 *   deletes the file.
 * - On demand, anywhere the share sheet reaches (Files, a cloud drive, email).
 * - To the holder's Privasys Drive, when they link it from the Backup screen:
 *   the same file in a "Privasys Wallet" folder. Off by default, because Drive
 *   needs a Privasys account with billing and the wallet never requires it.
 *   Linking connects to Drive once, on the holder's tap; afterwards the file
 *   follows the profile whenever a Drive session is open, never prompting.
 *
 * What it holds: the profile (details, linked providers, photo) without the
 * seed, which the key backup carries, and the identity-check records. Not the
 * details kept for services: those include passwords, and a password in a
 * backup is one more place a password exists (see setup-keep.ts).
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as Crypto from 'expo-crypto';
import { File, Paths } from 'expo-file-system';

import { currentDrive, ensureDrive, type DriveSession } from '@/services/drive';
import { loadKycRecords, saveKycRecord, type KycRecord } from '@/services/kyc';
import { ensureDataRoot, peekDataRoot } from '@/services/sovereign';
import { useProfileStore, type UserProfile } from '@/stores/profile';
import { base64urlToBytes, bytesToBase64url } from '@/utils/encoding';
import * as SecureStore from '@/utils/storage';

export const BACKUP_FORMAT = 'privasys-wallet-backup';
const BACKUP_VERSION = 1;
const KEY_INFO = 'privasys-profile-backup/v1';
/** The automatic copy, in the folder the phone's own backup carries. */
export const AUTO_BACKUP_NAME = 'privasys-wallet-backup.json';
const AUTO_OFF_KEY = 'privasys.profile-backup.auto-off';
const DRIVE_ON_KEY = 'privasys.profile-backup.drive-on';
const LAST_DRIVE_KEY = 'privasys.profile-backup.last-drive';
/** The folder and file the copy lives under in the holder's Drive. */
export const DRIVE_FOLDER = 'Privasys Wallet';
export const DRIVE_FILE = 'wallet-backup.json';
const LAST_AUTO_KEY = 'privasys.profile-backup.last-auto';

const utf8 = (s: string) => new TextEncoder().encode(s);

/** What a backup carries. The profile has no seed and no device DID. */
export interface BackupContents {
    profile: Omit<UserProfile, 'pairwiseSeed' | 'did'> | null;
    kycRecords: KycRecord[];
}

interface BackupFile {
    format: typeof BACKUP_FORMAT;
    version: number;
    createdAt: number;
    nonce: string;
    data: string;
}

export class BackupError extends Error {
    constructor(
        public readonly reason: 'not-a-backup' | 'wrong-wallet' | 'no-root' | 'no-profile' | 'no-drive' | 'none-in-drive',
        message: string,
    ) {
        super(message);
    }
}

function keyFrom(root: Uint8Array): Uint8Array {
    return hkdf(sha256, root, undefined, utf8(KEY_INFO), 32);
}

/** Gather what the backup carries from this phone. */
export async function collectContents(): Promise<BackupContents> {
    const profile = useProfileStore.getState().profile;
    let kept: BackupContents['profile'] = null;
    if (profile) {
        const { pairwiseSeed: _seed, did: _did, ...rest } = profile;
        kept = rest;
    }
    return { profile: kept, kycRecords: await loadKycRecords() };
}

/** Encrypt contents under the data root's backup key. Exported for tests. */
export function sealContents(root: Uint8Array, contents: BackupContents, now = Date.now()): string {
    const nonce = new Uint8Array(Crypto.getRandomBytes(24));
    const ct = xchacha20poly1305(keyFrom(root), nonce, utf8(BACKUP_FORMAT)).encrypt(utf8(JSON.stringify(contents)));
    const file: BackupFile = {
        format: BACKUP_FORMAT,
        version: BACKUP_VERSION,
        createdAt: Math.floor(now / 1000),
        nonce: bytesToBase64url(nonce),
        data: bytesToBase64url(ct),
    };
    return JSON.stringify(file);
}

/** Decrypt a backup file's text. Throws BackupError. Exported for tests. */
export function openContents(root: Uint8Array, text: string): BackupContents & { createdAt: number } {
    let file: BackupFile;
    try {
        file = JSON.parse(text) as BackupFile;
    } catch {
        throw new BackupError('not-a-backup', 'this file is not a Privasys Wallet backup');
    }
    if (file?.format !== BACKUP_FORMAT || file.version !== BACKUP_VERSION || !file.nonce || !file.data) {
        throw new BackupError('not-a-backup', 'this file is not a Privasys Wallet backup');
    }
    try {
        const pt = xchacha20poly1305(keyFrom(root), base64urlToBytes(file.nonce), utf8(BACKUP_FORMAT)).decrypt(
            base64urlToBytes(file.data),
        );
        const contents = JSON.parse(new TextDecoder().decode(pt)) as BackupContents;
        return { ...contents, kycRecords: contents.kycRecords ?? [], createdAt: file.createdAt };
    } catch {
        throw new BackupError('wrong-wallet', 'this backup belongs to another wallet, or was changed');
    }
}

/** The encrypted backup of this phone, as file text. */
export async function buildBackup(): Promise<string> {
    return sealContents(await ensureDataRoot(), await collectContents());
}

/**
 * Put a backup's contents into this wallet. Details are added beside what is
 * already here, never over it (the same merge a provider import uses), so a
 * restore cannot erase something the holder entered since. Returns how many
 * details and records came back.
 */
export async function restoreContents(contents: BackupContents): Promise<{ attributes: number; records: number }> {
    const store = useProfileStore.getState();
    if (!store.profile) throw new BackupError('no-profile', 'finish setting up the wallet before restoring a backup');
    let attributes = 0;
    const incoming = contents.profile;
    if (incoming) {
        const { displayName, email, avatarUri } = store.profile;
        store.updateProfile({
            displayName: displayName || incoming.displayName,
            email: email || incoming.email,
            avatarUri: avatarUri || incoming.avatarUri,
        });
        for (const p of incoming.linkedProviders ?? []) {
            if (!useProfileStore.getState().profile?.linkedProviders.some((l) => l.provider === p.provider)) {
                store.linkProvider(p);
            }
        }
        for (const attr of incoming.attributes ?? []) {
            const r = useProfileStore.getState().mergeAttribute(attr, true);
            if (r.status === 'added' || r.status === 'added-value') attributes++;
        }
    }
    let records = 0;
    const held = new Set((await loadKycRecords()).map((r) => r.jti));
    for (const rec of contents.kycRecords) {
        if (!held.has(rec.jti)) {
            await saveKycRecord(rec);
            records++;
        }
    }
    return { attributes, records };
}

/** Open a backup file's text with this phone's data root and restore it. */
export async function restoreFromText(text: string): Promise<{ attributes: number; records: number }> {
    const root = await peekDataRoot();
    if (!root) throw new BackupError('no-root', 'recover your wallet with its phrase before restoring a backup');
    return restoreContents(openContents(root, text));
}

// ---------------------------------------------------------------- automatic copy

function autoFile(): File {
    return new File(Paths.document, AUTO_BACKUP_NAME);
}

export async function isAutoBackupOn(): Promise<boolean> {
    return (await SecureStore.getItemAsync(AUTO_OFF_KEY)) !== '1';
}

/** When the automatic copy was last written, epoch seconds, or null. */
export async function lastAutoBackupAt(): Promise<number | null> {
    const v = await SecureStore.getItemAsync(LAST_AUTO_KEY);
    return v ? Number(v) : null;
}

/** Turn the automatic copy on (written at once) or off (deleted at once). */
export async function setAutoBackup(on: boolean): Promise<void> {
    if (on) {
        await SecureStore.deleteItemAsync(AUTO_OFF_KEY);
        await writeAutoBackup();
    } else {
        await SecureStore.setItemAsync(AUTO_OFF_KEY, '1');
        try {
            const f = autoFile();
            if (f.exists) f.delete();
        } catch (e: any) {
            console.warn('[profile-backup] could not delete the automatic copy:', e?.message ?? e);
        }
        await SecureStore.deleteItemAsync(LAST_AUTO_KEY);
    }
}

let writing: Promise<void> | null = null;

/**
 * Rewrite the automatic copy if it is on and there is a profile. Silent and
 * best effort: the next change tries again.
 */
export function writeAutoBackup(): Promise<void> {
    if (writing) return writing;
    writing = (async () => {
        try {
            const profile = useProfileStore.getState().profile;
            if (!(await isAutoBackupOn()) || !profile) return;
            // A copy already here may be the only one of this holder's
            // profile: a phone restored from its own backup has it before the
            // wallet runs. Bring it in before replacing it, and never replace
            // one this wallet cannot open while the profile is still empty
            // (not recovered yet): that would trade the holder's details for
            // nothing. A wallet with details of its own is a new wallet, and
            // its copy wins.
            const existing = readAutoBackup();
            if (existing) {
                const root = await peekDataRoot();
                let opens = false;
                try {
                    if (root) {
                        openContents(root, existing);
                        opens = true;
                    }
                } catch {
                    opens = false;
                }
                if (opens) await restoreFromAutoBackupIfEmpty();
                else if (profile.attributes.length === 0) return;
            }
            const text = await buildBackup();
            const f = autoFile();
            if (!f.exists) f.create();
            f.write(text);
            await SecureStore.setItemAsync(LAST_AUTO_KEY, String(Math.floor(Date.now() / 1000)));
            if (await isDriveBackupOn()) void saveToDrive(text, false);
        } catch (e: any) {
            console.warn('[profile-backup] automatic copy failed:', e?.message ?? e);
        }
    })().finally(() => {
        writing = null;
    });
    return writing;
}

/** The automatic copy's text, if the phone has one (a restored phone may). */
export function readAutoBackup(): string | null {
    try {
        const f = autoFile();
        return f.exists ? f.textSync() : null;
    } catch {
        return null;
    }
}

let watching = false;

/**
 * Keep the automatic copy current: rewrite it a few seconds after the profile
 * last changed. Called once at start-up.
 */
export function watchProfileForBackup(): void {
    if (watching) return;
    watching = true;
    let timer: ReturnType<typeof setTimeout> | null = null;
    useProfileStore.subscribe((state, prev) => {
        if (state.profile === prev.profile || !state.profile) return;
        // A profile just created (after a recovery, on a restored phone) picks
        // up the copy the phone's backup brought.
        if (!prev.profile) void restoreFromAutoBackupIfEmpty();
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => void writeAutoBackup(), 5000);
    });
}

// ---------------------------------------------------------------- Privasys Drive

export async function isDriveBackupOn(): Promise<boolean> {
    return (await SecureStore.getItemAsync(DRIVE_ON_KEY)) === '1';
}

export async function lastDriveBackupAt(): Promise<number | null> {
    const v = await SecureStore.getItemAsync(LAST_DRIVE_KEY);
    return v ? Number(v) : null;
}

async function backupFolder(s: DriveSession, create: boolean): Promise<string | null> {
    const root = await s.drive.listRoot(s.tenant.id);
    const found = root.find((n) => n.kind === 'folder' && n.name === DRIVE_FOLDER);
    if (found) return found.id;
    if (!create) return null;
    return (await s.drive.createFolder(s.tenant.id, DRIVE_FOLDER)).id;
}

/**
 * Write the copy to the holder's Drive. Interactive (the holder's tap) may
 * connect to Drive; otherwise only an open session is used, so this never
 * prompts. Returns whether it was saved. Older copies are removed only after
 * the new one is in place.
 */
export async function saveToDrive(text?: string, interactive = true): Promise<boolean> {
    try {
        const s = interactive ? await ensureDrive() : currentDrive();
        if (!s) {
            if (interactive) throw new BackupError('no-drive', 'Privasys Drive is not available');
            return false;
        }
        const body = text ?? (await buildBackup());
        const folder = (await backupFolder(s, true)) as string;
        const before = await s.drive.listFolder(s.tenant.id, folder);
        const saved = await s.drive.uploadFile(s.tenant.id, DRIVE_FILE, body, {
            parentId: folder,
            mime: 'application/json',
        });
        for (const old of before) {
            if (old.kind === 'file' && old.name === DRIVE_FILE && old.id !== saved.id) {
                await s.drive.deleteNode(s.tenant.id, old.id).catch(() => undefined);
            }
        }
        await SecureStore.setItemAsync(LAST_DRIVE_KEY, String(Math.floor(Date.now() / 1000)));
        return true;
    } catch (e: any) {
        if (interactive) throw e;
        console.warn('[profile-backup] Drive copy failed:', e?.message ?? e);
        return false;
    }
}

/** Link (save now, on the holder's tap) or unlink the Drive copy. */
export async function setDriveBackup(on: boolean): Promise<void> {
    if (on) {
        await saveToDrive(undefined, true);
        await SecureStore.setItemAsync(DRIVE_ON_KEY, '1');
    } else {
        await SecureStore.deleteItemAsync(DRIVE_ON_KEY);
    }
}

/** Fetch the copy from the holder's Drive and restore it. */
export async function restoreFromDrive(): Promise<{ attributes: number; records: number }> {
    const s = await ensureDrive();
    if (!s) throw new BackupError('no-drive', 'Privasys Drive is not available');
    const folder = await backupFolder(s, false);
    const file = folder
        ? (await s.drive.listFolder(s.tenant.id, folder)).find((n) => n.kind === 'file' && n.name === DRIVE_FILE)
        : undefined;
    if (!file) throw new BackupError('none-in-drive', 'there is no backup in this Drive');
    const bytes = await s.drive.downloadBytes(s.tenant.id, file.id);
    return restoreFromText(new TextDecoder().decode(bytes));
}

const AUTO_RESTORED_KEY = 'privasys.profile-backup.auto-restored';

/**
 * On a phone restored from the phone's own backup, the automatic copy is
 * already in Documents when the wallet first runs. Once a recovery has brought
 * the data root back and a profile exists with nothing in it, bring the
 * copy's contents in, once. Silent: a copy that does not open (another
 * wallet's) is left alone.
 */
export async function restoreFromAutoBackupIfEmpty(): Promise<number> {
    try {
        if (await SecureStore.getItemAsync(AUTO_RESTORED_KEY)) return 0;
        const profile = useProfileStore.getState().profile;
        const root = await peekDataRoot();
        if (!profile || !root || profile.attributes.length > 0) return 0;
        const text = readAutoBackup();
        if (!text) return 0;
        const r = await restoreContents(openContents(root, text));
        await SecureStore.setItemAsync(AUTO_RESTORED_KEY, '1');
        return r.attributes + r.records;
    } catch (e: any) {
        console.warn('[profile-backup] automatic restore skipped:', e?.message ?? e);
        return 0;
    }
}

/** Part of Clear All Data: the copy is this identity's, not the next one's. */
export async function clearProfileBackupLocalState(): Promise<void> {
    try {
        const f = autoFile();
        if (f.exists) f.delete();
    } catch {
        /* nothing to delete */
    }
    await SecureStore.deleteItemAsync(AUTO_OFF_KEY);
    await SecureStore.deleteItemAsync(LAST_AUTO_KEY);
    await SecureStore.deleteItemAsync(AUTO_RESTORED_KEY);
    await SecureStore.deleteItemAsync(DRIVE_ON_KEY);
    await SecureStore.deleteItemAsync(LAST_DRIVE_KEY);
}
