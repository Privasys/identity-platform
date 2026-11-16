// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * App forms: a question an app asks the holder, answered in the wallet.
 *
 * The app supplies data, never code. Its form is built only from components
 * the wallet draws itself (plain text, label and value fields, attributes
 * under the wallet's own labels, a divider) and buttons whose kind is on a
 * closed list; the wallet writes every button's label. The IdP refuses a form
 * outside this vocabulary, and the wallet checks again here, so a form that
 * reaches the screen is one the wallet knows how to draw safely.
 *
 * Answering is the holder's signed choice for that form and that action:
 *   1. the wallet asks the IdP to begin, naming the action; the passkey
 *      challenge commits to the sent form, its app, its reference, its digest
 *      and the action;
 *   2. the holder signs with the identity's privasys.id passkey (biometric);
 *   3. the IdP verifies, takes the form once, and returns an answer token;
 *   4. the wallet attests the app's platform host, checks it is the app that
 *      asked, and posts the token to the form's callback over RA-TLS.
 * The digest the wallet computes over the exact form string it drew must
 * equal the one the IdP binds, or the wallet refuses to sign: what the holder
 * saw is what they answer.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import { CANONICAL_KEYS } from '@/services/attributes';

export const APP_FORM_TYPE = 'app-form';

export type FormActionKind = 'approve' | 'deny' | 'accept' | 'decline' | 'confirm';
const ACTION_KINDS: FormActionKind[] = ['approve', 'deny', 'accept', 'decline', 'confirm'];

export type FormBlock =
    | { type: 'text'; text: string }
    | { type: 'fields'; items: { label: string; value: string }[] }
    | { type: 'attributes'; values: [string, string][] }
    | { type: 'divider' };

export interface AppForm {
    id: string;
    title: string;
    blocks: FormBlock[];
    actions: { id: string; kind: FormActionKind }[];
    callback: string;
    link?: string;
    /** Hex SHA-256 of the exact form string. */
    digest: string;
}

const MAX_FORM_BYTES = 3 << 10;

/** Hex SHA-256 of the form string's UTF-8 bytes, as the IdP and the app compute it. */
export function formDigest(form: string): string {
    return bytesToHex(sha256(new TextEncoder().encode(form)));
}

// Bidirectional embeddings, overrides, isolates and marks; zero-width
// characters; the soft hyphen; and every control character but the newline
// where it is allowed.
const INVISIBLE = /[‪-‮⁦-⁩‎‏؜​-‍⁠﻿­]/;
const CONTROL = /[\u0000-\u0009\u000B-\u001F\u007F-\u009F]/;
const CONTROL_OR_NEWLINE = /[\u0000-\u001F\u007F-\u009F]/;

export function cleanText(v: unknown, max: number, newlines: boolean): string | null {
    if (typeof v !== 'string' || v === '') return null;
    if ([...v].length > max) return null;
    if (INVISIBLE.test(v) || (newlines ? CONTROL : CONTROL_OR_NEWLINE).test(v)) return null;
    return v;
}

export function isPath(p: unknown): p is string {
    return typeof p === 'string' && p.startsWith('/') && !p.startsWith('//') && p.length <= 512 && !/[\\\s]/.test(p);
}

export function onlyKeys(o: Record<string, unknown>, allowed: string[]): boolean {
    return Object.keys(o).every((k) => allowed.includes(k));
}

/** Parse and check a form string, or null: a form the wallet would not draw
 *  is never shown, whatever the IdP accepted. */
export function parseForm(form: unknown): AppForm | null {
    if (typeof form !== 'string' || form === '' || new TextEncoder().encode(form).length > MAX_FORM_BYTES) return null;
    let raw: Record<string, unknown>;
    try {
        raw = JSON.parse(form);
    } catch {
        return null;
    }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
    if (!onlyKeys(raw, ['v', 'id', 'title', 'blocks', 'actions', 'callback', 'link'])) return null;
    if (raw.v !== 1 || typeof raw.id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(raw.id)) return null;
    const title = cleanText(raw.title, 80, false);
    if (!title) return null;

    const blocks: FormBlock[] = [];
    const rawBlocks = raw.blocks ?? [];
    if (!Array.isArray(rawBlocks) || rawBlocks.length > 12) return null;
    for (const b of rawBlocks as Record<string, unknown>[]) {
        if (!b || typeof b !== 'object') return null;
        switch (b.type) {
            case 'divider':
                if (!onlyKeys(b, ['type'])) return null;
                blocks.push({ type: 'divider' });
                break;
            case 'text': {
                const text = cleanText(b.text, 600, true);
                if (!onlyKeys(b, ['type', 'text']) || !text) return null;
                blocks.push({ type: 'text', text });
                break;
            }
            case 'fields': {
                if (!onlyKeys(b, ['type', 'items']) || !Array.isArray(b.items) || b.items.length === 0 || b.items.length > 8) {
                    return null;
                }
                const items: { label: string; value: string }[] = [];
                for (const it of b.items as Record<string, unknown>[]) {
                    if (!it || typeof it !== 'object' || !onlyKeys(it, ['label', 'value'])) return null;
                    const label = cleanText(it.label, 40, false);
                    const value = cleanText(it.value, 200, false);
                    if (!label || !value) return null;
                    items.push({ label, value });
                }
                blocks.push({ type: 'fields', items });
                break;
            }
            case 'attributes': {
                const v = b.values;
                if (!onlyKeys(b, ['type', 'values']) || !v || typeof v !== 'object' || Array.isArray(v)) return null;
                const entries = Object.entries(v as Record<string, unknown>);
                if (entries.length === 0 || entries.length > 12) return null;
                const values: [string, string][] = [];
                for (const [key, value] of entries) {
                    const clean = cleanText(value, 200, false);
                    if (!/^[a-z][a-z0-9_]{0,63}$/.test(key) || !clean) return null;
                    // Only keys the wallet can label itself are shown.
                    if (CANONICAL_KEYS.has(key)) values.push([key, clean]);
                }
                blocks.push({ type: 'attributes', values });
                break;
            }
            default:
                return null;
        }
    }

    if (!Array.isArray(raw.actions) || raw.actions.length === 0 || raw.actions.length > 3) return null;
    const actions: { id: string; kind: FormActionKind }[] = [];
    const ids = new Set<string>();
    const kinds = new Set<string>();
    for (const a of raw.actions as Record<string, unknown>[]) {
        if (!a || typeof a !== 'object' || !onlyKeys(a, ['id', 'kind'])) return null;
        if (typeof a.id !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(a.id) || ids.has(a.id)) return null;
        if (!ACTION_KINDS.includes(a.kind as FormActionKind) || kinds.has(a.kind as string)) return null;
        ids.add(a.id);
        kinds.add(a.kind as string);
        actions.push({ id: a.id, kind: a.kind as FormActionKind });
    }
    if (!isPath(raw.callback)) return null;
    if (raw.link !== undefined && raw.link !== '' && !isPath(raw.link)) return null;

    return {
        id: raw.id,
        title,
        blocks,
        actions,
        callback: raw.callback,
        link: typeof raw.link === 'string' && raw.link ? raw.link : undefined,
        digest: formDigest(form),
    };
}

/** Read an app-form payload {kind, form}. */
export function readFormPayload(payload: Record<string, unknown> | null | undefined): AppForm | null {
    return payload ? parseForm(payload.form) : null;
}

/** Destructive actions are drawn as such, whatever the app would prefer. */
export function isDeclining(kind: FormActionKind): boolean {
    return kind === 'deny' || kind === 'decline';
}
