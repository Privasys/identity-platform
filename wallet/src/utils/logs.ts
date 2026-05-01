// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * In-memory ring buffer for the wallet's console output.
 *
 * We patch `console.{log,info,warn,error,debug}` once at app start
 * so every existing call site is captured without further changes.
 * The buffer is bounded so it cannot grow without limit on long
 * sessions; the oldest entries are dropped first.
 *
 * Two consumers:
 *  - the "View Logs" / "Export Logs" entries in Settings.
 *  - the "Report Error" preview on the Connect error screen,
 *    which uses {@link buildErrorReport} to produce a single
 *    self-contained text blob the user can copy to the clipboard.
 */

import Constants from 'expo-constants';
import { Platform } from 'react-native';

export type LogLevel = 'log' | 'info' | 'warn' | 'error' | 'debug';

export interface LogEntry {
    /** Unix epoch milliseconds at the time of capture. */
    ts: number;
    level: LogLevel;
    /** Already-stringified message. */
    msg: string;
}

const MAX_ENTRIES = 500;

/** The error reporting destination shown to the user before a manual report. */
export const REPORT_DESTINATION = 'errors.privasys.org';

const buffer: LogEntry[] = [];
let installed = false;

function stringifyArg(arg: unknown): string {
    if (arg instanceof Error) {
        return arg.stack ?? `${arg.name}: ${arg.message}`;
    }
    if (typeof arg === 'string') return arg;
    try {
        return JSON.stringify(arg);
    } catch {
        return String(arg);
    }
}

function push(level: LogLevel, args: unknown[]): void {
    const msg = args.map(stringifyArg).join(' ');
    buffer.push({ ts: Date.now(), level, msg });
    if (buffer.length > MAX_ENTRIES) {
        buffer.splice(0, buffer.length - MAX_ENTRIES);
    }
}

/** Patch the global console once. Idempotent. */
export function installLogCapture(): void {
    if (installed) return;
    installed = true;

    const levels: LogLevel[] = ['log', 'info', 'warn', 'error', 'debug'];
    for (const level of levels) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const original = (console as any)[level]?.bind(console) as
            | ((...a: unknown[]) => void)
            | undefined;
        if (!original) continue;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (console as any)[level] = (...args: unknown[]) => {
            try {
                push(level, args);
            } catch {
                // Never let logging crash the app.
            }
            original(...args);
        };
    }
}

/** Snapshot of the current buffer (oldest first). */
export function getLogs(): LogEntry[] {
    return buffer.slice();
}

/** Drop all captured entries. */
export function clearLogs(): void {
    buffer.length = 0;
}

function formatEntry(e: LogEntry): string {
    const iso = new Date(e.ts).toISOString();
    return `[${iso}] [${e.level.toUpperCase()}] ${e.msg}`;
}

/** Render the captured buffer as a single newline-joined text blob. */
export function formatLogs(entries: LogEntry[] = buffer): string {
    return entries.map(formatEntry).join('\n');
}

/** Build the version/build header common to every export. */
function buildHeader(): string {
    const extra = (Constants.expoConfig?.extra ?? {}) as Record<string, string | undefined>;
    const lines = [
        `Privasys Wallet`,
        `Version:      ${extra.CODE_VERSION ?? 'unknown'}`,
        `Build Number: ${extra.BUILD_NUMBER ?? 'unknown'}`,
        `Build ID:     ${extra.BUILD_ID ?? 'unknown'}`,
        `Stage:        ${extra.STAGE ?? 'unknown'}`,
        `Commit:       ${extra.COMMIT_HASH ?? 'unknown'}`,
        `Platform:     ${Platform.OS} ${Platform.Version}`,
        `Generated:    ${new Date().toISOString()}`,
    ];
    return lines.join('\n');
}

/** Full export — header plus every captured log line. */
export function buildLogExport(): string {
    return `${buildHeader()}\n\n${formatLogs()}\n`;
}

/**
 * Build the body of a manual error report. Includes the displayed error
 * string plus the tail of the log buffer so the on-call engineer has
 * enough context to triage without needing further round-trips.
 */
export function buildErrorReport(
    errorMessage: string | null,
    tail = 80,
): string {
    const slice = buffer.slice(-tail);
    return [
        buildHeader(),
        '',
        '── Error ──',
        errorMessage ?? '(no message)',
        '',
        `── Last ${slice.length} log lines ──`,
        formatLogs(slice),
    ].join('\n');
}
