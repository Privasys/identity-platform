// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Helper for the one-off string-extraction codemod.
 *
 * The wallet's sources are stored with CRLF line endings, so a naive
 * multi-line search-and-replace written with "\n" matches nothing. This
 * normalises to LF for matching and restores the file's original convention
 * on write, keeping the diff to the lines actually changed.
 *
 * It is deliberately strict: every replacement must match exactly once. A
 * pattern that matches zero times, or more than once, throws rather than
 * silently doing the wrong thing to a screen the user reads.
 */

import { readFileSync, writeFileSync } from 'node:fs';

/** Apply `pairs` of [find, replace] to `file`, preserving its line endings. */
export function edit(file, pairs) {
    const raw = readFileSync(file, 'utf8');
    const crlf = raw.includes('\r\n');
    let s = crlf ? raw.replace(/\r\n/g, '\n') : raw;

    const problems = [];
    for (const [find, replace] of pairs) {
        const parts = s.split(find);
        if (parts.length === 1) {
            problems.push(`NOT FOUND: ${JSON.stringify(find.slice(0, 70))}`);
            continue;
        }
        if (parts.length > 2) {
            problems.push(`${parts.length - 1}x AMBIGUOUS: ${JSON.stringify(find.slice(0, 70))}`);
            continue;
        }
        s = parts.join(replace);
    }
    if (problems.length) {
        throw new Error(`${file}\n  ` + problems.join('\n  '));
    }

    writeFileSync(file, crlf ? s.replace(/\n/g, '\r\n') : s, 'utf8');
    return s;
}

/** Insert `text` immediately after the single occurrence of `anchor`. */
export function insertAfter(file, anchor, text) {
    return edit(file, [[anchor, anchor + text]]);
}
