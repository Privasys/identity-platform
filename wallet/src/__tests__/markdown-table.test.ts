// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { columnWidths, parseMarkdown } from '@/services/markdown';

describe('markdown table columns', () => {
    const table = (md: string) => {
        const b = parseMarkdown(md).find((x) => x.t === 'table');
        if (!b || b.t !== 'table') throw new Error('no table');
        return b;
    };

    it('gives every column one width, from its longest cell', () => {
        const b = table('| Capability | Privasys |\n|---|---|\n| TEE | SGX + TDX + SEV-SNP |\n| A much longer capability name | ✅ |');
        const [first, second] = columnWidths(b.head, b.rows);
        expect(first).toBeGreaterThan(second);
        expect(first).toBe(Math.round('A much longer capability name'.length * 7.5) + 20);
    });

    it('keeps a narrow column readable and a long one wrapping', () => {
        const b = table(`| a | b |\n|---|---|\n| x | ${'word '.repeat(40)} |`);
        expect(columnWidths(b.head, b.rows)).toEqual([90, 280]);
    });

    it('sizes a column a short row leaves out', () => {
        const b = table('| a | b | c |\n|---|---|---|\n| one |');
        expect(columnWidths(b.head, b.rows)).toHaveLength(3);
    });
});
