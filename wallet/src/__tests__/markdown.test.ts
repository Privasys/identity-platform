// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { openableLink, parseInline, parseMarkdown } from '../services/markdown';

describe('parseMarkdown', () => {
    it('reads the common blocks', () => {
        const doc = parseMarkdown(
            [
                '# Title',
                '',
                'A **bold** and *em* line',
                'continued.',
                '',
                '- one',
                '- two',
                '  - nested',
                '',
                '1. first',
                '2. second',
                '',
                '> quoted',
                '',
                '```mermaid',
                'graph TD; A-->B',
                '```',
                '',
                '---',
                '',
                '| a | b |',
                '|:--|--:|',
                '| 1 | 2 |',
            ].join('\n'),
        );
        expect(doc.map((b) => b.t)).toEqual(['heading', 'para', 'list', 'list', 'quote', 'code', 'rule', 'table']);
        const list = doc[2] as Extract<(typeof doc)[number], { t: 'list' }>;
        expect(list.items).toHaveLength(2);
        expect(list.items[1].c.map((b) => b.t)).toEqual(['para', 'list']);
        const ordered = doc[3] as Extract<(typeof doc)[number], { t: 'list' }>;
        expect(ordered.ordered).toBe(true);
        expect(doc[5]).toEqual({ t: 'code', lang: 'mermaid', v: 'graph TD; A-->B' });
        const table = doc[7] as Extract<(typeof doc)[number], { t: 'table' }>;
        expect(table.align).toEqual(['left', 'right']);
        expect(table.rows).toHaveLength(1);
    });

    it('reads task boxes and setext headings', () => {
        const doc = parseMarkdown('Heading\n=======\n\n- [x] done\n- [ ] todo');
        expect(doc[0]).toMatchObject({ t: 'heading', level: 1 });
        const list = doc[1] as Extract<(typeof doc)[number], { t: 'list' }>;
        expect(list.items.map((i) => i.checked)).toEqual([true, false]);
    });

    it('keeps an unclosed fence to the end, and bounds nesting', () => {
        expect(parseMarkdown('```\nno end')).toEqual([{ t: 'code', lang: '', v: 'no end' }]);
        expect(() => parseMarkdown('>'.repeat(500) + ' deep')).not.toThrow();
        expect(() => parseMarkdown('- '.repeat(500) + 'deep')).not.toThrow();
    });
});

describe('parseInline', () => {
    it('reads emphasis, code, links and strikethrough', () => {
        expect(parseInline('**b** *i* `c` ~~d~~ [l](https://x.org)')).toEqual([
            { t: 'strong', c: [{ t: 'text', v: 'b' }] },
            { t: 'text', v: ' ' },
            { t: 'em', c: [{ t: 'text', v: 'i' }] },
            { t: 'text', v: ' ' },
            { t: 'code', v: 'c' },
            { t: 'text', v: ' ' },
            { t: 'del', c: [{ t: 'text', v: 'd' }] },
            { t: 'text', v: ' ' },
            { t: 'link', href: 'https://x.org', c: [{ t: 'text', v: 'l' }] },
        ]);
    });

    it('leaves snake_case, lone stars and escapes as text', () => {
        expect(parseInline('a_b_c 2 * 3 \\*not\\*')).toEqual([{ t: 'text', v: 'a_b_c 2 * 3 *not*' }]);
    });

    it('shows an image only as its alt text', () => {
        expect(parseInline('![chart](https://tracker.example/p.png)')).toEqual([{ t: 'text', v: '[chart]' }]);
    });
});

describe('openableLink', () => {
    it('offers only web and mail links', () => {
        expect(openableLink('https://privasys.org')).toBe(true);
        expect(openableLink('mailto:a@b.org')).toBe(true);
        for (const bad of ['javascript:alert(1)', 'privasys://x', '/relative', 'file:///etc/passwd', 'data:text/html,x']) {
            expect(openableLink(bad)).toBe(false);
        }
    });
});
