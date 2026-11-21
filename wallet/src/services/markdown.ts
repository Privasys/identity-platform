// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A small Markdown parser for showing a document in the wallet, with no
 * dependency. It covers what documents use: headings, paragraphs, lists
 * (nested by indent, ordered or not, task boxes), block quotes, fenced and
 * indented code, rules and GitHub tables; inline bold, italic,
 * strikethrough, code and links. HTML, images and footnotes are not drawn:
 * HTML shows as text, an image as its alt text, so a document can never make
 * the wallet load anything.
 *
 * Diagrams and maths are not rendered (that would need a browser engine in
 * the wallet); a ```mermaid block or $$ maths shows as code.
 */

export type Inline =
    | { t: 'text'; v: string }
    | { t: 'strong'; c: Inline[] }
    | { t: 'em'; c: Inline[] }
    | { t: 'del'; c: Inline[] }
    | { t: 'code'; v: string }
    | { t: 'link'; href: string; c: Inline[] };

export type Block =
    | { t: 'heading'; level: number; c: Inline[] }
    | { t: 'para'; c: Inline[] }
    | { t: 'code'; lang: string; v: string }
    | { t: 'quote'; c: Block[] }
    | { t: 'list'; ordered: boolean; start: number; items: { checked?: boolean; c: Block[] }[] }
    | { t: 'rule' }
    | { t: 'table'; align: ('left' | 'center' | 'right' | null)[]; head: Inline[][]; rows: Inline[][][] };

const FENCE = /^ {0,3}(`{3,}|~{3,})\s*([^`\s]*)[^`]*$/;
const HEADING = /^ {0,3}(#{1,6})(?:\s+(.*?))?\s*#*\s*$/;
const RULE = /^ {0,3}([-*_])(?:\s*\1){2,}\s*$/;
const QUOTE = /^ {0,3}> ?(.*)$/;
const ITEM = /^( *)([-*+]|\d{1,9}[.)])\s+(.*)$/;
const TABLE_SEP = /^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)*\|?\s*$/;

const MAX_DEPTH = 8;

/** Parse a document. Bounded: nesting stops at MAX_DEPTH. */
export function parseMarkdown(src: string, depth = 0): Block[] {
    const lines = src.replace(/\r\n?/g, '\n').replace(/\t/g, '    ').split('\n');
    const out: Block[] = [];
    let i = 0;
    let para: string[] = [];
    const flush = () => {
        if (para.length) out.push({ t: 'para', c: parseInline(para.join('\n').trim()) });
        para = [];
    };

    while (i < lines.length) {
        const line = lines[i];
        if (!line.trim()) {
            flush();
            i++;
            continue;
        }
        const fence = FENCE.exec(line);
        if (fence) {
            flush();
            const marker = fence[1];
            const body: string[] = [];
            i++;
            while (i < lines.length && !lines[i].trimStart().startsWith(marker)) body.push(lines[i++]);
            i++; // the closing fence, or the end
            out.push({ t: 'code', lang: fence[2].toLowerCase(), v: body.join('\n') });
            continue;
        }
        if (/^ {4}/.test(line) && para.length === 0) {
            const body: string[] = [];
            while (i < lines.length && (/^ {4}/.test(lines[i]) || !lines[i].trim())) body.push(lines[i++].slice(4));
            while (body.length && !body[body.length - 1].trim()) body.pop();
            out.push({ t: 'code', lang: '', v: body.join('\n') });
            continue;
        }
        const h = HEADING.exec(line);
        if (h) {
            flush();
            out.push({ t: 'heading', level: h[1].length, c: parseInline(h[2] ?? '') });
            i++;
            continue;
        }
        // Setext headings: a paragraph line underlined with === or ---.
        if (para.length === 1 && /^ {0,3}(=+|-+)\s*$/.test(line)) {
            out.push({ t: 'heading', level: line.trim()[0] === '=' ? 1 : 2, c: parseInline(para[0].trim()) });
            para = [];
            i++;
            continue;
        }
        if (RULE.test(line)) {
            flush();
            out.push({ t: 'rule' });
            i++;
            continue;
        }
        if (QUOTE.test(line)) {
            flush();
            const body: string[] = [];
            while (i < lines.length && lines[i].trim() && QUOTE.test(lines[i])) body.push(QUOTE.exec(lines[i++])![1]);
            out.push({ t: 'quote', c: depth < MAX_DEPTH ? parseMarkdown(body.join('\n'), depth + 1) : [{ t: 'para', c: [{ t: 'text', v: body.join('\n') }] }] });
            continue;
        }
        if (line.includes('|') && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1]) && lines[i + 1].includes('-')) {
            flush();
            const cells = (l: string) => {
                let s = l.trim();
                if (s.startsWith('|')) s = s.slice(1);
                if (s.endsWith('|') && !s.endsWith('\\|')) s = s.slice(0, -1);
                return s.split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, '|'));
            };
            const head = cells(line);
            const align = cells(lines[i + 1]).map((c) =>
                c.startsWith(':') && c.endsWith(':') ? 'center' : c.endsWith(':') ? 'right' : c.startsWith(':') ? 'left' : null,
            );
            i += 2;
            const rows: Inline[][][] = [];
            while (i < lines.length && lines[i].trim() && lines[i].includes('|')) {
                const r = cells(lines[i++]);
                rows.push(head.map((_, k) => parseInline(r[k] ?? '')));
            }
            out.push({ t: 'table', align: head.map((_, k) => align[k] ?? null), head: head.map(parseInline), rows });
            continue;
        }
        const item = ITEM.exec(line);
        if (item && (para.length === 0 || !/^\d/.test(item[2]) || item[2].startsWith('1'))) {
            flush();
            const indent = item[1].length;
            const ordered = /^\d/.test(item[2]);
            const start = ordered ? parseInt(item[2], 10) : 1;
            const items: { checked?: boolean; c: Block[] }[] = [];
            while (i < lines.length) {
                const m = ITEM.exec(lines[i]);
                if (!m || m[1].length !== indent || /^\d/.test(m[2]) !== ordered) break;
                const body: string[] = [m[3]];
                const contentIndent = m[1].length + m[2].length + 1;
                i++;
                while (i < lines.length) {
                    const l = lines[i];
                    if (!l.trim()) {
                        // A blank line ends the item unless the next line is indented into it.
                        const next = lines[i + 1];
                        if (next !== undefined && next.length - next.trimStart().length >= contentIndent) {
                            body.push('');
                            i++;
                            continue;
                        }
                        break;
                    }
                    const lead = l.length - l.trimStart().length;
                    const sibling = ITEM.exec(l);
                    if (sibling && sibling[1].length <= indent) break;
                    if (lead < contentIndent && !sibling && (HEADING.test(l) || RULE.test(l) || QUOTE.test(l) || FENCE.test(l))) break;
                    body.push(lead >= contentIndent ? l.slice(contentIndent) : l.trimStart());
                    i++;
                }
                let checked: boolean | undefined;
                const task = /^\[([ xX])\]\s+/.exec(body[0]);
                if (task) {
                    checked = task[1] !== ' ';
                    body[0] = body[0].slice(task[0].length);
                }
                items.push({
                    checked,
                    c: depth < MAX_DEPTH ? parseMarkdown(body.join('\n'), depth + 1) : [{ t: 'para', c: parseInline(body.join(' ')) }],
                });
                while (i < lines.length && !lines[i].trim()) {
                    const next = lines[i + 1];
                    const m2 = next !== undefined ? ITEM.exec(next) : null;
                    if (m2 && m2[1].length === indent && /^\d/.test(m2[2]) === ordered) i++;
                    else break;
                }
            }
            out.push({ t: 'list', ordered, start, items });
            continue;
        }
        para.push(line);
        i++;
    }
    flush();
    return out;
}

/** Parse inline formatting. Unknown or unbalanced markers stay as text. */
export function parseInline(src: string, depth = 0): Inline[] {
    const out: Inline[] = [];
    let text = '';
    const push = (n: Inline) => {
        if (text) out.push({ t: 'text', v: text });
        text = '';
        out.push(n);
    };
    const nest = (s: string) => (depth < MAX_DEPTH ? parseInline(s, depth + 1) : [{ t: 'text' as const, v: s }]);
    let i = 0;
    while (i < src.length) {
        const ch = src[i];
        if (ch === '\\' && i + 1 < src.length && /[\\`*_{}\[\]()#+\-.!|~>]/.test(src[i + 1])) {
            text += src[i + 1];
            i += 2;
            continue;
        }
        if (ch === '`') {
            const run = /^`+/.exec(src.slice(i))![0];
            const end = src.indexOf(run, i + run.length);
            if (end > 0) {
                push({ t: 'code', v: src.slice(i + run.length, end).trim() });
                i = end + run.length;
                continue;
            }
        }
        if (ch === '!' && src[i + 1] === '[') {
            const m = /^!\[([^\]]*)\]\([^)]*\)/.exec(src.slice(i));
            if (m) {
                // An image shows as its alt text: the wallet loads nothing.
                text += m[1] ? `[${m[1]}]` : '';
                i += m[0].length;
                continue;
            }
        }
        if (ch === '[') {
            const m = /^\[((?:[^\]\\]|\\.)*)\]\(\s*<?([^)\s>]*)>?(?:\s+"[^"]*")?\s*\)/.exec(src.slice(i));
            if (m) {
                push({ t: 'link', href: m[2], c: nest(m[1]) });
                i += m[0].length;
                continue;
            }
        }
        if (ch === '<') {
            const m = /^<(https?:\/\/[^>\s]+)>/.exec(src.slice(i));
            if (m) {
                push({ t: 'link', href: m[1], c: [{ t: 'text', v: m[1] }] });
                i += m[0].length;
                continue;
            }
        }
        if (ch === '~' && src[i + 1] === '~') {
            const end = src.indexOf('~~', i + 2);
            if (end > i + 2) {
                push({ t: 'del', c: nest(src.slice(i + 2, end)) });
                i = end + 2;
                continue;
            }
        }
        if (ch === '*' || ch === '_') {
            const double = src[i + 1] === ch;
            const marker = double ? ch + ch : ch;
            // `_` inside a word (snake_case) is not emphasis.
            const wordBefore = i > 0 && /\w/.test(src[i - 1]);
            if (!(ch === '_' && wordBefore) && src[i + marker.length] && !/\s/.test(src[i + marker.length])) {
                let end = src.indexOf(marker, i + marker.length);
                while (end > 0 && (/\s/.test(src[end - 1]) || (!double && src[end + 1] === ch))) {
                    end = src.indexOf(marker, end + (double ? 2 : 1));
                }
                if (end > i + marker.length - 1 && !(ch === '_' && /\w/.test(src[end + marker.length] ?? ''))) {
                    const inner = nest(src.slice(i + marker.length, end));
                    push(double ? { t: 'strong', c: inner } : { t: 'em', c: inner });
                    i = end + marker.length;
                    continue;
                }
            }
        }
        if (ch === '\n') {
            // A hard break is two spaces or a backslash; otherwise a soft break is a space.
            text = text.endsWith('  ') ? text.trimEnd() + '\n' : text + ' ';
            i++;
            continue;
        }
        text += ch;
        i++;
    }
    if (text) out.push({ t: 'text', v: text });
    return out;
}

/** Whether a link may be offered to the holder to open: web and mail only. */
export function openableLink(href: string): boolean {
    return /^(https?:\/\/|mailto:)/i.test(href);
}

/** A cell's text, for sizing its column. */
function plain(c: Inline[]): string {
    return c.map((n) => ('v' in n ? n.v : plain(n.c))).join('');
}

/**
 * Each column's width, from its longest cell: about 7.5 points a character at
 * 14 pt, between 90 and 280 so a long cell wraps rather than stretching the
 * table. The table scrolls sideways when the columns add up to more than the
 * screen, and shares out any room left in proportion when they do not.
 */
export function columnWidths(head: Inline[][], rows: Inline[][][]): number[] {
    return head.map((_, c) => {
        const longest = Math.max(0, ...[head, ...rows].map((row) => (row[c] ? plain(row[c]).length : 0)));
        return Math.min(280, Math.max(90, Math.round(longest * 7.5) + 20));
    });
}
