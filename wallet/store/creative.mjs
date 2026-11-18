// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The App Store's creative assets (iOS 27 and iPadOS 27 and later), rendered
 * in a headless Chromium from raw iPhone screenshots:
 *
 *   product-page-header.png  3840 x 1646, key art within 1646 x 661 at the centre
 *   search-results.png       3840 x 2560, key art within 2168 x 1030 at (836, 765)
 *
 *   node store/creative.mjs --shots <dir of raw iPhone PNGs> --out <dir>
 *        [--locale en-GB] [--chrome <path>] [--profile <dir>] [--guides 1]
 *
 * Apple crops everything outside the safe area on some devices, so only
 * decoration lies there. --guides 1 draws the safe area, to check by eye; never
 * upload those. Flatten the output afterwards (store/flatten.ps1): App Store
 * Connect refuses an alpha channel.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

const NAVY = '#0F172A';
const GREEN = '#34E89E';
const BLUE = '#00BCF2';

/** Screenshot height for a width, from the iPhone's 1320 x 2868. */
const tall = (w) => Math.round((w * 2868) / 1320);

const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

function phone(url, x, y, w, opacity = 1) {
    const r = Math.round(w * 0.085);
    return `<div style="position:absolute;left:${x}px;top:${y}px;width:${w}px;height:${tall(w)}px;border-radius:${r}px;overflow:hidden;opacity:${opacity};box-shadow:0 0 0 ${Math.max(4, Math.round(w * 0.008))}px rgba(52,232,158,.55),0 ${Math.round(w * 0.04)}px ${Math.round(w * 0.14)}px rgba(0,0,0,.5)"><img src="${url}" style="display:block;width:100%;height:100%"></div>`;
}

function shell(w, h, font, body, guide) {
    const g = guide
        ? `<div style="position:absolute;left:${guide.x}px;top:${guide.y}px;width:${guide.w}px;height:${guide.h}px;outline:6px dashed #FF3B30;z-index:9"></div>`
        : '';
    return `<!doctype html><html><head><meta charset="utf-8"><style>
@font-face { font-family: Inter; src: url("${font}") format("truetype"); font-weight: 100 900; }
html, body { margin: 0; width: ${w}px; height: ${h}px; overflow: hidden; background: ${NAVY}; }
body { position: relative; font-family: Inter, sans-serif; color: #FFFFFF; }
</style></head><body>${body}${g}</body></html>`;
}

/** One idea for a first-time visitor, alone in the safe area; the wallet's
 *  screens stand either side, where a narrow device may crop them. */
function header(shot, copy, font, guides) {
    const safe = { x: 1097, y: 493, w: 1646, h: 661 };
    const body = `
${phone(shot('05-approval'), -150, -420, 560, 0.6)}
${phone(shot('04-attestation'), 480, 240, 560)}
${phone(shot('08-drive-file'), 2800, -620, 560)}
${phone(shot('02-access'), 3430, 130, 560, 0.6)}
<div style="position:absolute;left:${safe.x}px;top:${safe.y}px;width:${safe.w}px;height:${safe.h}px;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;gap:28px;font-weight:750;font-size:112px;line-height:1.1;letter-spacing:-0.02em">
  <div>${esc(copy.first)}</div><div style="color:${GREEN}">${esc(copy.second)}</div>
</div>`;
    return shell(3840, 1646, font, body, guides ? safe : null);
}

/** What the app is, at a glance, beside its real interface: all of it inside
 *  the safe area. The logo's two colours mark the corners outside it. */
function search(shot, copy, font, guides) {
    const safe = { x: 836, y: 765, w: 2168, h: 1030 };
    const pw = Math.floor((safe.h * 1320) / 2868);
    const gap = 44;
    const body = `
<div style="position:absolute;left:0;top:0;width:0;height:0;border-style:solid;border-width:640px 640px 0 0;border-color:${GREEN} transparent transparent transparent"></div>
<div style="position:absolute;right:0;bottom:0;width:0;height:0;border-style:solid;border-width:0 0 640px 640px;border-color:transparent transparent ${BLUE} transparent"></div>
<div style="position:absolute;left:${safe.x}px;top:${safe.y}px;width:${safe.w - pw * 2 - gap - 90}px;height:${safe.h}px;display:flex;flex-direction:column;justify-content:center;gap:40px">
  <div style="font-size:142px;line-height:1.06;font-weight:750;letter-spacing:-0.02em">${esc(copy.title)}</div>
  <div style="font-size:66px;line-height:1.25;font-weight:500;color:${GREEN}">${copy.lines.map((l) => `<div>${esc(l)}</div>`).join('')}</div>
</div>
${phone(shot('05-approval'), safe.x + safe.w - pw * 2 - gap, safe.y, pw)}
${phone(shot('04-attestation'), safe.x + safe.w - pw, safe.y, pw)}`;
    return shell(3840, 2560, font, body, guides ? safe : null);
}

function main() {
    const a = {};
    const argv = process.argv.slice(2);
    for (let i = 0; i < argv.length; i += 2) a[argv[i].replace(/^--/, '')] = argv[i + 1];
    if (!a.shots || !a.out) throw new Error('--shots and --out are required');
    const locale = a.locale || 'en-GB';
    const chrome = a.chrome || process.env.CHROME || 'google-chrome';
    const copy = JSON.parse(readFileSync(join(here, 'headlines', `${locale}.json`), 'utf8')).creative;
    const font = pathToFileURL(resolve(here, '..', 'src', 'assets', 'fonts', 'InterVariable.ttf')).href;
    const out = resolve(a.out);
    const work = join(out, '.pages');
    mkdirSync(work, { recursive: true });
    const profile = resolve(a.profile || join(out, '.profile'));
    const shot = (name) => {
        const p = resolve(a.shots, `${name}.png`);
        if (!existsSync(p)) throw new Error(`no ${name}.png in ${a.shots}`);
        return pathToFileURL(p).href;
    };
    const guides = a.guides === '1';
    const pages = [
        ['product-page-header', 3840, 1646, header(shot, copy.header, font, guides)],
        ['search-results', 3840, 2560, search(shot, copy.search, font, guides)],
    ];
    for (const [name, w, h, html] of pages) {
        const file = join(work, `${name}.html`);
        writeFileSync(file, html);
        execFileSync(
            chrome,
            [
                '--headless=new',
                '--disable-gpu',
                '--hide-scrollbars',
                '--force-device-scale-factor=1',
                '--allow-file-access-from-files',
                '--virtual-time-budget=5000',
                `--user-data-dir=${profile}`,
                `--window-size=${w},${h}`,
                `--screenshot=${join(out, `${name}.png`)}`,
                pathToFileURL(file).href,
            ],
            { stdio: 'ignore', timeout: 120000 },
        );
        console.log(`${name}.png`);
    }
}

main();
