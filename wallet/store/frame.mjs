// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Frames raw store screenshots (the Maestro runs of the demo build) with a
 * headline, at the exact pixel size each store slot takes, by rendering a
 * page per screenshot in a headless Chromium.
 *
 *   node store/frame.mjs --shots <dir of raw PNGs> --out <dir> --target <name>
 *        [--locale en-GB] [--chrome <path to chrome/brave>] [--profile <dir>]
 *
 * Targets (pixels, from App Store Connect's and Play Console's specifications):
 *   iphone       1320 x 2868  App Store, iPhone 6.9" (Dynamic Island, large)
 *   iphone-63    1206 x 2622  App Store, iPhone 6.1" or 6.3" (Dynamic Island,
 *                             medium): the iPhone size Apple requires
 *   ipad         2064 x 2752  App Store, iPad 13"
 *   duo          2007 x 2853  App Store, iPhone Duo inner display
 *   play-phone   1080 x 1920  Google Play, phone (9:16)
 *   play-tablet  2560 x 1600  Google Play, 7" and 10" tablets (landscape)
 *   fold-1x1     2160 x 2160  Google Play, foldable, unfolded screen in 1:1
 *   fold-4x3     2880 x 2160  Google Play, foldable, unfolded screen in 4:3
 *   fold-outer   1350 x 2160  Google Play, foldable, outer screen in 10:16
 *
 * The output is a PNG per headline, in the headline file's order (01-..., 02-...).
 * Browsers write PNGs with an alpha channel, which App Store Connect refuses:
 * flatten them afterwards (store/flatten.ps1 on Windows, `magick -alpha off`
 * elsewhere).
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

const TARGETS = {
    iphone: { w: 1320, h: 2868, layout: 'portrait' },
    'iphone-63': { w: 1206, h: 2622, layout: 'portrait' },
    ipad: { w: 2064, h: 2752, layout: 'portrait' },
    duo: { w: 2007, h: 2853, layout: 'portrait' },
    'play-phone': { w: 1080, h: 1920, layout: 'portrait' },
    'play-tablet': { w: 2560, h: 1600, layout: 'landscape' },
    'fold-1x1': { w: 2160, h: 2160, layout: 'landscape' },
    'fold-4x3': { w: 2880, h: 2160, layout: 'landscape' },
    'fold-outer': { w: 1350, h: 2160, layout: 'portrait' },
    feature: { w: 1024, h: 500, layout: 'landscape' },
};

function args() {
    const a = {};
    const argv = process.argv.slice(2);
    for (let i = 0; i < argv.length; i += 2) a[argv[i].replace(/^--/, '')] = argv[i + 1];
    for (const k of ['shots', 'out', 'target']) if (!a[k]) throw new Error(`--${k} is required`);
    if (!TARGETS[a.target]) throw new Error(`unknown target ${a.target}: ${Object.keys(TARGETS).join(', ')}`);
    return { locale: 'en-GB', chrome: process.env.CHROME || 'google-chrome', ...a };
}

const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

/** The page for one screenshot: the brand's Deep Navy ground (the app's own green
 *  header would vanish on Brand Green), a white headline, and the
 *  screenshot below it with rounded top corners, running off the bottom edge
 *  (portrait) or standing beside the headline (landscape). The focal point
 *  stays in the centre of the canvas. */
function page({ w, h, layout }, shotUrl, headline, fontUrl) {
    // Landscape canvases use the same headline-over-screenshot layout: a
    // headline in a side column wrapped into four short lines.
    const portrait = true;
    const wide = layout === 'landscape';
    const pad = Math.round(w * (wide ? 0.04 : 0.07));
    const titleSize = Math.round(wide ? h * 0.068 : w * 0.074);
    const shotWidth = Math.round(w * (wide ? 0.78 : 0.8));
    const radius = Math.round(shotWidth * 0.055);
    return `<!doctype html><html><head><meta charset="utf-8"><style>
@font-face { font-family: Inter; src: url("${fontUrl}") format("truetype"); font-weight: 100 900; }
html, body { margin: 0; width: ${w}px; height: ${h}px; overflow: hidden; }
body {
  background: #0F172A; font-family: Inter, -apple-system, "Segoe UI", sans-serif; color: #FFFFFF;
  display: flex; flex-direction: ${portrait ? 'column' : 'row'}; align-items: center; box-sizing: border-box;
  padding: ${portrait ? `${Math.round(pad * 1.6)}px ${pad}px 0` : `0 0 0 ${pad}px`};
  gap: ${portrait ? Math.round(pad * 0.9) : pad}px;
}
h1 {
  margin: 0; font-size: ${titleSize}px; line-height: 1.12; font-weight: 750; letter-spacing: -0.02em;
  text-align: ${portrait ? 'center' : 'left'}; text-wrap: balance;
  ${portrait ? `max-width: ${Math.round(w * 0.86)}px;` : `flex: 1 1 0; padding-right: ${Math.round(pad * 0.4)}px;`}
}
.shot {
  width: ${shotWidth}px; ${portrait ? 'flex: 1 1 auto; min-height: 0;' : 'flex: none;'}
  border-radius: ${radius}px ${radius}px ${portrait ? '0 0' : `${radius}px ${radius}px`};
  box-shadow: 0 0 0 ${Math.max(2, Math.round(w * 0.004))}px rgba(52, 232, 158, 0.55), 0 ${Math.round(w * 0.012)}px ${Math.round(w * 0.05)}px rgba(0, 0, 0, 0.45);
  overflow: hidden;
  ${portrait ? '' : `align-self: center; margin-right: ${pad}px; max-height: ${h - pad * 2}px;`}
}
.shot img { display: block; width: 100%; ${portrait ? 'height: 100%; object-fit: cover; object-position: top;' : 'height: auto;'} }
</style></head><body><h1>${esc(headline)}</h1><div class="shot"><img src="${shotUrl}"></div></body></html>`;
}

/** Google Play's feature graphic: the app icon, the name, one line, and the
 *  top of a phone screenshot, kept inside the centre (Play may crop the
 *  edges and lays its own button over the graphic). */
function featurePage(shotUrl, iconUrl, title, line, fontUrl) {
    return `<!doctype html><html><head><meta charset="utf-8"><style>
@font-face { font-family: Inter; src: url("${fontUrl}") format("truetype"); font-weight: 100 900; }
html, body { margin: 0; width: 1024px; height: 500px; overflow: hidden; }
body { background: #0F172A; font-family: Inter, sans-serif; color: #FFFFFF; display: flex; align-items: center;
  gap: 56px; padding: 0 64px 0 96px; box-sizing: border-box; }
.text { flex: 1 1 0; display: flex; flex-direction: column; gap: 18px; }
.icon { width: 96px; height: 96px; border-radius: 22px; overflow: hidden; background: #FFFFFF; }
.icon img { width: 100%; height: 100%; }
h1 { margin: 0; font-size: 50px; line-height: 1.05; font-weight: 750; letter-spacing: -0.02em; }
p { margin: 0; font-size: 25px; line-height: 1.3; color: #34E89E; text-wrap: balance; }
.shot { width: 300px; align-self: flex-start; margin-top: 64px; height: 436px; border-radius: 28px 28px 0 0; overflow: hidden;
  box-shadow: 0 0 0 3px rgba(52, 232, 158, 0.55), 0 12px 48px rgba(0, 0, 0, 0.45); }
.shot img { width: 100%; height: 100%; object-fit: cover; object-position: top; display: block; }
</style></head><body><div class="text"><div class="icon"><img src="${iconUrl}"></div>
<h1>${esc(title)}</h1><p>${esc(line)}</p></div><div class="shot"><img src="${shotUrl}"></div></body></html>`;
}

function render(chrome, profile, html, png, w, h) {
    execFileSync(
        chrome,
        [
            '--headless=new',
            '--disable-gpu',
            '--hide-scrollbars',
            '--force-device-scale-factor=1',
            '--allow-file-access-from-files',
            '--virtual-time-budget=4000',
            `--user-data-dir=${profile}`,
            `--window-size=${w},${h}`,
            `--screenshot=${png}`,
            pathToFileURL(html).href,
        ],
        { stdio: 'ignore', timeout: 120000 },
    );
}

function main() {
    const o = args();
    const target = TARGETS[o.target];
    const copy = JSON.parse(readFileSync(join(here, 'headlines', `${o.locale}.json`), 'utf8'));
    const headlines = copy.shots;
    const font = pathToFileURL(resolve(here, '..', 'src', 'assets', 'fonts', 'InterVariable.ttf')).href;
    const out = resolve(o.out);
    const work = join(out, '.pages');
    mkdirSync(work, { recursive: true });
    const profile = resolve(o.profile || join(out, '.profile'));
    if (o.target === 'feature') {
        const raw = resolve(o.shots, `${copy.feature.shot}.png`);
        if (!existsSync(raw)) throw new Error(`no ${copy.feature.shot}.png in ${o.shots}`);
        const icon = pathToFileURL(resolve(here, '..', 'assets', 'icon.production.png')).href;
        const html = join(work, 'feature-graphic.html');
        writeFileSync(html, featurePage(pathToFileURL(raw).href, icon, copy.feature.title, copy.feature.line, font));
        render(o.chrome, profile, html, join(out, 'feature-graphic.png'), target.w, target.h);
        console.log('feature-graphic.png');
        return;
    }
    let n = 0;
    for (const { shot, headline } of headlines) {
        const raw = resolve(o.shots, `${shot}.png`);
        if (!existsSync(raw)) {
            console.warn(`skip ${shot}: no ${basename(raw)} in ${o.shots}`);
            continue;
        }
        n += 1;
        const name = `${String(n).padStart(2, '0')}-${shot}`;
        const html = join(work, `${name}.html`);
        writeFileSync(html, page(target, pathToFileURL(raw).href, headline, font));
        render(o.chrome, profile, html, join(out, `${name}.png`), target.w, target.h);
        console.log(`${name}.png  ${headline}`);
    }
    if (!n) throw new Error('no screenshot matched the headlines');
}

main();
