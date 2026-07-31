// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * Reusable attribute UI: a picker for a relying party choosing what to request,
 * and a badge for showing what a value is worth.
 *
 * The trust cue is the reason this ships here rather than being left to each
 * integrator. "First Name" and "First Name, from a government ID" are different
 * products at different prices, and a site that renders both as plain grey text
 * has quietly thrown away the only thing the holder is paying attention to. Every
 * Privasys surface should draw that distinction the same way, so it is drawn
 * once, here.
 *
 * Plain DOM inside a closed shadow root, matching AuthUI: an adopter's stylesheet
 * cannot leak in and reshape a trust marker, and there is no framework to agree
 * on. A React wrapper lives in ./react for consumers that would rather not hold a
 * ref, and it mounts these same elements.
 */

import {
    ATTRIBUTE_MAP,
    CANONICAL_ATTRIBUTES,
    assuranceOf,
    isBillable,
    isGovVerified,
    requestableAttributes,
    type CanonicalAttribute,
} from './attributes';

const SHIELD = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`;
const PERSON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-6 8-6s8 2 8 6"/></svg>`;

const ATTRIBUTES_CSS = /* css */ `
:host {
    all: initial;
    display: block;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: #0F172A;
    -webkit-font-smoothing: antialiased;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

.group { margin-bottom: 18px; }
.group-title {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: #94A3B8;
    margin-bottom: 8px;
}
.row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 9px 10px;
    border-radius: 10px;
    cursor: pointer;
    transition: background 0.12s;
}
.row:hover { background: #F8FAFC; }
.row input { accent-color: #00A0EB; width: 16px; height: 16px; cursor: pointer; flex: none; }
.row-label { font-size: 14px; flex: 1 1 auto; }
.row-key {
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', Consolas, monospace;
    font-size: 11px;
    color: #94A3B8;
}

/* Badges. The government marker is the only saturated colour in the component:
   nothing else in a picker should compete with it for attention. */
.badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    flex: none;
    padding: 2px 7px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    line-height: 1.5;
    white-space: nowrap;
}
.badge svg { width: 12px; height: 12px; }
.badge.gov { color: #047857; background: #ECFDF5; }
.badge.self { color: #64748B; background: #F1F5F9; }
.badge.paid { color: #9A3412; background: #FFF7ED; }

@media (prefers-color-scheme: dark) {
    :host { color: #E2E8F0; }
    .row:hover { background: rgba(255,255,255,0.05); }
    .group-title, .row-key { color: #64748B; }
    .badge.gov { color: #6EE7B7; background: rgba(16,185,129,0.14); }
    .badge.self { color: #94A3B8; background: rgba(255,255,255,0.07); }
    .badge.paid { color: #FDBA74; background: rgba(249,115,22,0.14); }
}
`;

/** What a badge asserts about a value. */
export type AttributeAssuranceBadge = 'gov' | 'self';

/**
 * A badge element for one attribute: government-verified or self-asserted, plus
 * an optional "Paid" marker for a disclosure the relying party is charged for.
 *
 * Returns a detached element with its own shadow root, so it can be dropped into
 * any layout without inheriting the host page's typography. Pass a
 * CanonicalAttribute when the list came from `fetchAttributeReferential`; a bare
 * key resolves against the bundled one.
 */
export function attributeBadge(
    attr: CanonicalAttribute | string,
    opts: { showPaid?: boolean } = {},
): HTMLElement {
    const host = document.createElement('span');
    host.setAttribute('data-privasys-attribute-badge', '');
    host.style.display = 'inline-flex';
    host.style.gap = '4px';
    const shadow = host.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = ATTRIBUTES_CSS;
    shadow.appendChild(style);

    const gov = isGovVerified(attr);
    const badge = document.createElement('span');
    badge.className = `badge ${gov ? 'gov' : 'self'}`;
    badge.innerHTML = `${gov ? SHIELD : PERSON}<span>${gov ? 'Government ID' : 'Self-asserted'}</span>`;
    // The label is redundant to a sighted user next to the icon, but the icon is
    // the whole message for a screen reader that skips the decorative svg.
    badge.setAttribute('title', gov
        ? 'Read from a government document and certified inside an enclave.'
        : 'Provided by the holder or their identity provider, not checked against a document.');
    shadow.appendChild(badge);

    if (opts.showPaid && isBillable(attr)) {
        const paid = document.createElement('span');
        paid.className = 'badge paid';
        paid.textContent = 'Paid';
        paid.setAttribute('title', 'Requesting this disclosure costs the relying party credits.');
        shadow.appendChild(paid);
    }
    return host;
}

/** Options for {@link AttributePicker}. */
export interface AttributePickerConfig {
    /** Where to mount. */
    container: HTMLElement;
    /** Keys selected on first render. */
    selected?: string[];
    /**
     * The list to offer. Defaults to the bundled referential; pass the result of
     * `fetchAttributeReferential` to offer what the IdP is serving today.
     */
    attributes?: CanonicalAttribute[];
    /**
     * Offer only these keys. Use it where the choice is already narrowed by
     * something other than the referential, such as the set an app's own
     * registration allows.
     */
    only?: string[];
    /** Called on every change with the selected keys, in referential order. */
    onChange?: (keys: string[]) => void;
    /** Show the raw canonical key beside each label. Useful in a developer
     *  console, noise everywhere else. */
    showKeys?: boolean;
}

/**
 * A checkbox list of the attributes a relying party can request, grouped by what
 * they are worth and badged accordingly.
 *
 * Superseded spellings are hidden: they still resolve and must never be removed,
 * but offering both names for one disclosure turns a decision into a puzzle. A
 * client that already stored the old spelling keeps working, and
 * `selected` still accepts it.
 */
export class AttributePicker {
    private cfg: AttributePickerConfig;
    private host: HTMLElement;
    private shadow: ShadowRoot;
    private chosen: Set<string>;

    constructor(config: AttributePickerConfig) {
        this.cfg = config;
        this.chosen = new Set(config.selected ?? []);
        this.host = document.createElement('div');
        this.host.setAttribute('data-privasys-attribute-picker', '');
        this.shadow = this.host.attachShadow({ mode: 'closed' });
        const style = document.createElement('style');
        style.textContent = ATTRIBUTES_CSS;
        this.shadow.appendChild(style);
        config.container.appendChild(this.host);
        this.render();
    }

    /** The selected keys, in referential order so a stored registration does not
     *  churn on every re-save. */
    get selection(): string[] {
        return this.list().filter((a) => this.chosen.has(a.key)).map((a) => a.key);
    }

    /** Replace the selection from outside (a form reset, a loaded record). */
    setSelection(keys: string[]): void {
        this.chosen = new Set(keys);
        this.render();
    }

    /** Remove the picker from the page. */
    destroy(): void {
        this.host.remove();
    }

    private list(): CanonicalAttribute[] {
        const all = this.cfg.attributes ?? CANONICAL_ATTRIBUTES;
        const offered = requestableAttributes(all);
        if (!this.cfg.only?.length) return offered;
        const allow = new Set(this.cfg.only);
        return offered.filter((a) => allow.has(a.key));
    }

    private render(): void {
        const style = this.shadow.querySelector('style')!;
        this.shadow.innerHTML = '';
        this.shadow.appendChild(style);

        const items = this.list();
        // Government-backed first: it is the expensive, consequential half of the
        // choice, and burying it under nine profile fields is how a developer
        // ends up requesting a passport scan they did not mean to.
        for (const [title, group] of [
            ['Verified by a government document', items.filter((a) => isGovVerified(a))],
            ['Provided by the holder', items.filter((a) => !isGovVerified(a))],
        ] as [string, CanonicalAttribute[]][]) {
            if (!group.length) continue;
            const section = document.createElement('div');
            section.className = 'group';
            const heading = document.createElement('div');
            heading.className = 'group-title';
            heading.textContent = title;
            section.appendChild(heading);
            for (const a of group) section.appendChild(this.row(a));
            this.shadow.appendChild(section);
        }
    }

    private row(a: CanonicalAttribute): HTMLElement {
        const row = document.createElement('label');
        row.className = 'row';

        const box = document.createElement('input');
        box.type = 'checkbox';
        box.checked = this.chosen.has(a.key);
        box.addEventListener('change', () => {
            if (box.checked) this.chosen.add(a.key);
            else this.chosen.delete(a.key);
            this.cfg.onChange?.(this.selection);
        });
        row.appendChild(box);

        const label = document.createElement('span');
        label.className = 'row-label';
        label.textContent = a.label;
        row.appendChild(label);

        if (this.cfg.showKeys) {
            const key = document.createElement('span');
            key.className = 'row-key';
            key.textContent = a.key;
            row.appendChild(key);
        }

        row.appendChild(attributeBadge(a, { showPaid: true }));
        return row;
    }
}

/** The label the referential gives a key, for a consent screen or an audit list
 *  that has a stored key and nothing else. Falls back to the key so an attribute
 *  newer than this bundle still reads as itself rather than as nothing. */
export function attributeLabel(key: string): string {
    return ATTRIBUTE_MAP[key]?.label ?? key;
}

/** The human wording for an assurance level, for a surface that draws its own
 *  markup but should not invent its own vocabulary. */
export function assuranceLabel(attr: CanonicalAttribute | string): string {
    return assuranceOf(attr) === 'gov_verified' ? 'Government ID' : 'Self-asserted';
}
