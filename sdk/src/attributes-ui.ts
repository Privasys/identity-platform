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
import {
    attributeSections,
    disclosureCost,
    formatCredits,
    priceOf,
    type AttributePrices,
    type AttributeSectionId,
} from './attribute-pricing';

const SHIELD = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`;
const PERSON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-6 8-6s8 2 8 6"/></svg>`;

const ATTRIBUTES_CSS = /* css */ `
:host {
    all: initial;
    display: block;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    -webkit-font-smoothing: antialiased;
    /* The host page's colours, where it names them. Custom properties are the
       one thing a closed shadow root inherits, so these are the whole theming
       surface: a page can match its palette, it cannot restyle a trust marker. */
    --_accent: var(--privasys-accent, #00A0EB);
    --_text: var(--privasys-text, #0F172A);
    --_muted: var(--privasys-muted, #64748B);
    --_border: var(--privasys-border, #E2E8F0);
    --_surface: var(--privasys-surface, transparent);
    --_hover: var(--privasys-hover, #F8FAFC);
    --_accent-weak: var(--privasys-accent-weak, rgba(0, 160, 235, 0.10));
    --_gov: #047857;
    --_price-fg: #9A3412;
    --_price-bg: #FFF7ED;
    color: var(--_text);
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

.group { margin-bottom: 16px; }
.group:last-child { margin-bottom: 0; }
.group-title {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    font-weight: 600;
    color: var(--_muted);
    margin-bottom: 8px;
}
.group-title svg { width: 14px; height: 14px; flex: none; }
.group-gov .group-title svg, .group-paid .group-title svg { color: var(--_gov); }
.group-hint { font-size: 12px; line-height: 1.45; color: var(--_muted); margin: -4px 0 8px; }
.total { font-size: 12px; font-weight: 600; margin-top: 8px; color: var(--_text); }

/* Chips: a dialog's worth of choice in a few lines. */
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 11px;
    border: 1px solid var(--_border);
    border-radius: 999px;
    background: var(--_surface);
    color: var(--_text);
    font: inherit;
    font-size: 13px;
    line-height: 1.4;
    cursor: pointer;
    transition: background 0.12s, border-color 0.12s;
}
.chip:hover { background: var(--_hover); }
.chip:focus-visible { outline: 2px solid var(--_accent); outline-offset: 2px; }
.chip.on { border-color: var(--_accent); background: var(--_accent-weak); color: var(--_accent); }

/* Rows: the same sections for a page with room. */
.rows { display: flex; flex-direction: column; }
.row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 10px;
    border-radius: 10px;
    cursor: pointer;
    transition: background 0.12s;
}
.row:hover { background: var(--_hover); }
.row input { accent-color: var(--_accent); width: 16px; height: 16px; cursor: pointer; flex: none; }
.row-label { font-size: 14px; flex: 1 1 auto; }
.row-key {
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', Consolas, monospace;
    font-size: 11px;
    color: var(--_muted);
}

/* The price of a sold disclosure, in place of a bare "Paid". */
.price {
    flex: none;
    padding: 1px 7px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
    color: var(--_price-fg);
    background: var(--_price-bg);
}

/* Badges. The government marker is the only saturated colour in the component:
   nothing else should compete with it for attention. */
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
    :host {
        --_text: var(--privasys-text, #E2E8F0);
        --_muted: var(--privasys-muted, #94A3B8);
        --_border: var(--privasys-border, rgba(255, 255, 255, 0.12));
        --_hover: var(--privasys-hover, rgba(255, 255, 255, 0.05));
        --_gov: #6EE7B7;
        --_price-fg: #FDBA74;
        --_price-bg: rgba(249, 115, 22, 0.14);
    }
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

/** Section wording a host can replace: what each group is, and why it matters. */
export interface AttributeSectionCopy {
    title: string;
    /** A line under the title. Omit for none. */
    hint?: string;
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
    /**
     * `chips` lays each section out as toggle pills, compact enough for a
     * dialog; `list` (the default) as checkbox rows, for a page with room.
     */
    layout?: 'list' | 'chips';
    /**
     * Prices from `fetchAttributePrices`. A sold attribute shows its price; until
     * one arrives, or where the catalogue does not list it, it says "Paid".
     * Can also be supplied later with `setPrices`.
     */
    prices?: AttributePrices | null;
    /** Replace a section's title or hint, e.g. to say who pays in this product. */
    copy?: Partial<Record<AttributeSectionId, AttributeSectionCopy>>;
    /**
     * Shown under the paid section once something paid is chosen and every chosen
     * price is known. `{price}` becomes the total for one disclosure of the
     * selection, e.g. "Each visitor who presents these costs you {price}."
     * Omit for no total.
     */
    totalTemplate?: string;
}

const DEFAULT_COPY: Record<AttributeSectionId, AttributeSectionCopy> = {
    holder: { title: 'Provided by the holder' },
    gov: { title: 'Verified by a government document' },
    paid: {
        title: 'Paid',
        hint: 'Certified from a government document. Each disclosure is charged at the price shown.',
    },
};

/**
 * The attributes a relying party can request, in sections by what they are
 * worth: what the holder supplies, what a government document certifies, and
 * what is sold. Each section states its assurance once, so a chip carries only
 * its name and, where it is sold, its price. Repeating "Self-asserted" or
 * "Government ID" on every chip spent most of the space on the one fact the
 * heading already said.
 *
 * Superseded spellings are hidden: they still resolve and must never be removed,
 * but offering both names for one disclosure turns a decision into a puzzle. A
 * client that already stored the old spelling keeps working, and
 * `selected` still accepts it.
 *
 * Colours follow the host through custom properties (`--privasys-accent`,
 * `--privasys-text`, `--privasys-muted`, `--privasys-border`,
 * `--privasys-surface`), the one thing that passes into the closed shadow root,
 * so the component looks like the page it sits in while no stylesheet can
 * reshape a trust marker.
 */
export class AttributePicker {
    private cfg: AttributePickerConfig;
    private host: HTMLElement;
    private shadow: ShadowRoot;
    private chosen: Set<string>;
    private prices: AttributePrices | null;

    constructor(config: AttributePickerConfig) {
        this.cfg = config;
        this.chosen = new Set(config.selected ?? []);
        this.prices = config.prices ?? null;
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

    /** Supply or refresh prices without losing the selection. */
    setPrices(prices: AttributePrices | null): void {
        this.prices = prices;
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

    private toggle(key: string, on: boolean): void {
        if (on) this.chosen.add(key);
        else this.chosen.delete(key);
        this.cfg.onChange?.(this.selection);
        this.render();
    }

    private render(): void {
        const style = this.shadow.querySelector('style')!;
        this.shadow.innerHTML = '';
        this.shadow.appendChild(style);

        const items = this.list();
        const chips = this.cfg.layout === 'chips';
        for (const section of attributeSections(items)) {
            const copy = { ...DEFAULT_COPY[section.id], ...this.cfg.copy?.[section.id] };
            const wrap = document.createElement('div');
            wrap.className = `group group-${section.id}`;

            const heading = document.createElement('div');
            heading.className = 'group-title';
            // The section, not each chip, carries the assurance mark.
            heading.insertAdjacentHTML('afterbegin', section.id === 'holder' ? PERSON : SHIELD);
            heading.appendChild(document.createTextNode(copy.title));
            wrap.appendChild(heading);
            if (copy.hint) {
                const hint = document.createElement('div');
                hint.className = 'group-hint';
                hint.textContent = copy.hint;
                wrap.appendChild(hint);
            }

            const body = document.createElement('div');
            body.className = chips ? 'chips' : 'rows';
            for (const a of section.attributes) body.appendChild(chips ? this.chip(a) : this.row(a));
            wrap.appendChild(body);

            if (section.id === 'paid' && this.cfg.totalTemplate) {
                const cost = disclosureCost(this.prices, items, [...this.chosen]);
                if (cost !== undefined && cost > 0) {
                    const total = document.createElement('div');
                    total.className = 'total';
                    total.textContent = this.cfg.totalTemplate.replace('{price}', formatCredits(cost));
                    wrap.appendChild(total);
                }
            }
            this.shadow.appendChild(wrap);
        }
    }

    /** The price tag for a sold attribute, or null for a free one. */
    private priceTag(a: CanonicalAttribute): HTMLElement | null {
        if (!isBillable(a)) return null;
        const p = priceOf(this.prices, a);
        const tag = document.createElement('span');
        tag.className = 'price';
        tag.textContent = p === undefined ? 'Paid' : formatCredits(p);
        tag.setAttribute(
            'title',
            p === undefined ? 'This disclosure is charged.' : `Each disclosure costs ${formatCredits(p)}.`,
        );
        return tag;
    }

    private keyTag(a: CanonicalAttribute): HTMLElement | null {
        if (!this.cfg.showKeys) return null;
        const key = document.createElement('span');
        key.className = 'row-key';
        key.textContent = a.key;
        return key;
    }

    private chip(a: CanonicalAttribute): HTMLElement {
        const on = this.chosen.has(a.key);
        const chip = document.createElement('button');
        chip.type = 'button';
        chip.className = on ? 'chip on' : 'chip';
        chip.setAttribute('role', 'checkbox');
        chip.setAttribute('aria-checked', String(on));
        chip.addEventListener('click', () => this.toggle(a.key, !on));

        const label = document.createElement('span');
        label.textContent = a.label;
        chip.appendChild(label);
        const key = this.keyTag(a);
        if (key) chip.appendChild(key);
        const price = this.priceTag(a);
        if (price) chip.appendChild(price);
        return chip;
    }

    private row(a: CanonicalAttribute): HTMLElement {
        const row = document.createElement('label');
        row.className = 'row';

        const box = document.createElement('input');
        box.type = 'checkbox';
        box.checked = this.chosen.has(a.key);
        box.addEventListener('change', () => this.toggle(a.key, box.checked));
        row.appendChild(box);

        const label = document.createElement('span');
        label.className = 'row-label';
        label.textContent = a.label;
        row.appendChild(label);

        const key = this.keyTag(a);
        if (key) row.appendChild(key);
        const price = this.priceTag(a);
        if (price) row.appendChild(price);
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
