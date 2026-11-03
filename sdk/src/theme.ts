/**
 * An adopter's theme for the sign-in gate.
 *
 * The gate is rendered on the identity provider's origin, so what an adopter
 * passes is untrusted: it arrives by postMessage and styles a page people
 * trust with their credentials. A theme is therefore a closed set of tokens.
 * Each surviving value becomes a CSS custom property on the host, set through
 * the DOM; nothing a page passes ever becomes stylesheet text, and the rules
 * that read the properties are fixed here.
 */

export const THEME_COLOURS = [
    'text', 'background', 'border', 'focus', 'focusText',
    'primary', 'primaryText', 'secondary', 'secondaryText', 'link',
] as const;

export type ThemeColour = (typeof THEME_COLOURS)[number];

export interface AuthTheme {
    /** A ready-made style. `'govuk'` follows the GOV.UK Design System's buttons, focus and links. */
    preset?: 'govuk';
    /** A font stack. Letters, digits, spaces, commas, quotes and hyphens, at most 200 characters. */
    font?: string;
    /** Colours, as hex only (`#rgb` or `#rrggbb`). */
    colours?: Partial<Record<ThemeColour, string>>;
    /** Corner radius in pixels, an integer from 0 to 24. */
    radius?: number;
}

const FONT = /^[A-Za-z0-9 ,'"-]{1,200}$/;
const HEX = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;

/**
 * The adopter's `theme`, reduced to what is allowed. A value that fails its
 * rule is dropped whole, never trimmed into something that passes. A theme
 * with nothing left yields `undefined`, which is the default gate.
 */
export function sanitiseTheme(raw: unknown): AuthTheme | undefined {
    if (!raw || typeof raw !== 'object') return undefined;
    const r = raw as Record<string, unknown>;
    const theme: AuthTheme = {};
    if (r.preset === 'govuk') theme.preset = 'govuk';
    if (typeof r.font === 'string' && FONT.test(r.font)) theme.font = r.font;
    if (r.colours && typeof r.colours === 'object') {
        const colours: Partial<Record<ThemeColour, string>> = {};
        for (const key of THEME_COLOURS) {
            const v = (r.colours as Record<string, unknown>)[key];
            if (typeof v === 'string' && HEX.test(v)) colours[key] = v;
        }
        if (Object.keys(colours).length) theme.colours = colours;
    }
    if (typeof r.radius === 'number' && Number.isInteger(r.radius) && r.radius >= 0 && r.radius <= 24) {
        theme.radius = r.radius;
    }
    return Object.keys(theme).length ? theme : undefined;
}

/** The custom properties a theme sets on the gate's host element. */
export function themeProperties(theme: AuthTheme): Record<string, string> {
    const props: Record<string, string> = {};
    if (theme.font) props['--pv-font'] = theme.font;
    if (theme.radius !== undefined) props['--pv-radius'] = `${theme.radius}px`;
    for (const key of THEME_COLOURS) {
        const v = theme.colours?.[key];
        if (v) props[`--pv-${key}`] = v;
    }
    return props;
}

// One fixed block per token: a rule reading a property that is not set would
// lose the default gate's value (and its dark variant), so only the blocks
// for tokens the theme sets are applied. The blocks hold no adopter text.
const TOKEN_RULES: Record<string, string> = {
    '--pv-font': `:host, button, a { font-family: var(--pv-font); }`,
    '--pv-radius': `.btn-provider, .btn-retry, .btn-back, .gate-close { border-radius: var(--pv-radius); }`,
    '--pv-text': `:host, .auth-panel-heading, .btn-label, .gate-header-brand { color: var(--pv-text); }`,
    '--pv-background': `:host { background: var(--pv-background); }`,
    '--pv-border': `.footer, .gate-header, .btn-retry, .session-info { border-color: var(--pv-border); }`,
    '--pv-primary': `.btn-provider.primary, .btn-provider.primary:hover { background: var(--pv-primary); border-color: var(--pv-primary); }`,
    '--pv-primaryText': `.btn-provider.primary, .btn-provider.primary .btn-label, .btn-provider.primary svg { color: var(--pv-primaryText); }`,
    '--pv-secondary': `.btn-provider:not(.primary), .btn-provider:not(.primary):hover, .btn-retry { background: var(--pv-secondary); border-color: var(--pv-secondary); }`,
    '--pv-secondaryText': `.btn-provider:not(.primary), .btn-provider:not(.primary) .btn-label, .btn-provider:not(.primary) svg, .btn-retry { color: var(--pv-secondaryText); }`,
    '--pv-link': `.link-btn, .footer a { color: var(--pv-link); }`,
    '--pv-focus': `button:focus-visible, a:focus-visible { outline-color: var(--pv-focus); }`,
};

/**
 * The fixed rules for the tokens this theme sets. Specificity comes from the
 * host's `themed` class, which outranks the default sheet's dark variants.
 */
export function themeRules(theme: AuthTheme): string {
    return Object.keys(themeProperties(theme))
        .map((prop) => TOKEN_RULES[prop])
        .filter(Boolean)
        .map((rule) => rule.split('\n').map(scopeToThemed).join('\n'))
        .join('\n');
}

function scopeToThemed(rule: string): string {
    const open = rule.indexOf('{');
    const selectors = rule.slice(0, open).split(',').map((s) => s.trim());
    const scoped = selectors.map((s) => (s === ':host' ? ':host(.themed)' : `:host(.themed) ${s}`));
    return `${scoped.join(', ')} ${rule.slice(open)}`;
}

/**
 * The GOV.UK preset, read with the adopter's tokens where given. The page's
 * own font carries it: GDS Transport is licensed to gov.uk services and is
 * never embedded here, nor is the crown.
 */
export const GOVUK_CSS = /* css */ `
:host(.theme-govuk) {
    font-family: var(--pv-font, Arial, sans-serif);
    font-size: 19px;
    color: var(--pv-text, #0b0c0c);
    background: var(--pv-background, #fff);
    line-height: 1.32;
}
:host(.theme-govuk) .auth-panel-heading { color: var(--pv-text, #0b0c0c); font-weight: 700; }
:host(.theme-govuk) .brand-panel-name { color: var(--pv-text, #0b0c0c); }
:host(.theme-govuk) .brand-panel-desc, :host(.theme-govuk) .brand-panel-desc strong { color: var(--pv-text, #505a5f); }
:host(.theme-govuk) .divider { display: none; }
:host(.theme-govuk) .btn-hint { display: none; }
:host(.theme-govuk) .btn-provider {
    justify-content: center;
    font-size: 19px;
    padding: 10px 12px;
    border: 2px solid transparent;
    border-radius: var(--pv-radius, 0);
    box-shadow: 0 2px 0 #929191;
    background: var(--pv-secondary, #f3f2f1);
    color: var(--pv-secondaryText, #0b0c0c);
    transition: none;
}
:host(.theme-govuk) .btn-provider ~ .btn-provider { margin-top: 16px; }
:host(.theme-govuk) .btn-provider .btn-label { flex: 0 1 auto; color: inherit; font-weight: 400; }
:host(.theme-govuk) .btn-provider svg { color: inherit; }
:host(.theme-govuk) .btn-provider:hover { background: #dbdad9; border-color: transparent; box-shadow: 0 2px 0 #929191; }
:host(.theme-govuk) .btn-provider:active { transform: translateY(2px); box-shadow: none; }
:host(.theme-govuk) .btn-provider.primary {
    background: var(--pv-primary, #00703c);
    color: var(--pv-primaryText, #fff);
    box-shadow: 0 2px 0 #002d18;
}
:host(.theme-govuk) .btn-provider.primary .btn-label,
:host(.theme-govuk) .btn-provider.primary svg { color: var(--pv-primaryText, #fff); }
:host(.theme-govuk) .btn-provider.primary:hover { background: #005a30; box-shadow: 0 2px 0 #002d18; }
:host(.theme-govuk) .btn-provider:focus-visible,
:host(.theme-govuk) .btn-provider.primary:focus-visible,
:host(.theme-govuk) .btn-retry:focus-visible {
    outline: 3px solid transparent;
    background: var(--pv-focus, #ffdd00);
    color: var(--pv-focusText, #0b0c0c);
    border-color: var(--pv-focus, #ffdd00);
    box-shadow: 0 2px 0 var(--pv-focusText, #0b0c0c);
}
:host(.theme-govuk) .btn-provider:focus-visible .btn-label,
:host(.theme-govuk) .btn-provider:focus-visible svg { color: var(--pv-focusText, #0b0c0c); }
:host(.theme-govuk) .btn-retry, :host(.theme-govuk) .gate-close { border-radius: var(--pv-radius, 0); }
:host(.theme-govuk) .btn-back { border-radius: 0; color: var(--pv-text, #0b0c0c); text-decoration: underline; }
:host(.theme-govuk) .link-btn,
:host(.theme-govuk) .footer a { color: var(--pv-link, #1d70b8); text-decoration: underline; }
:host(.theme-govuk) a:focus-visible,
:host(.theme-govuk) .link-btn:focus-visible,
:host(.theme-govuk) .btn-back:focus-visible {
    outline: 3px solid transparent;
    background: var(--pv-focus, #ffdd00);
    color: var(--pv-focusText, #0b0c0c);
    box-shadow: 0 -2px var(--pv-focus, #ffdd00), 0 4px var(--pv-focusText, #0b0c0c);
    text-decoration: none;
}
:host(.theme-govuk) .footer { font-size: 16px; color: var(--pv-text, #505a5f); border-color: var(--pv-border, #b1b4b6); }
:host(.theme-govuk) .gate-seal { color: var(--pv-text, #505a5f); }
:host(.theme-govuk) .gate-seal-text strong { color: var(--pv-text, #0b0c0c); }
@media (prefers-color-scheme: dark) {
    :host(.theme-govuk) { color: var(--pv-text, #f3f2f1); background: var(--pv-background, #0b0c0c); }
    :host(.theme-govuk) .auth-panel-heading, :host(.theme-govuk) .brand-panel-name { color: var(--pv-text, #f3f2f1); }
    :host(.theme-govuk) .brand-panel-desc, :host(.theme-govuk) .brand-panel-desc strong { color: var(--pv-text, #b1b4b6); }
    :host(.theme-govuk) .btn-provider { background: var(--pv-secondary, #383f43); color: var(--pv-secondaryText, #f3f2f1); box-shadow: 0 2px 0 #0b0c0c; }
    :host(.theme-govuk) .btn-provider:hover { background: #505a5f; box-shadow: 0 2px 0 #0b0c0c; }
    :host(.theme-govuk) .btn-provider.primary { background: var(--pv-primary, #00703c); color: var(--pv-primaryText, #fff); box-shadow: 0 2px 0 #000; }
    :host(.theme-govuk) .btn-provider.primary:hover { background: #005a30; }
    :host(.theme-govuk) .btn-provider:focus-visible,
    :host(.theme-govuk) .btn-provider.primary:focus-visible { background: var(--pv-focus, #ffdd00); color: var(--pv-focusText, #0b0c0c); box-shadow: 0 2px 0 var(--pv-focusText, #0b0c0c); }
    :host(.theme-govuk) .btn-back { color: var(--pv-text, #f3f2f1); }
    :host(.theme-govuk) .link-btn,
    :host(.theme-govuk) .footer a { color: var(--pv-link, #8cb8dc); }
    :host(.theme-govuk) .footer { color: var(--pv-text, #b1b4b6); border-color: var(--pv-border, #505a5f); }
    :host(.theme-govuk) .gate-seal { color: var(--pv-text, #b1b4b6); }
    :host(.theme-govuk) .gate-seal-text strong { color: var(--pv-text, #f3f2f1); }
}
`;

/** The gate's stylesheet additions for a theme: the preset and the token rules. */
export function themeStylesheet(theme: AuthTheme): string {
    return (theme.preset === 'govuk' ? GOVUK_CSS : '') + themeRules(theme);
}

/** The classes a theme puts on the gate's host element. */
export function themeClasses(theme: AuthTheme): string[] {
    const classes = ['themed'];
    if (theme.preset === 'govuk') classes.push('theme-govuk');
    return classes;
}
