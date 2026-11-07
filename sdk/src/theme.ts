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

/** The gate's stylesheet additions for a theme: the rules for its tokens. */
export function themeStylesheet(theme: AuthTheme): string {
    return themeRules(theme);
}

/** The classes a theme puts on the gate's host element. */
export function themeClasses(_theme: AuthTheme): string[] {
    return ['themed'];
}
