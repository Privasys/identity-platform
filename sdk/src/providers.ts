/**
 * Which external identity providers a sign-in ceremony offers.
 *
 * The identity provider publishes the social providers it is configured
 * with (GitHub, Google, Microsoft, LinkedIn). By default the gate shows
 * every one of them. An adopter whose users sign in with one workplace
 * identity, say a government department on Microsoft Entra ID, names that
 * provider alone: the gate then shows a single "Sign in with Microsoft"
 * button instead of a chooser.
 *
 * The list arrives from the adopter page via postMessage and is rendered
 * inside the trusted origin, so it is checked against a closed vocabulary
 * here, like `methods` and `pitch`.
 */

/** The external identity providers the identity provider can federate. */
export const SOCIAL_PROVIDERS = ['github', 'google', 'microsoft', 'linkedin'] as const;

export type SocialProvider = (typeof SOCIAL_PROVIDERS)[number];

/** Brand-correct provider names for button labels. */
export const SOCIAL_PROVIDER_NAMES: Record<SocialProvider, string> = {
    github: 'GitHub',
    google: 'Google',
    microsoft: 'Microsoft',
    linkedin: 'LinkedIn',
};

/**
 * The adopter's `providers` option, reduced to known providers in the
 * order given, without duplicates. Anything that is not a non-empty array
 * of known names yields `undefined`, which means "no preference".
 */
export function sanitiseProviders(raw: unknown): readonly SocialProvider[] | undefined {
    if (!Array.isArray(raw)) return undefined;
    const out: SocialProvider[] = [];
    for (const p of raw) {
        if (typeof p !== 'string') continue;
        const name = p.trim().toLowerCase() as SocialProvider;
        if ((SOCIAL_PROVIDERS as readonly string[]).includes(name) && !out.includes(name)) out.push(name);
    }
    return out.length ? out : undefined;
}

/**
 * The providers the gate offers: those the identity provider has
 * available, restricted to the adopter's preference when one was given
 * and ordered as the adopter listed them. A requested provider the
 * identity provider does not have is left out; a preference that matches
 * nothing yields the published list, never an empty one.
 */
export function selectProviders(
    available: readonly string[],
    requested: readonly SocialProvider[] | undefined,
): string[] {
    if (!requested) return [...available];
    const chosen = requested.filter((p) => available.includes(p));
    // A preference that matches nothing is a misconfiguration; a gate with
    // no button at all would strand the user, so offer what is published.
    return chosen.length ? chosen : [...available];
}

/** The display name for a provider, falling back to the raw identifier. */
export function providerName(provider: string): string {
    return (SOCIAL_PROVIDER_NAMES as Record<string, string>)[provider] ?? provider;
}

/**
 * The label of a provider button. When the provider is the only way to
 * sign in, the button carries the full call to action; in a chooser the
 * provider's name is enough, as it sits under a heading.
 */
export function providerButtonLabel(provider: string, solo: boolean, displayName?: string): string {
    // A client with its own registration names it (its organisation), which
    // only reads as a call to action.
    if (displayName) return `Sign in with ${displayName}`;
    const name = providerName(provider);
    return solo ? `Sign in with ${name}` : name;
}

/**
 * The identity provider's button icons, reduced to https addresses. The
 * frame draws each as an image, never as markup, so the address is the
 * whole exposure; anything else is dropped and the brand icon stays.
 */
/** An https address without credentials, at most 512 characters, or nothing. */
function httpsAddress(raw: unknown): string | undefined {
    if (typeof raw !== 'string' || raw.length > 512) return undefined;
    let url: URL;
    try { url = new URL(raw); } catch { return undefined; }
    if (url.protocol !== 'https:' || url.username || url.password) return undefined;
    return url.href;
}

/**
 * A client's own registration with a provider, offered on the gate as a
 * button of its own next to the platform's (an organisation's staff
 * sign-in), with the organisation's name and, optionally, its icon.
 */
export interface OwnRegistration {
    provider: SocialProvider;
    displayName: string;
    iconUrl?: string;
}

/**
 * The identity provider's `own` listing, reduced to known providers with
 * a name of at most 64 characters and an https icon; anything else is
 * dropped, since the frame draws what it is given.
 */
export function sanitiseOwn(raw: unknown): OwnRegistration[] | undefined {
    if (!Array.isArray(raw)) return undefined;
    const out: OwnRegistration[] = [];
    for (const item of raw) {
        if (!item || typeof item !== 'object') continue;
        const { provider, display_name: name, icon } = item as Record<string, unknown>;
        if (typeof provider !== 'string' || !(SOCIAL_PROVIDERS as readonly string[]).includes(provider)) continue;
        if (typeof name !== 'string' || !name.trim() || name.length > 64) continue;
        const iconUrl = httpsAddress(icon);
        out.push({ provider: provider as SocialProvider, displayName: name.trim(), ...(iconUrl ? { iconUrl } : {}) });
    }
    return out.length ? out : undefined;
}

export function sanitiseIcons(raw: unknown): Record<string, string> | undefined {
    if (!raw || typeof raw !== 'object') return undefined;
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
        if (typeof v !== 'string' || v.length > 512) continue;
        let url: URL;
        try { url = new URL(v); } catch { continue; }
        if (url.protocol !== 'https:' || url.username || url.password) continue;
        out[k] = url.href;
    }
    return Object.keys(out).length ? out : undefined;
}

/** The identity provider's display names, reduced to plain short strings. */
export function sanitiseDisplayNames(raw: unknown): Record<string, string> | undefined {
    if (!raw || typeof raw !== 'object') return undefined;
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
        if (typeof v === 'string' && v.trim() && v.length <= 64) out[k] = v.trim();
    }
    return Object.keys(out).length ? out : undefined;
}
