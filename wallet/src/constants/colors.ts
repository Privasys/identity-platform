// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Semantic colour palette, light and dark. Screens must use these tokens (via
 * `usePalette()` from '@/components/Themed') instead of hardcoded hex values —
 * hardcoded light values were why dark mode was broken app-wide.
 *
 * Brand accents (green/blue) are scheme-invariant; surfaces and text invert.
 */

const brand = {
    /** Privasys green — headers, success accents, TEE badge (SGX). */
    green: '#34E89E',
    /** Privasys blue — links, TEE badge (TDX). */
    blue: '#00BCF2',
    /** Primary action blue (iOS-style). */
    action: '#007AFF',
    /** Approve green. */
    approve: '#34C759',
    /** Destructive red. */
    danger: '#DC2626',
};

export type Palette = {
    /** Page background behind cards. */
    screenBg: string;
    /** Card / tile surface. */
    card: string;
    /** Secondary surface (input fields, muted tiles, code blocks). */
    cardAlt: string;
    /** Primary text. */
    textPrimary: string;
    /** Secondary text (descriptions, metadata). */
    textSecondary: string;
    /** Muted text (placeholders, timestamps, section headers). */
    textMuted: string;
    /** Hairline borders / dividers. */
    border: string;
    /** Success tint (banner backgrounds) + border + text. */
    successBg: string;
    successBorder: string;
    successText: string;
    /** Warning (amber) tint + border + text. */
    warnBg: string;
    warnBorder: string;
    warnText: string;
    /** Danger (red) tint + border + text. */
    dangerBg: string;
    dangerBorder: string;
    dangerText: string;
    /** Info (teal) tint + border + text — challenge/liveness affordances. */
    infoBg: string;
    infoBorder: string;
    infoText: string;
    /** Neutral button background (Reject/Cancel). */
    buttonNeutral: string;
    /** Brand accents (scheme-invariant). */
    green: string;
    blue: string;
    action: string;
    approve: string;
    danger: string;
};

const light: Palette = {
    screenBg: '#F8FAFB',
    card: '#FFFFFF',
    cardAlt: '#F1F5F9',
    textPrimary: '#0F172A',
    textSecondary: '#64748B',
    textMuted: '#94A3B8',
    border: '#E2E8F0',
    successBg: '#E8FFF0',
    successBorder: '#34D399',
    successText: '#166534',
    warnBg: '#FEF9E7',
    warnBorder: '#F6D680',
    warnText: '#92610A',
    dangerBg: '#FFF1F0',
    dangerBorder: '#FCA5A5',
    dangerText: '#991B1B',
    infoBg: '#ECFDF5',
    infoBorder: '#5EEAD4',
    infoText: '#0F766E',
    buttonNeutral: 'rgba(128,128,128,0.2)',
    ...brand,
};

const dark: Palette = {
    screenBg: '#0B1220',
    card: '#16202F',
    cardAlt: '#1E293B',
    textPrimary: '#F1F5F9',
    textSecondary: '#94A3B8',
    textMuted: '#64748B',
    border: '#2C3A4E',
    successBg: '#07301D',
    successBorder: '#14532D',
    successText: '#86EFAC',
    warnBg: '#33280A',
    warnBorder: '#92610A',
    warnText: '#FCD34D',
    dangerBg: '#350F0F',
    dangerBorder: '#7F1D1D',
    dangerText: '#FCA5A5',
    infoBg: '#062A26',
    infoBorder: '#0F766E',
    infoText: '#5EEAD4',
    buttonNeutral: 'rgba(148,163,184,0.25)',
    ...brand,
};

/**
 * Legacy shape consumed by Themed.tsx (text/background/tint + tab icons),
 * extended with the full semantic palette per scheme.
 */
export default {
    light: {
        text: light.textPrimary,
        background: light.screenBg,
        tint: brand.action,
        tabIconDefault: light.textMuted,
        tabIconSelected: brand.action,
        ...light,
    },
    dark: {
        text: dark.textPrimary,
        background: dark.screenBg,
        tint: brand.green,
        tabIconDefault: dark.textMuted,
        tabIconSelected: brand.green,
        ...dark,
    },
};

export { light as lightPalette, dark as darkPalette };
