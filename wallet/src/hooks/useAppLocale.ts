// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Keeps the displayed language in step with the user's preference.
 *
 * Resolution order, highest first:
 *   1. Settings -> Language, an explicit choice the user made here
 *   2. the profile's `locale` attribute, auto-filled from the device on first
 *      run and shareable with relying parties that request the claim
 *   3. the OS locale, for the window before a profile exists
 *   4. en-GB
 *
 * The profile attribute sits above the raw device locale so that language
 * stays ONE concept across the wallet, the IdP and any RP: what the user is
 * shown is what they would disclose.
 *
 * Applying is fire-and-forget. `applyLocale` resolves false when a pack
 * cannot be fetched or fails its digest check, and the wallet simply stays on
 * the language it already had. Nothing here blocks a render.
 */

import { useEffect } from 'react';

import { applyLocale } from '@/i18n';
import { negotiateLocale } from '@/i18n/locales';
import { getDeviceLocale } from '@/services/device-locale';
import { useProfileStore } from '@/stores/profile';
import { useSettingsStore } from '@/stores/settings';

/** The tag the wallet should be showing, before any pack availability check. */
export function preferredLocale(
    override: string | null,
    profileLocale: string | undefined,
): string {
    return negotiateLocale(override || profileLocale || getDeviceLocale());
}

export function useAppLocale(): void {
    const override = useSettingsStore((s) => s.language);
    const profileLocale = useProfileStore((s) => s.profile?.locale);

    useEffect(() => {
        void applyLocale(preferredLocale(override, profileLocale));
    }, [override, profileLocale]);
}
