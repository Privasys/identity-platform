// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Device-sourced locale.
 *
 * `locale` is the textbook attribute we can read straight from the OS rather
 * than asking the user: iOS/Android expose the user's preferred language as a
 * BCP-47 tag, surfaced here via expo-localization. We auto-fill the profile's
 * locale from the device so it "just works"; the manual picker (backed by the
 * referential value set) is only an override for when the app language should
 * differ from the device language.
 */

import { getLocales } from 'expo-localization';

/**
 * The device's preferred locale as a BCP-47 tag (e.g. "en-GB"), or '' if it
 * cannot be determined.
 */
export function getDeviceLocale(): string {
    try {
        const locales = getLocales();
        return locales?.[0]?.languageTag ?? '';
    } catch {
        return '';
    }
}
