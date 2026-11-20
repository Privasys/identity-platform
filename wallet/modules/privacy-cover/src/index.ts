// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The native app-switcher cover. iOS: the logo's closed halves, added the
 * moment the wallet goes to the background so the system's snapshot never
 * holds the holder's data. Android 13+: no Recents screenshot at all.
 */

import { Platform } from 'react-native';
import { requireOptionalNativeModule } from 'expo-modules-core';

const PrivacyCover = Platform.OS !== 'web' ? requireOptionalNativeModule('PrivacyCover') : null;

/** Cover the wallet whenever it goes to the background: on while the app lock is. */
export function setEnabled(on: boolean): void {
    PrivacyCover?.setEnabled(on);
}

/** Lift the cover, once the wallet's own screen has caught up on its return. */
export function release(): void {
    PrivacyCover?.release();
}
