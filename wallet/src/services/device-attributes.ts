// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Device-sourced attribute registry.
 *
 * Some canonical attributes are marked `deviceSourced` in the referential
 * (canonical-attributes.json) because the client OS can supply them directly,
 * so the wallet auto-fills them instead of prompting. This maps each such
 * attribute key to the function that reads it from the device. To add another
 * (e.g. a future `zoneinfo` from the device timezone), set `deviceSourced: true`
 * in the referential and add its reader here.
 */

import { getDeviceLocale } from '@/services/device-locale';

const DEVICE_SOURCES: Record<string, () => string> = {
    locale: getDeviceLocale,
};

/**
 * The device value for a canonical attribute, or '' if the OS cannot supply it
 * (or the attribute has no device reader).
 */
export function getDeviceAttribute(key: string): string {
    const reader = DEVICE_SOURCES[key];
    return reader ? reader() : '';
}
