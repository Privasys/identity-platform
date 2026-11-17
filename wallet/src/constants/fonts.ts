// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { Platform } from 'react-native';

/** The system monospace face: identifiers, codes, logs. No font is bundled
 *  for it. */
export const MONO = Platform.select({ ios: 'Menlo', android: 'monospace', default: 'monospace' });
