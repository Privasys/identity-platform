// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The bytes behind a demo Drive file: a bundled sample for the PDF and the
 * photo, a string for Markdown. Kept apart from the fixtures so the tests,
 * which never open a file, do not load the asset system.
 */

import { Asset } from 'expo-asset';
import { File } from 'expo-file-system';

import type { DemoContent } from './fixtures';
import { DEMO_NOTES } from './notes';

/* eslint-disable @typescript-eslint/no-require-imports */
const SAMPLES = {
    pdf: require('./assets/residents-meeting-minutes.pdf'),
    jpeg: require('./assets/harbour-at-dusk.jpg'),
};
/* eslint-enable @typescript-eslint/no-require-imports */

export async function contentBytes(content: DemoContent): Promise<Uint8Array> {
    if (content === 'pdf' || content === 'jpeg') {
        // Embedded in the app, so this resolves on a simulator with no network.
        const [asset] = await Asset.loadAsync(SAMPLES[content]);
        if (!asset.localUri) throw new Error('the demo sample is missing');
        return new File(asset.localUri).bytes();
    }
    return new TextEncoder().encode(DEMO_NOTES[content]);
}
