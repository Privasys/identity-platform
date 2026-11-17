// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * In-wallet document preview. iOS: Apple's Quick Look over the wallet's own
 * screen (PDF, images, Office documents, text). Android: a PDF's pages drawn
 * by the system's PdfRenderer, for the wallet to show itself.
 */

import { Platform } from 'react-native';
import { requireNativeModule } from 'expo-modules-core';

const FilePreview = Platform.OS !== 'web' ? requireNativeModule('FilePreview') : null;

/** iOS: whether Quick Look can show this file. */
export async function canPreview(path: string): Promise<boolean> {
    if (Platform.OS !== 'ios' || !FilePreview) return false;
    return FilePreview.canPreview(path);
}

/** iOS: show the file with Quick Look. Resolves once it is on screen. The
 *  caller deletes the file when its own screen closes. */
export async function preview(path: string, title: string): Promise<void> {
    if (Platform.OS !== 'ios' || !FilePreview) throw new Error('Quick Look is iOS only');
    await FilePreview.preview(path, title);
}

export interface RenderedPage {
    uri: string;
    width: number;
    height: number;
}

/** Android: draw a PDF's pages to images beside it. */
export async function renderPdf(
    path: string,
    width: number,
    maxPages = 200,
): Promise<{ pages: RenderedPage[]; pageCount: number }> {
    if (Platform.OS !== 'android' || !FilePreview) throw new Error('PDF rendering is Android only');
    return FilePreview.renderPdf(path, Math.round(width), maxPages);
}
