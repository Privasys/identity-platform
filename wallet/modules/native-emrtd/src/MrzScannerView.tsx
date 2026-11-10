// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The live camera preview that reads the document's photo page.
 *
 * It reports the text it reads in each frame, with where it is, and keeps the
 * last frame that looked like it held a machine readable zone. `snapshot`
 * returns that frame, so the picture sent on is the one that was read.
 */

import { requireNativeViewManager } from 'expo-modules-core';
import type { ComponentType, Ref } from 'react';
import type { NativeSyntheticEvent, StyleProp, ViewStyle } from 'react-native';
import { Platform } from 'react-native';

import type { FrameCrop, TextLine } from './mrz-lines';

/** What was read in one frame. */
export interface MrzFrame {
    /** Counts up with each frame read. */
    frame: number;
    /** The frame's size in pixels, upright. */
    width: number;
    height: number;
    /** Whether this frame was kept for `snapshot`. */
    held: boolean;
    lines: TextLine[];
}

/** The native view's own methods, reached through its ref. */
export interface MrzScannerHandle {
    /** The kept frame as a base64 JPEG, cut to `crop`. Empty when none is kept. */
    snapshot(crop: FrameCrop): Promise<string>;
}

export interface MrzScannerProps {
    ref?: Ref<MrzScannerHandle>;
    style?: StyleProp<ViewStyle>;
    /** Runs the camera while true. */
    active: boolean;
    onText?: (event: NativeSyntheticEvent<MrzFrame>) => void;
    onReady?: () => void;
    onCameraError?: (event: NativeSyntheticEvent<{ message: string }>) => void;
}

function load(): ComponentType<MrzScannerProps> | null {
    if (Platform.OS === 'web') return null;
    try {
        return requireNativeViewManager<MrzScannerProps>('NativeEmrtd');
    } catch {
        // A build without the native module: the caller says so.
        return null;
    }
}

/** Null where the native view is not in the build. */
export const MrzScannerView = load();
