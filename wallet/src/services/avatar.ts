// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The holder's avatar: a selfie or a photo from the library, made small enough
 * to live inside the profile.
 *
 * The picture is stored as a data URI, not a file path. The profile lives in
 * secure storage and survives a reinstall of the container; a file:// path did
 * not (earlier builds lost every cached avatar that way). A 256 pixel square
 * JPEG is a few tens of kilobytes, the same order as the ID portrait the
 * profile already carries.
 *
 * The library needs no permission: both platforms hand the app only the photo
 * the holder picked. The camera does, and is asked for when the holder taps
 * "Take a selfie", never before.
 */

import { manipulateAsync, SaveFormat } from 'expo-image-manipulator';
import * as ImagePicker from 'expo-image-picker';

/** Edge of the stored square, in pixels. */
export const AVATAR_EDGE = 256;

export type AvatarSource = 'camera' | 'library';

/** The holder refused the camera; the message is for the settings hint. */
export class AvatarPermissionError extends Error {}

/**
 * Ask for a picture and return it as a JPEG data URI, or null when the holder
 * backed out. Throws AvatarPermissionError when the camera is refused.
 */
export async function pickAvatar(source: AvatarSource): Promise<string | null> {
    const options: ImagePicker.ImagePickerOptions = {
        mediaTypes: ['images'],
        allowsEditing: true,
        aspect: [1, 1],
        quality: 1,
    };
    let result: ImagePicker.ImagePickerResult;
    if (source === 'camera') {
        const permission = await ImagePicker.requestCameraPermissionsAsync();
        if (!permission.granted) throw new AvatarPermissionError('camera refused');
        result = await ImagePicker.launchCameraAsync({
            ...options,
            cameraType: ImagePicker.CameraType.front,
        });
    } else {
        result = await ImagePicker.launchImageLibraryAsync(options);
    }
    if (result.canceled || !result.assets?.[0]) return null;
    return toAvatarDataUri(result.assets[0]);
}

/**
 * Centre-crop to a square and shrink to AVATAR_EDGE. The editor already asks
 * for a square, but Android's editor can be skipped and iOS returns the crop
 * rounded, so the square is enforced here rather than trusted.
 */
async function toAvatarDataUri(asset: ImagePicker.ImagePickerAsset): Promise<string> {
    const edge = Math.min(asset.width, asset.height);
    const out = await manipulateAsync(
        asset.uri,
        [
            {
                crop: {
                    originX: Math.floor((asset.width - edge) / 2),
                    originY: Math.floor((asset.height - edge) / 2),
                    width: edge,
                    height: edge,
                },
            },
            { resize: { width: AVATAR_EDGE, height: AVATAR_EDGE } },
        ],
        { compress: 0.8, base64: true, format: SaveFormat.JPEG },
    );
    if (!out.base64) throw new Error('the picture could not be encoded');
    return `data:image/jpeg;base64,${out.base64}`;
}
