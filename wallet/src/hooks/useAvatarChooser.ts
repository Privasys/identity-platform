// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * One way to set the avatar, used from Profile (tap the picture) and from
 * Personal Data (the Avatar chip, or tap the Avatar card).
 *
 * The choice is an alert with two actions and Cancel, because Android shows
 * three alert buttons at most. Removing the avatar is the swipe on its card in
 * Personal Data, like every other attribute.
 */

import { useCallback } from 'react';
import { Alert } from 'react-native';
import { useTranslation } from 'react-i18next';

import { CANONICAL_ATTRIBUTES } from '@/services/attributes';
import { AvatarPermissionError, pickAvatar, type AvatarSource } from '@/services/avatar';
import { useProfileStore } from '@/stores/profile';

export function useAvatarChooser(): () => void {
    const { t } = useTranslation();

    const apply = useCallback(
        async (source: AvatarSource) => {
            try {
                const uri = await pickAvatar(source);
                if (!uri) return;
                const { setAttribute, updateProfile } = useProfileStore.getState();
                const now = Math.floor(Date.now() / 1000);
                // `picture` is single-valued: setAttribute replaces the one
                // there. The mirrored avatarUri is what Profile and disclosure
                // read.
                setAttribute({
                    key: 'picture',
                    label: CANONICAL_ATTRIBUTES.find((a) => a.key === 'picture')?.label ?? 'Avatar',
                    value: uri,
                    source: 'manual',
                    sources: [{ source: 'manual', displayName: t('personalData.sourceManual'), addedAt: now }],
                    acquiredAt: now,
                    updatedAt: now,
                    verified: false,
                });
                updateProfile({ avatarUri: uri });
            } catch (e) {
                if (e instanceof AvatarPermissionError) {
                    Alert.alert(t('profile.photoTitle'), t('profile.photoCameraDenied'));
                    return;
                }
                console.warn('[avatar] could not use the picture', e);
                Alert.alert(t('profile.photoTitle'), t('profile.photoFailed'));
            }
        },
        [t],
    );

    return useCallback(() => {
        Alert.alert(t('profile.photoTitle'), undefined, [
            { text: t('profile.photoTakeSelfie'), onPress: () => void apply('camera') },
            { text: t('profile.photoChoose'), onPress: () => void apply('library') },
            { text: t('common.cancel'), style: 'cancel' },
        ]);
    }, [apply, t]);
}
