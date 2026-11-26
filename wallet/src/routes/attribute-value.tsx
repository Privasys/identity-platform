// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Personal Data -> a coded attribute (nationality, billing country, language):
 * pick it from the list instead of typing a code.
 *
 * Opened to ADD a value (no `value` param) or to CHANGE one (`value` = the
 * one held). Either way the choice is saved here, the same way Personal Data
 * saves a typed value, and the screen closes. A changed value is
 * self-asserted again, exactly as an edit on Personal Data makes it.
 */

import { useLocalSearchParams, useRouter } from 'expo-router';
import { useMemo } from 'react';
import { StyleSheet, View as RNView } from 'react-native';
import { useTranslation } from 'react-i18next';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { SubPageHeader } from '@/components/SubPageHeader';
import { usePalette, type Palette } from '@/components/Themed';
import { ValueList } from '@/components/ValueList';
import { CANONICAL_ATTRIBUTES } from '@/services/attributes';
import type { ValueOption } from '@/services/value-sets';
import { useProfileStore } from '@/stores/profile';

export default function AttributeValueScreen() {
    const router = useRouter();
    const { t } = useTranslation();
    const insets = useSafeAreaInsets();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { key, value } = useLocalSearchParams<{ key: string; value?: string }>();
    const def = CANONICAL_ATTRIBUTES.find((a) => a.key === key);

    const choose = (option: ValueOption) => {
        const store = useProfileStore.getState();
        if (!def || !store.profile) {
            router.back();
            return;
        }
        const now = Math.floor(Date.now() / 1000);
        if (value) {
            if (option.value !== value) {
                store.updateAttributeValue(def.key, value, {
                    value: option.value,
                    source: 'manual',
                    sourceProvider: undefined,
                    sources: [{ source: 'manual', displayName: t('personalData.sourceManual'), addedAt: now }],
                    verified: false,
                    verifications: [],
                });
            }
        } else {
            store.mergeAttribute(
                {
                    key: def.key,
                    label: def.label,
                    value: option.value,
                    source: 'manual',
                    acquiredAt: now,
                    updatedAt: now,
                    verified: false,
                },
                !!def.multiValued,
            );
        }
        if (def.profileField === 'locale') store.updateProfile({ locale: option.value });
        router.back();
    };

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={def?.label ?? ''} />
            <RNView style={styles.body}>
                <ValueList attrKey={key} selected={value} onSelect={choose} bottomInset={insets.bottom + 16} />
            </RNView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    body: { flex: 1, paddingHorizontal: 20, paddingTop: 16 },
});
