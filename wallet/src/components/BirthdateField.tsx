// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A date of birth, chosen on the system calendar instead of typed.
 *
 * Stored as `YYYY-MM-DD` (OIDC `birthdate`, the same form the ID check writes
 * to birthdate_id), shown as a long date in the holder's language. Android
 * opens its own calendar dialog; iOS shows its calendar inline under the
 * field, with a Done to close it.
 */

import DateTimePicker, { DateTimePickerAndroid, type DateTimePickerEvent } from '@react-native-community/datetimepicker';
import Ionicons from '@expo/vector-icons/Ionicons';
import { useMemo, useState } from 'react';
import { Platform, Pressable, StyleSheet, View as RNView } from 'react-native';
import { useTranslation } from 'react-i18next';

import { Text, usePalette, type Palette } from '@/components/Themed';
import { calendarDate } from '@/services/calendar-date';

const EARLIEST = new Date(1900, 0, 1);
// Where the calendar opens when nothing is set yet: a plausible adult's
// birth year rather than today, which is the one date it can never be.
const DEFAULT_OPEN = new Date(1990, 0, 1);

/** A local-time day as `YYYY-MM-DD`. */
export function isoDay(date: Date): string {
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

export function BirthdateField({
    value,
    onChange,
    placeholder,
}: {
    /** `YYYY-MM-DD`, or empty when nothing is chosen yet. */
    value: string;
    onChange: (iso: string) => void;
    placeholder?: string;
}) {
    const { t, i18n } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const [iosOpen, setIosOpen] = useState(false);
    const chosen = calendarDate(value);
    const today = new Date();

    const pick = (event: DateTimePickerEvent, date?: Date) => {
        if (event.type === 'set' && date) onChange(isoDay(date));
    };

    const open = () => {
        if (Platform.OS === 'android') {
            DateTimePickerAndroid.open({
                value: chosen ?? DEFAULT_OPEN,
                mode: 'date',
                minimumDate: EARLIEST,
                maximumDate: today,
                onChange: pick,
            });
        } else {
            setIosOpen((o) => !o);
        }
    };

    return (
        <RNView>
            <Pressable style={styles.field} onPress={open} accessibilityRole="button">
                <Text style={chosen ? styles.value : styles.placeholder} numberOfLines={1}>
                    {chosen ? t('kyc.reviewDate', { when: chosen }) : placeholder ?? ''}
                </Text>
                <Ionicons name="calendar-outline" size={18} color={p.textMuted} />
            </Pressable>
            {iosOpen && Platform.OS === 'ios' ? (
                <RNView>
                    <DateTimePicker
                        value={chosen ?? DEFAULT_OPEN}
                        mode="date"
                        display="inline"
                        locale={i18n.language}
                        minimumDate={EARLIEST}
                        maximumDate={today}
                        accentColor={p.action}
                        onChange={pick}
                    />
                    <Pressable style={styles.done} onPress={() => setIosOpen(false)} hitSlop={8}>
                        <Text style={styles.doneText}>{t('common.done')}</Text>
                    </Pressable>
                </RNView>
            ) : null}
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    field: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 10,
        borderWidth: 1,
        borderColor: p.border,
        borderRadius: 10,
        paddingHorizontal: 12,
        paddingVertical: 11,
    },
    value: { flex: 1, fontSize: 15, color: p.textPrimary },
    placeholder: { flex: 1, fontSize: 15, color: p.textMuted },
    done: { alignSelf: 'flex-end', paddingVertical: 6, paddingHorizontal: 4 },
    doneText: { fontSize: 15, fontWeight: '600', color: p.action },
});
