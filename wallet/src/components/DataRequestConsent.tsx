// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The data-sharing screen: "what this service will receive".
 *
 * Shared by the sign-in consent step, the attribute step-up, and the KYC
 * identity-verification flow. Presentational only: the caller owns the data
 * and the approve/deny logic.
 *
 * A ROW IS TWO LINES, and that is the whole layout decision:
 *
 *     [✓]  Email                                  required
 *          bertrand@example.org
 *
 * The metadata sits right, the value gets a line of its own at full width.
 * The approval screen packs the same information onto one line because the
 * attribute list is one of five sections there and every pixel is contested.
 * Here the list IS the screen, and the values that overflow a right-hand
 * column (an email, a full name, an address) are exactly the ones a person
 * has to read in full before agreeing to send them. Two lines removes the
 * truncation rather than solving it with a tap.
 *
 * A row is one requested attribute and nothing else. A struck-through row is
 * one the holder unticked; it is never a derivation of another row.
 *
 * There is deliberately no attestation summary here. It used to render
 * "Attested · Intel TDX" plus two measurements, duplicating the approval
 * screen's whole job in a worse form, and its only caller has been deleted.
 */

import { Ionicons } from '@expo/vector-icons';
import { useMemo, useState } from 'react';
import { Pressable, ScrollView, StyleSheet, Switch, View as RNView } from 'react-native';
import { Trans, useTranslation } from 'react-i18next';

import { Text, usePalette, type Palette } from '@/components/Themed';

export interface ConsentDataItem {
    key: string;
    label: string;
    /**
     * The value that will actually be sent. Undefined when the wallet cannot
     * honestly produce one, in which case `note` explains why rather than
     * leaving the row silent.
     */
    value?: string;
    /** Stands in for the value: an assurance, or what a proof withholds. */
    note?: string;
    /** Render `note` in a warning colour (e.g. the wallet has nothing to send). */
    missing?: boolean;
    /** Right-hand chip. Omit both for a plain informational row. */
    required?: boolean;
    /** Government-backed: the chip says where the attribute came from. */
    gov?: boolean;
    /** Leading icon for a plain (non-toggle) item. */
    icon?: keyof typeof Ionicons.glyphMap;
    /** When set, the row leads with a tickbox instead of an icon. */
    toggle?: { value: boolean; onChange: () => void; disabled?: boolean };
}

export function DataRequestConsent({
    appName,
    origin,
    purpose,
    appIcon = 'cube-outline',
    title,
    sectionTitle,
    sectionDescription,
    items,
    note,
    persistent,
    denyLabel,
    approveLabel,
    approveCount,
    approveDisabled,
    submitting,
    onDeny,
    onApprove,
    contentBottomInset = 20,
    actionsBottomInset = 16,
    contentTopInset = 0,
}: {
    appName: string;
    origin: string;
    purpose?: string;
    appIcon?: keyof typeof Ionicons.glyphMap;
    /**
     * Screen title. When given, the screen grows the brand-green header band
     * every other screen in the wallet uses, and owns its own safe area.
     * Without it the caller is expected to supply `contentTopInset`.
     */
    title?: string;
    sectionTitle?: string;
    sectionDescription?: string;
    items: ConsentDataItem[];
    note?: string;
    persistent?: { value: boolean; onChange: (v: boolean) => void };
    denyLabel?: string;
    approveLabel?: string;
    /** Count shown in the approve button, e.g. "Share (2)". Omit to hide. */
    approveCount?: number;
    approveDisabled?: boolean;
    submitting?: boolean;
    onDeny: () => void;
    onApprove: () => void;
    contentBottomInset?: number;
    actionsBottomInset?: number;
    contentTopInset?: number;
}) {
    const p = usePalette();
    const { t } = useTranslation();
    const styles = useMemo(() => makeStyles(p), [p]);
    // Defaults resolve here rather than in the parameter list, so they follow
    // a language change like every other string on the screen.
    const sectionHeading = sectionTitle ?? t('consent.requestedData');
    const denyText = denyLabel ?? t('connect.deny');
    const approveText = approveLabel ?? t('connect.share');
    /** Rows whose value the holder has tapped to see in full. */
    const [shownInFull, setShownInFull] = useState<Set<string>>(new Set());

    return (
        <RNView style={styles.flex}>
            {title ? (
                <RNView style={[styles.header, { paddingTop: contentTopInset + 14 }]}>
                    <Text style={styles.headerTitle}>{title}</Text>
                </RNView>
            ) : null}

            <ScrollView
                style={styles.flex}
                contentContainerStyle={[
                    styles.scrollContent,
                    { paddingTop: title ? 4 : 20 + contentTopInset, paddingBottom: contentBottomInset },
                ]}
                showsVerticalScrollIndicator={false}
            >
                {/* The ask. A 56pt circle plus a name plus an origin said what
                    one line of type says, and cost 150 vertical pixels. */}
                {title ? (
                    <Text style={styles.ask}>
                        <Trans
                            i18nKey="consent.asks"
                            values={{ app: appName }}
                            components={{ b: <Text style={styles.askApp} /> }}
                        />
                    </Text>
                ) : (
                    <RNView style={styles.appCard}>
                        <RNView style={styles.appIcon}>
                            <Ionicons name={appIcon} size={28} color={p.card} />
                        </RNView>
                        <Text style={styles.appName}>{appName}</Text>
                        <Text style={styles.appOrigin}>{origin}</Text>
                    </RNView>
                )}

                {purpose ? (
                    <RNView style={styles.purposeContainer}>
                        <Ionicons name="chatbubble-outline" size={14} color={p.textSecondary} />
                        <Text style={styles.purposeText}>{purpose}</Text>
                    </RNView>
                ) : null}

                <Text style={styles.sectionTitle}>{sectionHeading}</Text>
                {sectionDescription ? (
                    <Text style={styles.sectionDescription}>{sectionDescription}</Text>
                ) : null}

                <RNView style={styles.card}>
                    {items.map((item, i) => {
                        const on = !item.toggle || item.toggle.value;
                        const locked = item.toggle?.disabled === true;
                        const full = shownInFull.has(item.key);
                        const chip = item.gov
                            ? t('consent.fromYourId')
                            : item.required
                                ? t('attestation.requiredMark')
                                : item.toggle
                                    ? t('consent.optional')
                                    : undefined;
                        const second = item.value ?? item.note;
                        return (
                            <RNView
                                key={item.key}
                                style={[styles.row, i === items.length - 1 && styles.rowLast]}
                            >
                                <RNView style={styles.rowTop}>
                                    {item.toggle ? (
                                        <Pressable
                                            onPress={locked ? undefined : item.toggle.onChange}
                                            disabled={locked}
                                            hitSlop={8}
                                            accessibilityRole="checkbox"
                                            accessibilityState={{ checked: on, disabled: locked }}
                                            accessibilityLabel={item.label}
                                        >
                                            <Ionicons
                                                name={locked ? 'checkmark-circle' : on ? 'checkbox' : 'square-outline'}
                                                size={18}
                                                color={locked ? p.approve : on ? p.action : p.textMuted}
                                            />
                                        </Pressable>
                                    ) : item.icon ? (
                                        <Ionicons name={item.icon} size={18} color={p.textSecondary} />
                                    ) : null}
                                    <Text style={[styles.rowLabel, !on && styles.rowOff]} numberOfLines={1}>
                                        {item.label}
                                    </Text>
                                    {chip ? (
                                        <Text style={[styles.chip, item.gov && styles.chipGov]}>{chip}</Text>
                                    ) : null}
                                </RNView>
                                {second ? (
                                    <Text
                                        style={[
                                            styles.rowValue,
                                            !item.value && styles.rowValueNote,
                                            item.missing && styles.rowValueMissing,
                                            // Struck through rather than removed:
                                            // the app asked and the holder
                                            // declined, and both facts belong on
                                            // screen.
                                            !on && styles.rowOffValue,
                                        ]}
                                        numberOfLines={full ? undefined : 2}
                                        onPress={
                                            item.value
                                                ? () => setShownInFull((s) => {
                                                    const n = new Set(s);
                                                    if (n.has(item.key)) n.delete(item.key);
                                                    else n.add(item.key);
                                                    return n;
                                                })
                                                : undefined
                                        }
                                        suppressHighlighting
                                    >
                                        {second}
                                    </Text>
                                ) : null}
                            </RNView>
                        );
                    })}
                </RNView>

                {persistent ? (
                    <RNView style={styles.persistentRow}>
                        <RNView style={styles.persistentInfo}>
                            <Text style={styles.persistentLabel}>{t('consent.alwaysShare')}</Text>
                            <Text style={styles.persistentHint}>{t('consent.alwaysShareHint')}</Text>
                        </RNView>
                        <Switch
                            value={persistent.value}
                            onValueChange={persistent.onChange}
                            trackColor={{ false: p.border, true: p.green }}
                            thumbColor="#FFFFFF"
                        />
                    </RNView>
                ) : null}

                {note ? <Text style={styles.note}>{note}</Text> : null}
            </ScrollView>

            <RNView style={[styles.actions, { paddingBottom: actionsBottomInset }]}>
                <Pressable
                    style={[styles.denyButton, submitting && styles.disabledButton]}
                    onPress={onDeny}
                    disabled={submitting}
                >
                    <Text style={styles.denyButtonText}>{denyText}</Text>
                </Pressable>
                <Pressable
                    style={[styles.approveButton, (submitting || approveDisabled) && styles.disabledButton]}
                    onPress={onApprove}
                    disabled={submitting || approveDisabled}
                >
                    <Text style={styles.approveButtonText}>
                        {approveCount !== undefined
                            ? t('consent.approveWithCount', { label: approveText, count: approveCount })
                            : approveText}
                    </Text>
                </Pressable>
            </RNView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    flex: { flex: 1 },
    scrollContent: { paddingHorizontal: 20 },

    header: {
        backgroundColor: p.green,
        paddingHorizontal: 20,
        paddingBottom: 20,
        borderBottomLeftRadius: 28,
        borderBottomRightRadius: 28,
    },
    headerTitle: { fontSize: 22, fontWeight: '700', color: '#FFFFFF', letterSpacing: -0.4 },

    ask: { fontSize: 17, lineHeight: 26, color: p.textSecondary, marginTop: 16, marginBottom: 22 },
    askApp: { fontWeight: '700', color: p.textPrimary },

    // Legacy identity block, kept for callers that render without a header.
    appCard: { alignItems: 'center', backgroundColor: p.card, borderRadius: 16, padding: 24, marginBottom: 12 },
    appIcon: {
        width: 56, height: 56, borderRadius: 28, backgroundColor: p.textPrimary,
        alignItems: 'center', justifyContent: 'center', marginBottom: 12,
    },
    appName: { fontSize: 20, fontWeight: '700', color: p.textPrimary, marginBottom: 4 },
    appOrigin: { fontSize: 13, color: p.textSecondary },

    purposeContainer: {
        flexDirection: 'row', alignItems: 'center', gap: 6, backgroundColor: p.cardAlt,
        borderRadius: 8, paddingVertical: 8, paddingHorizontal: 12, marginBottom: 12,
    },
    purposeText: { fontSize: 13, color: p.textSecondary, flex: 1, lineHeight: 18 },

    sectionTitle: {
        fontSize: 12, fontWeight: '700', letterSpacing: 0.6, textTransform: 'uppercase',
        color: p.textMuted, marginBottom: 6,
    },
    sectionDescription: { fontSize: 12.5, color: p.textSecondary, marginBottom: 10, lineHeight: 18 },

    card: {
        backgroundColor: p.card,
        borderRadius: 12,
        borderWidth: StyleSheet.hairlineWidth,
        borderColor: p.border,
        paddingHorizontal: 14,
    },
    row: {
        paddingVertical: 11,
        borderBottomWidth: StyleSheet.hairlineWidth,
        borderBottomColor: p.border,
    },
    rowLast: { borderBottomWidth: 0 },
    rowTop: { flexDirection: 'row', alignItems: 'center', gap: 10 },
    rowLabel: { flex: 1, fontSize: 14, color: p.textPrimary },
    rowOff: { color: p.textMuted },
    chip: { fontSize: 11, color: p.textMuted, letterSpacing: 0.2 },
    chipGov: { color: p.infoText, fontWeight: '600' },
    // Indented to sit under the label rather than the tickbox, so the eye
    // reads label-then-value as one unit.
    rowValue: { fontSize: 13, color: p.textPrimary, fontWeight: '500', marginTop: 4, marginLeft: 28 },
    rowValueNote: { color: p.textMuted, fontWeight: '400', fontSize: 12, fontStyle: 'italic' },
    rowValueMissing: { color: p.warnText, fontStyle: 'italic' },
    rowOffValue: { color: p.textMuted, textDecorationLine: 'line-through' },

    persistentRow: {
        flexDirection: 'row', alignItems: 'center', backgroundColor: p.card,
        borderRadius: 12, borderWidth: StyleSheet.hairlineWidth, borderColor: p.border,
        padding: 14, marginTop: 12,
    },
    persistentInfo: { flex: 1, marginRight: 12 },
    persistentLabel: { fontSize: 14, fontWeight: '600', color: p.textPrimary, marginBottom: 3 },
    persistentHint: { fontSize: 12, color: p.textMuted, lineHeight: 17 },

    note: { fontSize: 12.5, color: p.textMuted, marginTop: 14, lineHeight: 18 },

    actions: {
        flexDirection: 'row', gap: 10, paddingHorizontal: 20, paddingTop: 12,
        backgroundColor: p.screenBg,
        borderTopWidth: StyleSheet.hairlineWidth, borderTopColor: p.border,
    },
    denyButton: {
        flex: 1, paddingVertical: 15, borderRadius: 12,
        alignItems: 'center', backgroundColor: p.buttonNeutral,
    },
    denyButtonText: { fontSize: 16, fontWeight: '600', color: p.textPrimary },
    approveButton: {
        flex: 1.35, paddingVertical: 15, borderRadius: 12,
        alignItems: 'center', backgroundColor: p.green,
    },
    approveButtonText: { fontSize: 16, fontWeight: '600', color: '#FFFFFF' },
    disabledButton: { opacity: 0.5 },
});
