// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Personal Data sub-page — manage identity attributes.
 *
 * Moved from inline profile tab to its own screen. Includes:
 * - Attribute cards with provenance, inline editing, swipe-to-delete
 * - Add missing attributes via chips
 * - Import from account (OAuth provider linking)
 *
 * Export All Data stays on the profile tab.
 */

import { Ionicons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';
import { useMemo, useState } from 'react';
import {
    StyleSheet,
    KeyboardAvoidingView,
    Platform,
    ScrollView,
    Pressable,
    View as RNView,
    TextInput,
    Alert,
    Image,
} from 'react-native';
import { Swipeable } from 'react-native-gesture-handler';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { SubPageHeader } from '@/components/SubPageHeader';
import { useTranslation } from 'react-i18next';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { CANONICAL_ATTRIBUTES, isGovVerified } from '@/services/attributes';
import { useProfileStore, type ProfileAttribute } from '@/stores/profile';

export default function PersonalDataScreen() {
    const { t } = useTranslation();
    const router = useRouter();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const { profile, updateProfile, setAttribute, updateAttributeValue, removeAttributeValue } = useProfileStore();

    const [addingAttribute, setAddingAttribute] = useState<string | null>(null);
    const [newAttrValue, setNewAttrValue] = useState('');

    if (!profile) {
        router.back();
        return null;
    }

    const handleRemoveAttribute = (attr: ProfileAttribute) => {
        Alert.alert(
            t('personalData.removeTitle', { label: attr.label }),
            t('personalData.removeBody'),
            [
                { text: t('common.cancel'), style: 'cancel' },
                {
                    text: t('common.remove'),
                    style: 'destructive',
                    onPress: () => {
                        // Other values stored under the same key (multi-valued attrs).
                        const others = profile.attributes.filter(
                            (a) => a.key === attr.key && a.value !== attr.value,
                        );
                        removeAttributeValue(attr.key, attr.value);
                        // Keep the mirrored top-level field pointing at a value that
                        // still exists (or clear it if this was the last one).
                        const fallback = others[0]?.value ?? '';
                        if (attr.key === 'email') updateProfile({ email: fallback });
                        if (attr.key === 'name') updateProfile({ displayName: fallback });
                        if (attr.key === 'picture') updateProfile({ avatarUri: fallback });
                    },
                },
            ],
        );
    };

    const handleAddAttribute = (key: string) => {
        setAddingAttribute(key);
        setNewAttrValue('');
    };

    const handleSaveNewAttribute = () => {
        if (!addingAttribute || !newAttrValue.trim()) return;
        const def = CANONICAL_ATTRIBUTES.find((a) => a.key === addingAttribute);
        if (!def) return;

        const now = Math.floor(Date.now() / 1000);
        setAttribute({
            key: addingAttribute,
            label: def.label,
            value: newAttrValue.trim(),
            source: 'manual',
            acquiredAt: now,
            updatedAt: now,
            verified: false,
        });

        if (def.profileField === 'email') updateProfile({ email: newAttrValue.trim() });
        if (def.profileField === 'displayName') updateProfile({ displayName: newAttrValue.trim() });
        if (def.profileField === 'locale') updateProfile({ locale: newAttrValue.trim() });

        setAddingAttribute(null);
        setNewAttrValue('');
    };

    const existingKeys = new Set(profile.attributes.map((a) => a.key));
    // Government-verified keys are NOT offered for manual entry. A passport
    // number, a document expiry or an "18 or older" proof means something only
    // because a chip signed for it; letting someone type one produces a field
    // that looks like the real thing on a screen that is otherwise about
    // provenance. They arrive from the identity verifier or not at all, so the
    // chips list only what a person can legitimately assert about themselves
    // (2026-08-26). Date of Birth and Nationality stay: those are self-asserted
    // keys with gov-verified twins (birthdate_id, nationality_id), and the
    // disclosure path already knows the difference.
    const missingAttributes = CANONICAL_ATTRIBUTES.filter(
        (a) => !existingKeys.has(a.key) && a.key !== 'picture' && !isGovVerified(a.key),
    );

    // Logical display order, not insertion order: keep related attributes together
    // — the everyday name then its legal ID counterpart, contact grouped, then the
    // identity/document group. Same-key values (e.g. several emails) stay adjacent
    // (stable sort). Unlisted keys fall to the end.
    const ATTR_ORDER = [
        'name', 'given_name', 'given_name_id', 'family_name', 'family_name_id',
        'nickname', 'picture', 'picture_id', 'email', 'phone_number',
        'birthdate', 'birthdate_id', 'age_over_18', 'age_over_21', 'sex',
        'nationality', 'nationality_id',
        'place_of_birth', 'document_type', 'document_number', 'doc_expiry',
        'issuing_state', 'personal_number', 'locale',
    ];
    const orderOf = (k: string) => {
        const i = ATTR_ORDER.indexOf(k);
        return i === -1 ? ATTR_ORDER.length : i;
    };
    const sortedAttributes = [...profile.attributes].sort((a, b) => orderOf(a.key) - orderOf(b.key));

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t('personalData.title')} />

            {/* The editor and the add-attribute field sit at the BOTTOM of a
                long list, so the keyboard covered whichever one had focus and
                the list could not scroll past it: entering a display name by
                hand was impossible. Same treatment as recover-account, plus
                bottom padding the height of the keyboard has something to
                scroll into. */}
            <KeyboardAvoidingView
                style={{ flex: 1 }}
                behavior={Platform.OS === 'ios' ? 'padding' : undefined}
                // No offset. React Native computes the padding as
                // (view bottom - (keyboard top - offset)), so a POSITIVE offset
                // ADDS that much dead space above the keyboard rather than
                // correcting for a header. This view already begins BELOW the
                // header, so its bottom is the screen bottom and the plain
                // keyboard height is exactly right. An earlier cut passed
                // insets.top + 50 and put a block of roughly 97pt on screen,
                // which hid more than the keyboard ever did.
                keyboardVerticalOffset={0}
            >
            <ScrollView
                style={styles.scrollView}
                contentContainerStyle={[styles.scrollContent, { paddingBottom: insets.bottom + 120 }]}
                showsVerticalScrollIndicator={false}
                keyboardShouldPersistTaps="handled"
            >
                <Text style={styles.sectionDescription}>{t('personalData.description')}</Text>

                {/* Attribute cards */}
                {profile.attributes.length === 0 ? (
                    <RNView style={styles.emptyCard}>
                        <Ionicons name="document-text-outline" size={32} color={p.textMuted} />
                        <Text style={styles.emptyCardText}>{t('personalData.empty')}</Text>
                    </RNView>
                ) : (
                    sortedAttributes.map((attr) => (
                        <AttributeCard
                            key={`${attr.key}:${attr.value}`}
                            attr={attr}
                            onRemove={() => handleRemoveAttribute(attr)}
                            onEdit={(newValue) => {
                                const now = Math.floor(Date.now() / 1000);
                                // Editing makes the value self-asserted again: reset
                                // provenance to a single manual source.
                                updateAttributeValue(attr.key, attr.value, {
                                    value: newValue,
                                    source: 'manual',
                                    sourceProvider: undefined,
                                    sources: [{ source: 'manual', displayName: t('personalData.sourceManual'), addedAt: now }],
                                    verified: false,
                                    verifications: [],
                                });
                                if (attr.key === 'email') updateProfile({ email: newValue });
                                if (attr.key === 'name') updateProfile({ displayName: newValue });
                            }}
                        />
                    ))
                )}

                {/* Add missing attribute */}
                {addingAttribute ? (
                    <RNView style={styles.addAttrCard}>
                        <Text style={styles.addAttrLabel}>
                            {CANONICAL_ATTRIBUTES.find((a) => a.key === addingAttribute)?.label}
                        </Text>
                        <TextInput
                            style={styles.addAttrInput}
                            value={newAttrValue}
                            onChangeText={setNewAttrValue}
                            placeholder={t('personalData.enterValue')}
                            placeholderTextColor={p.textMuted}
                            autoFocus
                            autoCapitalize={addingAttribute === 'email' ? 'none' : 'words'}
                            keyboardType={addingAttribute === 'email' ? 'email-address' : addingAttribute === 'phone_number' ? 'phone-pad' : 'default'}
                        />
                        <RNView style={styles.addAttrActions}>
                            <Pressable onPress={() => setAddingAttribute(null)}>
                                <Text style={styles.addAttrCancel}>{t('common.cancel')}</Text>
                            </Pressable>
                            <Pressable
                                style={[styles.addAttrSave, !newAttrValue.trim() && { opacity: 0.4 }]}
                                onPress={handleSaveNewAttribute}
                                disabled={!newAttrValue.trim()}
                            >
                                <Text style={styles.addAttrSaveText}>{t('common.save')}</Text>
                            </Pressable>
                        </RNView>
                    </RNView>
                ) : missingAttributes.length > 0 ? (
                    <RNView style={styles.addAttrChips}>
                        <Text style={styles.addAttrHint}>Add:</Text>
                        {missingAttributes.map((def) => (
                            <Pressable
                                key={def.key}
                                style={styles.addAttrChip}
                                onPress={() => handleAddAttribute(def.key)}
                            >
                                <Ionicons name="add" size={14} color={p.blue} />
                                <Text style={styles.addAttrChipText}>{def.label}</Text>
                            </Pressable>
                        ))}
                    </RNView>
                ) : null}

                {/* Import — opens the dedicated Import Data subpage */}
                <Pressable style={styles.importButton} onPress={() => router.push('/import' as never)}>
                    <Ionicons name="cloud-download-outline" size={18} color={p.blue} />
                    <Text style={styles.importButtonText}>Import data</Text>
                </Pressable>

                <RNView style={{ height: 40 }} />
            </ScrollView>
            </KeyboardAvoidingView>
        </RNView>
    );
}

// ── Attribute card with provenance details ──────────────────────────────

function AttributeCard({ attr, onRemove, onEdit }: { attr: ProfileAttribute; onRemove: () => void; onEdit: (newValue: string) => void }) {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const [expanded, setExpanded] = useState(false);
    const [editing, setEditing] = useState(false);
    const [editValue, setEditValue] = useState(attr.value);

    const sourceLabel =
        attr.source === 'provider' && attr.sourceProvider
            ? t('personalData.viaProvider', { provider: attr.sourceProvider })
            : attr.source === 'manual'
            ? t('personalData.enteredManually')
            : attr.source === 'document'
            ? t('personalData.fromDocument')
            : attr.source;

    // Every party that has asserted this value. More than one = confirmations
    // that strengthen the attribute (e.g. entered manually, confirmed by LinkedIn).
    const sources = attr.sources && attr.sources.length > 0 ? attr.sources : null;
    const confirmed = sources && sources.length > 1;

    const acquiredDate = attr.acquiredAt
        ? t('time.onDateLong', { when: new Date(attr.acquiredAt * 1000) })
        : null;

    const updatedDate = attr.updatedAt
        ? t('time.onDateLong', { when: new Date(attr.updatedAt * 1000) })
        : null;

    // Image attributes (everyday avatar + the gov ID portrait) render as a
    // picture, not editable text.
    const isImage = attr.key === 'picture' || attr.key === 'picture_id';

    const handleStartEdit = () => {
        if (isImage) return;
        if (attr.verified) {
            Alert.alert(
                t('personalData.editVerifiedTitle'),
                t('personalData.editVerifiedBody'),
                [
                    { text: t('common.cancel'), style: 'cancel' },
                    { text: t('personalData.editAnyway'), onPress: () => { setEditing(true); setEditValue(attr.value); } },
                ],
            );
        } else {
            setEditing(true);
            setEditValue(attr.value);
        }
    };

    const handleSaveEdit = () => {
        const trimmed = editValue.trim();
        if (trimmed && trimmed !== attr.value) {
            onEdit(trimmed);
        }
        setEditing(false);
    };

    const renderRightActions = () => (
        <Pressable style={styles.swipeDeleteAction} onPress={onRemove}>
            <Ionicons name="trash-outline" size={20} color="#FFFFFF" />
            <Text style={styles.swipeDeleteText}>{t('common.delete')}</Text>
        </Pressable>
    );

    // The whole row used to be the expand target, so a swipe that ended on it
    // also fired onPress: the card expanded to show its provenance rows
    // mid-gesture, and the delete action grew with it. Guarding the press on a
    // swipe-open flag was not enough, because the press can land before the
    // swipe is recognised as one.
    //
    // The chevron is the target now. A swipe cannot expand anything, so the
    // row height is fixed for the whole gesture and the action beside it
    // cannot follow it downwards.
    const toggleExpanded = () => {
        if (!editing) setExpanded((v) => !v);
    };

    return (
        <Swipeable renderRightActions={renderRightActions} overshootRight={false}>
            <RNView>
                <RNView style={styles.attributeRow}>
                    <RNView style={styles.attributeInfo}>
                        <Pressable
                            onPress={toggleExpanded}
                            disabled={editing}
                            hitSlop={10}
                            accessibilityRole="button"
                            accessibilityState={{ expanded }}
                            accessibilityLabel={attr.label}
                            style={{ flexDirection: 'row', alignItems: 'center', gap: 6, alignSelf: 'flex-start' }}
                        >
                            <Text style={styles.attributeLabel}>{attr.label}</Text>
                            {!editing && (
                                <Ionicons
                                    name={expanded ? 'chevron-up' : 'chevron-down'}
                                    size={12}
                                    color={p.textMuted}
                                />
                            )}
                        </Pressable>

                        {editing ? (
                            <RNView style={styles.inlineEditRow}>
                                <TextInput
                                    style={styles.inlineEditInput}
                                    value={editValue}
                                    onChangeText={setEditValue}
                                    autoFocus
                                    autoCapitalize={attr.key === 'email' ? 'none' : 'words'}
                                    keyboardType={attr.key === 'email' ? 'email-address' : attr.key === 'phone_number' ? 'phone-pad' : 'default'}
                                    onSubmitEditing={handleSaveEdit}
                                    returnKeyType="done"
                                />
                                <Pressable onPress={handleSaveEdit}>
                                    <Ionicons name="checkmark-circle" size={24} color={p.green} />
                                </Pressable>
                                <Pressable onPress={() => setEditing(false)}>
                                    <Ionicons name="close-circle" size={24} color={p.textMuted} />
                                </Pressable>
                            </RNView>
                        ) : isImage && attr.value ? (
                            <Image
                                source={{ uri: attr.value }}
                                style={styles.attributeAvatar}
                            />
                        ) : (
                            <RNView style={{ flexDirection: 'row', alignItems: 'center', gap: 6 }}>
                                <Text style={[styles.attributeValue, { flex: 1 }]} numberOfLines={2}>{attr.value}</Text>
                                {!isImage && (
                                    <Pressable onPress={handleStartEdit} hitSlop={8}>
                                        <Ionicons name="pencil-outline" size={16} color={p.textMuted} />
                                    </Pressable>
                                )}
                            </RNView>
                        )}
                        <RNView style={styles.attributeMeta}>
                            {attr.verified ? (
                                <RNView style={styles.verifiedBadge}>
                                    <Ionicons name="checkmark-circle" size={12} color={p.green} />
                                    <Text style={styles.verifiedText}>{t('personalData.verified')}</Text>
                                </RNView>
                            ) : (
                                <RNView style={styles.verifiedBadge}>
                                    <Ionicons name="alert-circle-outline" size={12} color={p.warnText} />
                                    <Text style={[styles.verifiedText, { color: p.warnText }]}>
                                        {t('personalData.unverified')}
                                    </Text>
                                </RNView>
                            )}
                            {confirmed ? (
                                <RNView style={styles.confirmBadge}>
                                    <Ionicons name="shield-checkmark" size={12} color={p.blue} />
                                    <Text style={styles.confirmText}>
                                        {t('personalData.confirmedBy', { count: sources!.length })}
                                    </Text>
                                </RNView>
                            ) : (
                                <Text style={styles.sourceText}>{sourceLabel}</Text>
                            )}
                        </RNView>

                        {expanded && (
                            <RNView style={styles.provenanceSection}>
                                {acquiredDate && (
                                    <RNView style={styles.provenanceRow}>
                                        <Text style={styles.provenanceLabel}>{t('personalData.acquired')}</Text>
                                        <Text style={styles.provenanceValue}>{acquiredDate}</Text>
                                    </RNView>
                                )}
                                {updatedDate && updatedDate !== acquiredDate && (
                                    <RNView style={styles.provenanceRow}>
                                        <Text style={styles.provenanceLabel}>{t('personalData.updated')}</Text>
                                        <Text style={styles.provenanceValue}>{updatedDate}</Text>
                                    </RNView>
                                )}
                                {sources && sources.length > 0 && (
                                    <>
                                        <Text style={[styles.provenanceLabel, { marginTop: 8, marginBottom: 4 }]}>
                                            {t('personalData.sources')}
                                        </Text>
                                        {sources.map((s, i) => (
                                            <RNView key={i} style={styles.provenanceRow}>
                                                <Text style={styles.provenanceValue}>{s.displayName}</Text>
                                                <Text style={styles.provenanceValue}>
                                                    {t('time.onDate', { when: new Date(s.addedAt * 1000) })}
                                                </Text>
                                            </RNView>
                                        ))}
                                    </>
                                )}
                                {(attr.verifications ?? []).length > 0 && (
                                    <>
                                        <Text style={[styles.provenanceLabel, { marginTop: 8, marginBottom: 4 }]}>
                                            {t('personalData.verificationRecords')}
                                        </Text>
                                        {attr.verifications!.map((v, i) => (
                                            <RNView key={i} style={styles.verificationCard}>
                                                <RNView style={styles.provenanceRow}>
                                                    <Text style={styles.provenanceLabel}>{t('personalData.verifier')}</Text>
                                                    <Text style={styles.provenanceValue}>
                                                        {v.verifierDisplayName}
                                                    </Text>
                                                </RNView>
                                                <RNView style={styles.provenanceRow}>
                                                    <Text style={styles.provenanceLabel}>{t('personalData.method')}</Text>
                                                    <Text style={styles.provenanceValue}>
                                                        {v.method.replace(/_/g, ' ')}
                                                    </Text>
                                                </RNView>
                                                <RNView style={styles.provenanceRow}>
                                                    <Text style={styles.provenanceLabel}>{t('personalData.verified')}</Text>
                                                    <Text style={styles.provenanceValue}>
                                                        {t('time.onDate', { when: new Date(v.verifiedAt * 1000) })}
                                                    </Text>
                                                </RNView>
                                            </RNView>
                                        ))}
                                    </>
                                )}
                            </RNView>
                        )}
                    </RNView>
                </RNView>
            </RNView>
        </Swipeable>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    header: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingHorizontal: 16,
        paddingBottom: 14,
        backgroundColor: p.green,
    },
    backButton: { width: 32, alignItems: 'flex-start' },
    headerTitle: {
        fontSize: 18,
        fontWeight: '700',
        color: '#FFFFFF',
        letterSpacing: -0.3,
    },
    scrollView: { flex: 1 },
    scrollContent: { padding: 20, paddingBottom: 40 },

    sectionDescription: {
        fontSize: 13,
        color: p.textMuted,
        marginBottom: 12,
        lineHeight: 18,
    },

    emptyCard: {
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 24,
        gap: 8,
    },
    emptyCardText: { fontSize: 14, color: p.textMuted, textAlign: 'center' },

    attributeRow: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 16,
        marginBottom: 8,
    },
    attributeInfo: { flex: 1 },
    attributeLabel: { fontSize: 12, fontWeight: '600', color: p.textMuted, marginBottom: 2 },
    attributeValue: { fontSize: 16, color: p.textPrimary, marginBottom: 4 },
    attributeAvatar: {
        width: 48,
        height: 48,
        borderRadius: 24,
        marginVertical: 4,
    },
    attributeMeta: { flexDirection: 'row', alignItems: 'center', gap: 8 },
    verifiedBadge: { flexDirection: 'row', alignItems: 'center', gap: 4 },
    verifiedText: { fontSize: 11, color: p.green, fontWeight: '600' },
    sourceText: { fontSize: 11, color: p.textMuted },
    confirmBadge: { flexDirection: 'row', alignItems: 'center', gap: 4 },
    confirmText: { fontSize: 11, color: p.blue, fontWeight: '600' },

    inlineEditRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 8,
        marginBottom: 4,
    },
    inlineEditInput: {
        flex: 1,
        backgroundColor: p.cardAlt,
        borderRadius: 8,
        paddingHorizontal: 12,
        paddingVertical: 8,
        fontSize: 16,
        color: p.textPrimary,
    },

    provenanceSection: {
        marginTop: 8,
        paddingTop: 8,
        borderTopWidth: 0.5,
        borderTopColor: p.cardAlt,
    },
    provenanceRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        paddingVertical: 3,
    },
    provenanceLabel: {
        fontSize: 11,
        fontWeight: '600',
        color: p.textMuted,
        textTransform: 'uppercase',
        letterSpacing: 0.3,
    },
    provenanceValue: {
        fontSize: 12,
        color: p.textSecondary,
    },
    verificationCard: {
        backgroundColor: p.screenBg,
        borderRadius: 8,
        padding: 8,
        marginBottom: 4,
    },

    // Add attribute
    addAttrChips: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        alignItems: 'center',
        gap: 8,
        marginTop: 4,
        marginBottom: 4,
    },
    addAttrHint: {
        fontSize: 13,
        color: p.textMuted,
        fontWeight: '500',
    },
    addAttrChip: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 4,
        backgroundColor: p.card,
        borderRadius: 20,
        paddingVertical: 6,
        paddingHorizontal: 12,
        borderWidth: 1,
        borderColor: p.border,
    },
    addAttrChipText: {
        fontSize: 13,
        color: p.blue,
        fontWeight: '500',
    },
    addAttrCard: {
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 16,
        marginBottom: 8,
    },
    addAttrLabel: {
        fontSize: 12,
        fontWeight: '600',
        color: p.textMuted,
        marginBottom: 8,
    },
    addAttrInput: {
        backgroundColor: p.cardAlt,
        borderRadius: 8,
        paddingHorizontal: 12,
        paddingVertical: 10,
        fontSize: 16,
        color: p.textPrimary,
        marginBottom: 12,
    },
    addAttrActions: {
        flexDirection: 'row',
        justifyContent: 'flex-end',
        alignItems: 'center',
        gap: 16,
    },
    addAttrCancel: {
        fontSize: 14,
        color: p.textMuted,
        fontWeight: '500',
    },
    addAttrSave: {
        backgroundColor: p.blue,
        borderRadius: 8,
        paddingVertical: 8,
        paddingHorizontal: 20,
    },
    addAttrSaveText: {
        color: '#FFFFFF',
        fontSize: 14,
        fontWeight: '600',
    },

    // Import from account
    importButton: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        backgroundColor: p.card,
        borderRadius: 12,
        borderWidth: 1,
        borderColor: p.blue,
        padding: 14,
        marginTop: 8,
    },
    importButtonText: {
        fontSize: 15,
        fontWeight: '600',
        color: p.blue,
    },
    importPickerCard: {
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 16,
        marginTop: 8,
    },
    importPickerTitle: {
        fontSize: 16,
        fontWeight: '700',
        color: p.textPrimary,
        marginBottom: 4,
    },
    importPickerSubtitle: {
        fontSize: 13,
        color: p.textMuted,
        marginBottom: 12,
        lineHeight: 18,
    },
    providerRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 14,
        backgroundColor: p.screenBg,
        borderRadius: 12,
        padding: 14,
        marginBottom: 8,
    },
    providerInfo: { flex: 1 },
    providerName: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
    importPickerCancel: {
        alignItems: 'center',
        paddingVertical: 10,
        marginTop: 4,
    },
    importPickerCancelText: {
        fontSize: 14,
        color: p.textMuted,
        fontWeight: '500',
    },

    swipeDeleteAction: {
        backgroundColor: p.danger,
        justifyContent: 'center',
        alignItems: 'center',
        width: 80,
        // Fixed height, aligned to the top of the row rather than stretched to
        // it. Delete is one button whatever the row happens to be showing; an
        // expanded attribute used to turn it into a full-height red panel.
        height: 64,
        alignSelf: 'flex-start',
        borderRadius: 12,
        marginLeft: 8,
    },
    swipeDeleteText: {
        color: '#FFFFFF',
        fontSize: 12,
        fontWeight: '600',
        marginTop: 4,
    },
});
