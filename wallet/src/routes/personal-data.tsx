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
import { useState } from 'react';
import {
    StyleSheet,
    ScrollView,
    Pressable,
    View as RNView,
    TextInput,
    Alert,
    ActivityIndicator,
    Image,
} from 'react-native';
import { Swipeable } from 'react-native-gesture-handler';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text } from '@/components/Themed';
import { CANONICAL_ATTRIBUTES } from '@/services/attributes';
import { getClientId, linkIdentityProvider, PROVIDERS, type ProviderConfig } from '@/services/identity';
import { useProfileStore, type ProfileAttribute } from '@/stores/profile';

const PROVIDER_ICONS: Record<string, keyof typeof Ionicons.glyphMap> = {
    github: 'logo-github',
    google: 'logo-google',
    microsoft: 'logo-microsoft',
    linkedin: 'logo-linkedin',
};

export default function PersonalDataScreen() {
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const { profile, updateProfile, linkProvider, setAttribute, removeAttribute } = useProfileStore();

    const [linkingProvider, setLinkingProvider] = useState<string | null>(null);
    const [showImportPicker, setShowImportPicker] = useState(false);
    const [addingAttribute, setAddingAttribute] = useState<string | null>(null);
    const [newAttrValue, setNewAttrValue] = useState('');

    if (!profile) {
        router.back();
        return null;
    }

    const handleImportFromProvider = async (providerKey: string) => {
        setLinkingProvider(providerKey);
        try {
            const providerTemplate = PROVIDERS[providerKey];
            if (!providerTemplate) throw new Error(`Unknown provider: ${providerKey}`);

            const clientId = getClientId(providerKey);
            if (!clientId) {
                Alert.alert(
                    'Not configured',
                    `OAuth client ID for ${providerTemplate.displayName} is not configured yet.`,
                );
                return;
            }

            const config: ProviderConfig = { ...providerTemplate, clientId };
            const result = await linkIdentityProvider(config);

            linkProvider(result.provider);

            for (const attr of result.seedAttributes) {
                const existing = profile.attributes.find((a) => a.key === attr.key);
                if (!existing) {
                    setAttribute(attr);
                    if (attr.key === 'email' && attr.value) updateProfile({ email: attr.value });
                    if (attr.key === 'name' && attr.value) updateProfile({ displayName: attr.value });
                    if (attr.key === 'picture' && attr.value) updateProfile({ avatarUri: attr.value });
                    if (attr.key === 'locale' && attr.value) updateProfile({ locale: attr.value });
                }
            }

            setShowImportPicker(false);
        } catch (e: any) {
            if (e.message !== 'Authentication cancelled') {
                Alert.alert('Import failed', e.message);
            }
        } finally {
            setLinkingProvider(null);
        }
    };

    const handleRemoveAttribute = (attr: ProfileAttribute) => {
        Alert.alert(
            `Remove ${attr.label}?`,
            'This attribute will no longer be available for sharing.',
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Remove',
                    style: 'destructive',
                    onPress: () => {
                        removeAttribute(attr.key);
                        if (attr.key === 'email') updateProfile({ email: '' });
                        if (attr.key === 'name') updateProfile({ displayName: '' });
                        if (attr.key === 'picture') updateProfile({ avatarUri: '' });
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
    const missingAttributes = CANONICAL_ATTRIBUTES.filter(
        (a) => !existingKeys.has(a.key) && a.key !== 'picture',
    );

    return (
        <RNView style={styles.screen}>
            {/* Header */}
            <RNView style={[styles.header, { paddingTop: insets.top + 8 }]}>
                <Pressable onPress={() => router.back()} hitSlop={12} style={styles.backButton}>
                    <Ionicons name="chevron-back" size={24} color="#FFFFFF" />
                </Pressable>
                <Text style={styles.headerTitle}>Personal Data</Text>
                <RNView style={{ width: 32 }} />
            </RNView>

            <ScrollView
                style={styles.scrollView}
                contentContainerStyle={styles.scrollContent}
                showsVerticalScrollIndicator={false}
            >
                <Text style={styles.sectionDescription}>
                    Attributes you can selectively share with services. Tap to expand, swipe to delete.
                </Text>

                {/* Attribute cards */}
                {profile.attributes.length === 0 ? (
                    <RNView style={styles.emptyCard}>
                        <Ionicons name="document-text-outline" size={32} color="#C7C7CC" />
                        <Text style={styles.emptyCardText}>
                            No attributes yet. Import from an account or add manually.
                        </Text>
                    </RNView>
                ) : (
                    profile.attributes.map((attr) => (
                        <AttributeCard
                            key={attr.key}
                            attr={attr}
                            onRemove={() => handleRemoveAttribute(attr)}
                            onEdit={(newValue) => {
                                const now = Math.floor(Date.now() / 1000);
                                setAttribute({
                                    ...attr,
                                    value: newValue,
                                    source: 'manual',
                                    updatedAt: now,
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
                            placeholder="Enter value..."
                            placeholderTextColor="#94A3B8"
                            autoFocus
                            autoCapitalize={addingAttribute === 'email' ? 'none' : 'words'}
                            keyboardType={addingAttribute === 'email' ? 'email-address' : addingAttribute === 'phone_number' ? 'phone-pad' : 'default'}
                        />
                        <RNView style={styles.addAttrActions}>
                            <Pressable onPress={() => setAddingAttribute(null)}>
                                <Text style={styles.addAttrCancel}>Cancel</Text>
                            </Pressable>
                            <Pressable
                                style={[styles.addAttrSave, !newAttrValue.trim() && { opacity: 0.4 }]}
                                onPress={handleSaveNewAttribute}
                                disabled={!newAttrValue.trim()}
                            >
                                <Text style={styles.addAttrSaveText}>Save</Text>
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
                                <Ionicons name="add" size={14} color="#00BCF2" />
                                <Text style={styles.addAttrChipText}>{def.label}</Text>
                            </Pressable>
                        ))}
                    </RNView>
                ) : null}

                {/* Import from account */}
                {showImportPicker ? (
                    <RNView style={styles.importPickerCard}>
                        <Text style={styles.importPickerTitle}>Import from</Text>
                        <Text style={styles.importPickerSubtitle}>
                            Sign in once to fill your profile. The provider cannot access your Privasys data.
                        </Text>
                        {Object.entries(PROVIDERS).map(([key, config]) => {
                            const isLinking = linkingProvider === key;
                            return (
                                <Pressable
                                    key={key}
                                    style={styles.providerRow}
                                    onPress={() => handleImportFromProvider(key)}
                                    disabled={isLinking}
                                >
                                    <Ionicons
                                        name={PROVIDER_ICONS[key] ?? 'globe-outline'}
                                        size={22}
                                        color="#64748B"
                                    />
                                    <RNView style={styles.providerInfo}>
                                        <Text style={styles.providerName}>{config.displayName}</Text>
                                    </RNView>
                                    {isLinking ? (
                                        <ActivityIndicator size="small" color="#00BCF2" />
                                    ) : (
                                        <Ionicons name="chevron-forward" size={18} color="#94A3B8" />
                                    )}
                                </Pressable>
                            );
                        })}
                        <Pressable
                            style={styles.importPickerCancel}
                            onPress={() => setShowImportPicker(false)}
                        >
                            <Text style={styles.importPickerCancelText}>Cancel</Text>
                        </Pressable>
                    </RNView>
                ) : (
                    <Pressable
                        style={styles.importButton}
                        onPress={() => setShowImportPicker(true)}
                    >
                        <Ionicons name="cloud-download-outline" size={18} color="#00BCF2" />
                        <Text style={styles.importButtonText}>Import from an account</Text>
                    </Pressable>
                )}

                <RNView style={{ height: 40 }} />
            </ScrollView>
        </RNView>
    );
}

// ── Attribute card with provenance details ──────────────────────────────

function AttributeCard({ attr, onRemove, onEdit }: { attr: ProfileAttribute; onRemove: () => void; onEdit: (newValue: string) => void }) {
    const [expanded, setExpanded] = useState(false);
    const [editing, setEditing] = useState(false);
    const [editValue, setEditValue] = useState(attr.value);

    const sourceLabel =
        attr.source === 'provider' && attr.sourceProvider
            ? `via ${attr.sourceProvider}`
            : attr.source === 'manual'
            ? 'entered manually'
            : attr.source === 'document'
            ? 'from document'
            : attr.source;

    const acquiredDate = attr.acquiredAt
        ? new Date(attr.acquiredAt * 1000).toLocaleDateString(undefined, {
              year: 'numeric',
              month: 'short',
              day: 'numeric',
          })
        : null;

    const updatedDate = attr.updatedAt
        ? new Date(attr.updatedAt * 1000).toLocaleDateString(undefined, {
              year: 'numeric',
              month: 'short',
              day: 'numeric',
          })
        : null;

    const isAvatar = attr.key === 'picture';

    const handleStartEdit = () => {
        if (isAvatar) return;
        if (attr.verified) {
            Alert.alert(
                'Edit verified attribute?',
                'This attribute has been verified. Editing it will remove the verification status.',
                [
                    { text: 'Cancel', style: 'cancel' },
                    { text: 'Edit Anyway', onPress: () => { setEditing(true); setEditValue(attr.value); } },
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
            <Text style={styles.swipeDeleteText}>Delete</Text>
        </Pressable>
    );

    return (
        <Swipeable renderRightActions={renderRightActions} overshootRight={false}>
            <Pressable onPress={() => !editing && setExpanded(!expanded)}>
                <RNView style={styles.attributeRow}>
                    <RNView style={styles.attributeInfo}>
                        <RNView style={{ flexDirection: 'row', alignItems: 'center', gap: 6 }}>
                            <Text style={styles.attributeLabel}>{attr.label}</Text>
                            {!editing && (
                                expanded ? (
                                    <Ionicons name="chevron-up" size={12} color="#94A3B8" />
                                ) : (
                                    <Ionicons name="chevron-down" size={12} color="#94A3B8" />
                                )
                            )}
                        </RNView>

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
                                    <Ionicons name="checkmark-circle" size={24} color="#34E89E" />
                                </Pressable>
                                <Pressable onPress={() => setEditing(false)}>
                                    <Ionicons name="close-circle" size={24} color="#94A3B8" />
                                </Pressable>
                            </RNView>
                        ) : isAvatar && attr.value ? (
                            <Image
                                source={{ uri: attr.value }}
                                style={styles.attributeAvatar}
                            />
                        ) : (
                            <RNView style={{ flexDirection: 'row', alignItems: 'center', gap: 6 }}>
                                <Text style={[styles.attributeValue, { flex: 1 }]}>{attr.value}</Text>
                                {!isAvatar && (
                                    <Pressable onPress={handleStartEdit} hitSlop={8}>
                                        <Ionicons name="pencil-outline" size={16} color="#94A3B8" />
                                    </Pressable>
                                )}
                            </RNView>
                        )}
                        <RNView style={styles.attributeMeta}>
                            {attr.verified ? (
                                <RNView style={styles.verifiedBadge}>
                                    <Ionicons name="checkmark-circle" size={12} color="#34E89E" />
                                    <Text style={styles.verifiedText}>Verified</Text>
                                </RNView>
                            ) : (
                                <RNView style={styles.verifiedBadge}>
                                    <Ionicons name="alert-circle-outline" size={12} color="#F59E0B" />
                                    <Text style={[styles.verifiedText, { color: '#F59E0B' }]}>Unverified</Text>
                                </RNView>
                            )}
                            <Text style={styles.sourceText}>{sourceLabel}</Text>
                        </RNView>

                        {expanded && (
                            <RNView style={styles.provenanceSection}>
                                {acquiredDate && (
                                    <RNView style={styles.provenanceRow}>
                                        <Text style={styles.provenanceLabel}>Acquired</Text>
                                        <Text style={styles.provenanceValue}>{acquiredDate}</Text>
                                    </RNView>
                                )}
                                {updatedDate && updatedDate !== acquiredDate && (
                                    <RNView style={styles.provenanceRow}>
                                        <Text style={styles.provenanceLabel}>Updated</Text>
                                        <Text style={styles.provenanceValue}>{updatedDate}</Text>
                                    </RNView>
                                )}
                                {(attr.verifications ?? []).length > 0 && (
                                    <>
                                        <Text style={[styles.provenanceLabel, { marginTop: 8, marginBottom: 4 }]}>
                                            Verification Records
                                        </Text>
                                        {attr.verifications!.map((v, i) => (
                                            <RNView key={i} style={styles.verificationCard}>
                                                <RNView style={styles.provenanceRow}>
                                                    <Text style={styles.provenanceLabel}>Verifier</Text>
                                                    <Text style={styles.provenanceValue}>
                                                        {v.verifierDisplayName}
                                                    </Text>
                                                </RNView>
                                                <RNView style={styles.provenanceRow}>
                                                    <Text style={styles.provenanceLabel}>Method</Text>
                                                    <Text style={styles.provenanceValue}>
                                                        {v.method.replace(/_/g, ' ')}
                                                    </Text>
                                                </RNView>
                                                <RNView style={styles.provenanceRow}>
                                                    <Text style={styles.provenanceLabel}>Verified</Text>
                                                    <Text style={styles.provenanceValue}>
                                                        {new Date(v.verifiedAt * 1000).toLocaleDateString()}
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
            </Pressable>
        </Swipeable>
    );
}

const styles = StyleSheet.create({
    screen: { flex: 1, backgroundColor: '#F8FAFB' },
    header: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingHorizontal: 16,
        paddingBottom: 14,
        backgroundColor: '#0F172A',
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
        color: '#94A3B8',
        marginBottom: 12,
        lineHeight: 18,
    },

    emptyCard: {
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 24,
        gap: 8,
    },
    emptyCardText: { fontSize: 14, color: '#C7C7CC', textAlign: 'center' },

    attributeRow: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 8,
    },
    attributeInfo: { flex: 1 },
    attributeLabel: { fontSize: 12, fontWeight: '600', color: '#94A3B8', marginBottom: 2 },
    attributeValue: { fontSize: 16, color: '#0F172A', marginBottom: 4 },
    attributeAvatar: {
        width: 48,
        height: 48,
        borderRadius: 24,
        marginVertical: 4,
    },
    attributeMeta: { flexDirection: 'row', alignItems: 'center', gap: 8 },
    verifiedBadge: { flexDirection: 'row', alignItems: 'center', gap: 4 },
    verifiedText: { fontSize: 11, color: '#34E89E', fontWeight: '600' },
    sourceText: { fontSize: 11, color: '#94A3B8' },

    inlineEditRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 8,
        marginBottom: 4,
    },
    inlineEditInput: {
        flex: 1,
        backgroundColor: '#F1F5F9',
        borderRadius: 8,
        paddingHorizontal: 12,
        paddingVertical: 8,
        fontSize: 16,
        color: '#0F172A',
    },

    provenanceSection: {
        marginTop: 8,
        paddingTop: 8,
        borderTopWidth: 0.5,
        borderTopColor: '#F1F5F9',
    },
    provenanceRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        paddingVertical: 3,
    },
    provenanceLabel: {
        fontSize: 11,
        fontWeight: '600',
        color: '#94A3B8',
        textTransform: 'uppercase',
        letterSpacing: 0.3,
    },
    provenanceValue: {
        fontSize: 12,
        color: '#64748B',
    },
    verificationCard: {
        backgroundColor: '#F8FAFB',
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
        color: '#94A3B8',
        fontWeight: '500',
    },
    addAttrChip: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 4,
        backgroundColor: '#FFFFFF',
        borderRadius: 20,
        paddingVertical: 6,
        paddingHorizontal: 12,
        borderWidth: 1,
        borderColor: '#E2E8F0',
    },
    addAttrChipText: {
        fontSize: 13,
        color: '#00BCF2',
        fontWeight: '500',
    },
    addAttrCard: {
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 8,
    },
    addAttrLabel: {
        fontSize: 12,
        fontWeight: '600',
        color: '#94A3B8',
        marginBottom: 8,
    },
    addAttrInput: {
        backgroundColor: '#F1F5F9',
        borderRadius: 8,
        paddingHorizontal: 12,
        paddingVertical: 10,
        fontSize: 16,
        color: '#0F172A',
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
        color: '#94A3B8',
        fontWeight: '500',
    },
    addAttrSave: {
        backgroundColor: '#00BCF2',
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
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        borderWidth: 1,
        borderColor: '#00BCF2',
        padding: 14,
        marginTop: 8,
    },
    importButtonText: {
        fontSize: 15,
        fontWeight: '600',
        color: '#00BCF2',
    },
    importPickerCard: {
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginTop: 8,
    },
    importPickerTitle: {
        fontSize: 16,
        fontWeight: '700',
        color: '#0F172A',
        marginBottom: 4,
    },
    importPickerSubtitle: {
        fontSize: 13,
        color: '#94A3B8',
        marginBottom: 12,
        lineHeight: 18,
    },
    providerRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 14,
        backgroundColor: '#F8FAFB',
        borderRadius: 12,
        padding: 14,
        marginBottom: 8,
    },
    providerInfo: { flex: 1 },
    providerName: { fontSize: 15, fontWeight: '600', color: '#0F172A' },
    importPickerCancel: {
        alignItems: 'center',
        paddingVertical: 10,
        marginTop: 4,
    },
    importPickerCancelText: {
        fontSize: 14,
        color: '#94A3B8',
        fontWeight: '500',
    },

    swipeDeleteAction: {
        backgroundColor: '#FF3B30',
        justifyContent: 'center',
        alignItems: 'center',
        width: 80,
        borderRadius: 12,
        marginBottom: 8,
        marginLeft: 8,
    },
    swipeDeleteText: {
        color: '#FFFFFF',
        fontSize: 12,
        fontWeight: '600',
        marginTop: 4,
    },
});
