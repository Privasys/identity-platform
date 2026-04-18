// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Profile tab — view and manage identity, personal data, and consent history.
 */

import { Ionicons } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import { File, Paths } from 'expo-file-system';
import * as Sharing from 'expo-sharing';
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
import { CANONICAL_ATTRIBUTES, exportAttributesForAudit } from '@/services/attributes';
import { generateDid, generatePairwiseSeed, generateCanonicalDid } from '@/services/did';
import { getClientId, linkIdentityProvider, PROVIDERS, type ProviderConfig } from '@/services/identity';
import { useAuthStore } from '@/stores/auth';
import { useConsentStore } from '@/stores/consent';
import { useProfileStore, type ProfileAttribute } from '@/stores/profile';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

const PROVIDER_ICONS: Record<string, keyof typeof Ionicons.glyphMap> = {
    github: 'logo-github',
    google: 'logo-google',
    microsoft: 'logo-microsoft',
    linkedin: 'logo-linkedin'
};

export default function ProfileScreen() {
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const { profile, updateProfile, linkProvider, unlinkProvider, setAttribute, removeAttribute, clearProfile } =
        useProfileStore();
    const { credentials, removeCredential } = useAuthStore();
    const { apps, remove: removeTrustedApp } = useTrustedAppsStore();
    const consentRecordCount = useConsentStore((s) => s.records.length);

    const [linkingProvider, setLinkingProvider] = useState<string | null>(null);
    const [creatingProfile, setCreatingProfile] = useState(false);
    const [showImportPicker, setShowImportPicker] = useState(false);
    const [addingAttribute, setAddingAttribute] = useState<string | null>(null);
    const [newAttrValue, setNewAttrValue] = useState('');

    const handleCreateProfile = async () => {
        setCreatingProfile(true);
        try {
            const did = await generateDid();
            const pairwiseSeed = await generatePairwiseSeed();
            const canonicalDid = await generateCanonicalDid(pairwiseSeed);
            useProfileStore.getState().createProfile({
                displayName: 'Privasys User',
                email: '',
                avatarUri: '',
                locale: '',
                did,
                canonicalDid,
                pairwiseSeed,
                linkedProviders: [],
                attributes: []
            });
        } catch (e: any) {
            Alert.alert('Error', `Failed to create profile: ${e.message}`);
        } finally {
            setCreatingProfile(false);
        }
    };

    if (!profile) {
        return (
            <RNView style={[styles.screen, { paddingTop: insets.top }]}>
                <RNView style={styles.emptyState}>
                    <Ionicons name="person-circle-outline" size={64} color="#C7C7CC" />
                    <Text style={styles.emptyTitle}>No profile yet</Text>
                    <Text style={styles.emptyText}>
                        Set up your identity to manage your data, link accounts, and control what apps can see.
                    </Text>
                    <Pressable
                        style={styles.createProfileButton}
                        onPress={handleCreateProfile}
                        disabled={creatingProfile}
                    >
                        {creatingProfile ? (
                            <ActivityIndicator color="#FFFFFF" size="small" />
                        ) : (
                            <Text style={styles.createProfileButtonText}>Set Up Profile</Text>
                        )}
                    </Pressable>
                </RNView>
            </RNView>
        );
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
                    `OAuth client ID for ${providerTemplate.displayName} is not configured yet.`
                );
                return;
            }

            const config: ProviderConfig = { ...providerTemplate, clientId };
            const result = await linkIdentityProvider(config);

            linkProvider(result.provider);

            // Seed attributes that don't exist yet
            for (const attr of result.seedAttributes) {
                const existing = profile.attributes.find((a) => a.key === attr.key);
                if (!existing) {
                    setAttribute(attr);
                    // Sync top-level profile fields
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

    const handleCopyDid = () => {
        const didToCopy = profile.canonicalDid || profile.did;
        if (didToCopy) {
            Clipboard.setStringAsync(didToCopy);
            Alert.alert('Copied', 'DID copied to clipboard.');
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
                    }
                }
            ]
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

        // Sync top-level profile fields
        if (def.profileField === 'email') updateProfile({ email: newAttrValue.trim() });
        if (def.profileField === 'displayName') updateProfile({ displayName: newAttrValue.trim() });
        if (def.profileField === 'locale') updateProfile({ locale: newAttrValue.trim() });

        setAddingAttribute(null);
        setNewAttrValue('');
    };

    // Attributes that are in the canonical set but not yet in the profile
    const existingKeys = new Set(profile.attributes.map((a) => a.key));
    const missingAttributes = CANONICAL_ATTRIBUTES.filter(
        (a) => !existingKeys.has(a.key) && a.key !== 'picture',
    );

    return (
        <RNView style={styles.screen}>
            {/* Header */}
            <RNView style={[styles.header, { paddingTop: insets.top + 16 }]}>
                <Text style={styles.headerTitle}>Profile</Text>
            </RNView>

            <ScrollView
                style={styles.scrollView}
                contentContainerStyle={styles.scrollContent}
                showsVerticalScrollIndicator={false}
            >
                {/* Avatar + Name */}
                <RNView style={styles.profileCard}>
                    <RNView style={styles.avatarContainer}>
                        {profile.avatarUri ? (
                            <Image
                                source={{ uri: profile.avatarUri }}
                                style={styles.avatarImage}
                            />
                        ) : profile.displayName ? (
                            <RNView style={styles.avatar}>
                                <Text style={styles.avatarInitial}>
                                    {profile.displayName.charAt(0).toUpperCase()}
                                </Text>
                            </RNView>
                        ) : (
                            <RNView style={styles.avatar}>
                                <Ionicons name="person" size={36} color="#FFFFFF" />
                            </RNView>
                        )}
                    </RNView>
                    <Text style={styles.profileName}>{profile.displayName || 'Privasys User'}</Text>
                    {profile.email ? (
                        <Text style={styles.profileEmail}>{profile.email}</Text>
                    ) : null}
                </RNView>

                {/* DID */}
                <Text style={styles.sectionTitle}>IDENTITY</Text>
                <Pressable style={styles.didCard} onPress={handleCopyDid}>
                    <Ionicons name="finger-print" size={20} color="#00BCF2" />
                    <RNView style={{ flex: 1 }}>
                        <Text style={styles.didLabel}>Canonical DID</Text>
                        <Text style={styles.didText} numberOfLines={1}>
                            {profile.canonicalDid || 'Not generated'}
                        </Text>
                    </RNView>
                    <Ionicons name="copy-outline" size={18} color="#94A3B8" />
                </Pressable>
                <RNView style={styles.didCard}>
                    <Ionicons name="phone-portrait-outline" size={20} color="#64748B" />
                    <RNView style={{ flex: 1 }}>
                        <Text style={styles.didLabel}>Device DID</Text>
                        <Text style={styles.didText} numberOfLines={1}>
                            {profile.did || 'Not generated'}
                        </Text>
                    </RNView>
                </RNView>
                <Text style={styles.privacyNote}>
                    Apps receive a unique derived ID — they cannot track you across services.
                </Text>

                {/* Personal Data */}
                <Text style={styles.sectionTitle}>PERSONAL DATA</Text>
                <Text style={styles.sectionDescription}>
                    Attributes you can selectively share with services. Tap to expand, swipe to delete.
                </Text>

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

                {/* Export all data */}
                {profile.attributes.length > 0 && (
                    <Pressable
                        style={styles.exportButton}
                        onPress={async () => {
                            try {
                                const data = exportAttributesForAudit(profile);
                                const json = JSON.stringify(data, null, 2);
                                const file = new File(Paths.cache, `privasys-profile-${Date.now()}.json`);
                                file.write(json);
                                await Sharing.shareAsync(file.uri, {
                                    mimeType: 'application/json',
                                    dialogTitle: 'Save Profile Data',
                                    UTI: 'public.json',
                                });
                            } catch (e: any) {
                                Alert.alert('Export failed', e.message);
                            }
                        }}
                    >
                        <Ionicons name="download-outline" size={18} color="#00BCF2" />
                        <Text style={styles.exportButtonText}>Export All Data (JSON)</Text>
                    </Pressable>
                )}

                {/* Data Sharing */}
                <Text style={styles.sectionTitle}>DATA SHARING</Text>
                <Text style={styles.sectionDescription}>
                    Review what you've shared with services.
                </Text>

                <Pressable
                    style={styles.sharingCard}
                    onPress={() => router.push('/consent-history' as never)}
                >
                    <RNView style={styles.sharingRow}>
                        <RNView style={styles.sharingIconContainer}>
                            <Ionicons name="time-outline" size={20} color="#00BCF2" />
                        </RNView>
                        <RNView style={{ flex: 1 }}>
                            <Text style={styles.sharingLabel}>Consent History</Text>
                            <Text style={styles.sharingDetail}>
                                {consentRecordCount === 0
                                    ? 'No sharing events yet'
                                    : `${consentRecordCount} event${consentRecordCount !== 1 ? 's' : ''}`}
                            </Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color="#94A3B8" />
                    </RNView>
                </Pressable>

                {/* Profile metadata */}
                <Text style={styles.sectionTitle}>DETAILS</Text>
                <RNView style={styles.metaCard}>
                    <RNView style={styles.metaRow}>
                        <Text style={styles.metaLabel}>Created</Text>
                        <Text style={styles.metaValue}>
                            {new Date(profile.createdAt * 1000).toLocaleDateString()}
                        </Text>
                    </RNView>
                    <RNView style={styles.metaRow}>
                        <Text style={styles.metaLabel}>Last updated</Text>
                        <Text style={styles.metaValue}>
                            {new Date(profile.updatedAt * 1000).toLocaleDateString()}
                        </Text>
                    </RNView>
                    <RNView style={styles.metaRow}>
                        <Text style={styles.metaLabel}>Data attributes</Text>
                        <Text style={styles.metaValue}>{profile.attributes.length}</Text>
                    </RNView>
                </RNView>

                {/* Danger Zone */}
                <RNView style={styles.dangerSection}>
                    <RNView style={styles.dangerDivider} />
                    <Text style={styles.dangerTitle}>Danger Zone</Text>
                    <Text style={styles.dangerDescription}>
                        This will remove your profile, credentials, trusted apps, and all local data.
                        You will need to re-register with each service.
                    </Text>
                    <Pressable
                        style={styles.dangerButton}
                        onPress={() => {
                            Alert.alert(
                                'Clear All Data',
                                'This will permanently remove your profile, all credentials, trusted apps, and local data. This cannot be undone.',
                                [
                                    { text: 'Cancel', style: 'cancel' },
                                    {
                                        text: 'Clear Everything',
                                        style: 'destructive',
                                        onPress: () => {
                                            for (const cred of credentials) {
                                                removeCredential(cred.credentialId);
                                            }
                                            for (const app of apps) {
                                                removeTrustedApp(app.rpId);
                                            }
                                            clearProfile();
                                        }
                                    }
                                ]
                            );
                        }}
                    >
                        <Ionicons name="trash-outline" size={18} color="#DC2626" />
                        <Text style={styles.dangerButtonText}>Clear All Data</Text>
                    </Pressable>
                </RNView>
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
                ]
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
        <Pressable
            style={styles.swipeDeleteAction}
            onPress={onRemove}
        >
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
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingHorizontal: 20,
        paddingBottom: 16,
        backgroundColor: '#0F172A'
    },
    headerTitle: {
        fontSize: 28,
        fontWeight: '700',
        color: '#FFFFFF',
        letterSpacing: -0.5
    },
    scrollView: { flex: 1 },
    scrollContent: { padding: 20, paddingBottom: 40 },
    emptyState: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        gap: 12,
        paddingHorizontal: 40
    },
    emptyTitle: { fontSize: 20, fontWeight: '600', color: '#0F172A' },
    emptyText: { fontSize: 15, color: '#64748B', textAlign: 'center', lineHeight: 22 },
    createProfileButton: {
        backgroundColor: '#00BCF2',
        borderRadius: 12,
        paddingVertical: 14,
        paddingHorizontal: 32,
        marginTop: 8,
        alignItems: 'center' as const,
        minWidth: 180
    },
    createProfileButtonText: {
        color: '#FFFFFF',
        fontSize: 16,
        fontWeight: '600' as const
    },

    profileCard: {
        alignItems: 'center',
        backgroundColor: '#FFFFFF',
        borderRadius: 16,
        padding: 24,
        marginBottom: 24
    },
    avatarContainer: { marginBottom: 16 },
    avatar: {
        width: 80,
        height: 80,
        borderRadius: 40,
        backgroundColor: '#00BCF2',
        alignItems: 'center',
        justifyContent: 'center'
    },
    avatarImage: {
        width: 80,
        height: 80,
        borderRadius: 40,
    },
    avatarInitial: {
        fontSize: 32,
        fontWeight: '700',
        color: '#FFFFFF'
    },
    profileName: { fontSize: 22, fontWeight: '700', color: '#0F172A', marginBottom: 4 },
    profileEmail: { fontSize: 15, color: '#64748B' },

    sectionTitle: {
        fontSize: 12,
        fontWeight: '700',
        color: '#94A3B8',
        letterSpacing: 0.8,
        marginTop: 24,
        marginBottom: 8
    },
    sectionDescription: {
        fontSize: 13,
        color: '#94A3B8',
        marginBottom: 12,
        lineHeight: 18
    },

    didCard: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 10,
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 14,
        marginBottom: 8
    },
    didLabel: {
        fontSize: 11,
        fontWeight: '600',
        color: '#94A3B8',
        textTransform: 'uppercase',
        letterSpacing: 0.5,
        marginBottom: 2
    },
    didText: {
        fontSize: 12,
        fontFamily: 'Inter',
        color: '#64748B',
        lineHeight: 18
    },
    privacyNote: {
        fontSize: 12,
        color: '#34C17B',
        marginTop: 4,
        marginBottom: 8,
        lineHeight: 16
    },

    providerRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 14,
        backgroundColor: '#F8FAFB',
        borderRadius: 12,
        padding: 14,
        marginBottom: 8
    },
    providerInfo: { flex: 1 },
    providerName: { fontSize: 15, fontWeight: '600', color: '#0F172A' },

    emptyCard: {
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 24,
        gap: 8
    },
    emptyCardText: { fontSize: 14, color: '#C7C7CC', textAlign: 'center' },

    attributeRow: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 8
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

    exportButton: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        borderWidth: 1,
        borderColor: '#E2E8F0',
        padding: 14,
        marginTop: 8,
    },
    exportButtonText: {
        fontSize: 15,
        fontWeight: '600',
        color: '#00BCF2',
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

    metaCard: {
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16
    },
    metaRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        paddingVertical: 8,
        borderBottomWidth: 0.5,
        borderBottomColor: '#F1F5F9'
    },
    metaLabel: { fontSize: 14, color: '#64748B' },
    metaValue: { fontSize: 14, fontWeight: '500', color: '#0F172A' },

    sharingCard: {
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 8
    },
    sharingRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 14
    },
    sharingIconContainer: {
        width: 36,
        height: 36,
        borderRadius: 10,
        backgroundColor: '#F1F5F9',
        alignItems: 'center',
        justifyContent: 'center'
    },
    sharingLabel: { fontSize: 15, fontWeight: '600', color: '#0F172A', marginBottom: 2 },
    sharingDetail: { fontSize: 13, color: '#64748B' },

    dangerSection: {
        marginTop: 40,
        alignItems: 'center',
        gap: 10,
        paddingBottom: 20,
    },
    dangerDivider: {
        width: 40,
        height: 1,
        backgroundColor: '#E2E8F0',
        marginBottom: 4,
    },
    dangerTitle: {
        fontSize: 12,
        fontWeight: '600',
        color: '#94A3B8',
        textTransform: 'uppercase',
        letterSpacing: 0.5,
    },
    dangerDescription: {
        fontSize: 13,
        color: '#94A3B8',
        textAlign: 'center',
        lineHeight: 18,
        maxWidth: 280,
        marginBottom: 4,
    },
    dangerButton: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 8,
        borderRadius: 10,
        paddingVertical: 12,
        paddingHorizontal: 24,
        borderWidth: 1,
        borderColor: '#E2E8F0',
    },
    dangerButtonText: { color: '#DC2626', fontSize: 14, fontWeight: '500' },

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
