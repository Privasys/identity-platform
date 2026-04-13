// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Profile tab — view and manage identity, linked providers, and data attributes.
 */

import { Ionicons } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import { useRouter } from 'expo-router';
import { useState } from 'react';
import {
    StyleSheet,
    ScrollView,
    Pressable,
    View as RNView,
    TextInput,
    Alert,
    ActivityIndicator
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text } from '@/components/Themed';
import { generateDid, generatePairwiseSeed, generateCanonicalDid } from '@/services/did';
import { getClientId, linkIdentityProvider, PROVIDERS, type ProviderConfig } from '@/services/identity';
import { useConsentStore } from '@/stores/consent';
import { useProfileStore } from '@/stores/profile';

const PROVIDER_ICONS: Record<string, keyof typeof Ionicons.glyphMap> = {
    github: 'logo-github',
    google: 'logo-google',
    microsoft: 'logo-microsoft',
    linkedin: 'logo-linkedin'
};

export default function ProfileScreen() {
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const { profile, updateProfile, linkProvider, unlinkProvider, setAttribute, removeAttribute } =
        useProfileStore();
    const consentRecordCount = useConsentStore((s) => s.records.length);
    const standingConsentCount = useConsentStore((s) => s.standingConsents.length);

    const [editing, setEditing] = useState(false);
    const [editName, setEditName] = useState(profile?.displayName ?? '');
    const [editEmail, setEditEmail] = useState(profile?.email ?? '');
    const [linkingProvider, setLinkingProvider] = useState<string | null>(null);
    const [creatingProfile, setCreatingProfile] = useState(false);

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

    const handleSaveEdit = () => {
        updateProfile({ displayName: editName, email: editEmail });
        // Also update the corresponding attributes
        if (editName !== profile.displayName) {
            setAttribute({
                key: 'displayName',
                label: 'Display Name',
                value: editName,
                source: 'manual',
                verified: false
            });
        }
        if (editEmail !== profile.email) {
            setAttribute({
                key: 'email',
                label: 'Email',
                value: editEmail,
                source: 'manual',
                verified: false
            });
        }
        setEditing(false);
    };

    const handleLinkProvider = async (providerKey: string) => {
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
                }
            }
        } catch (e: any) {
            if (e.message !== 'Authentication cancelled') {
                Alert.alert('Link failed', e.message);
            }
        } finally {
            setLinkingProvider(null);
        }
    };

    const handleUnlinkProvider = (providerKey: string, displayName: string) => {
        Alert.alert(`Unlink ${displayName}?`, 'You can re-link at any time.', [
            { text: 'Cancel', style: 'cancel' },
            {
                text: 'Unlink',
                style: 'destructive',
                onPress: () => unlinkProvider(providerKey)
            }
        ]);
    };

    const handleCopyDid = () => {
        const didToCopy = profile.canonicalDid || profile.did;
        if (didToCopy) {
            Clipboard.setStringAsync(didToCopy);
            Alert.alert('Copied', 'DID copied to clipboard.');
        }
    };

    return (
        <RNView style={styles.screen}>
            {/* Header */}
            <RNView style={[styles.header, { paddingTop: insets.top + 16 }]}>
                <Text style={styles.headerTitle}>Profile</Text>
                <Pressable
                    onPress={editing ? handleSaveEdit : () => {
                        setEditName(profile.displayName);
                        setEditEmail(profile.email);
                        setEditing(true);
                    }}
                >
                    <Text style={styles.editButton}>{editing ? 'Save' : 'Edit'}</Text>
                </Pressable>
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

                    {editing ? (
                        <RNView style={styles.editFields}>
                            <TextInput
                                style={styles.editInput}
                                value={editName}
                                onChangeText={setEditName}
                                placeholder="Display Name"
                                placeholderTextColor="#94A3B8"
                            />
                            <TextInput
                                style={styles.editInput}
                                value={editEmail}
                                onChangeText={setEditEmail}
                                placeholder="Email"
                                placeholderTextColor="#94A3B8"
                                keyboardType="email-address"
                                autoCapitalize="none"
                            />
                        </RNView>
                    ) : (
                        <>
                            <Text style={styles.profileName}>{profile.displayName}</Text>
                            {profile.email ? (
                                <Text style={styles.profileEmail}>{profile.email}</Text>
                            ) : null}
                        </>
                    )}
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

                {/* Linked Providers */}
                <Text style={styles.sectionTitle}>LINKED ACCOUNTS</Text>
                <Text style={styles.sectionDescription}>
                    Used for profile information and account recovery. Not used for enclave authentication.
                </Text>

                {Object.entries(PROVIDERS).map(([key, config]) => {
                    const linked = profile.linkedProviders.find((p) => p.provider === key);
                    const isLinking = linkingProvider === key;
                    return (
                        <Pressable
                            key={key}
                            style={styles.providerRow}
                            onPress={() =>
                                linked
                                    ? handleUnlinkProvider(key, config.displayName)
                                    : handleLinkProvider(key)
                            }
                            disabled={isLinking}
                        >
                            <Ionicons
                                name={PROVIDER_ICONS[key] ?? 'globe-outline'}
                                size={22}
                                color={linked ? '#34E89E' : '#94A3B8'}
                            />
                            <RNView style={styles.providerInfo}>
                                <Text style={styles.providerName}>{config.displayName}</Text>
                                {linked ? (
                                    <Text style={styles.providerDetail}>
                                        {linked.email ?? linked.sub} · Linked{' '}
                                        {new Date(linked.linkedAt * 1000).toLocaleDateString()}
                                    </Text>
                                ) : (
                                    <Text style={styles.providerDetail}>Not linked</Text>
                                )}
                            </RNView>
                            {isLinking ? (
                                <ActivityIndicator size="small" color="#00BCF2" />
                            ) : (
                                <Ionicons
                                    name={linked ? 'close-circle-outline' : 'add-circle-outline'}
                                    size={22}
                                    color={linked ? '#FF3B30' : '#00BCF2'}
                                />
                            )}
                        </Pressable>
                    );
                })}

                {/* Data Attributes */}
                <Text style={styles.sectionTitle}>PERSONAL DATA</Text>
                <Text style={styles.sectionDescription}>
                    Attributes you can selectively share with attested enclaves.
                </Text>

                {profile.attributes.length === 0 ? (
                    <RNView style={styles.emptyCard}>
                        <Ionicons name="document-text-outline" size={32} color="#C7C7CC" />
                        <Text style={styles.emptyCardText}>
                            No data attributes yet. Link a provider or add manually.
                        </Text>
                    </RNView>
                ) : (
                    profile.attributes.map((attr) => (
                        <RNView key={attr.key} style={styles.attributeRow}>
                            <RNView style={styles.attributeInfo}>
                                <Text style={styles.attributeLabel}>{attr.label}</Text>
                                <Text style={styles.attributeValue}>{attr.value}</Text>
                                <RNView style={styles.attributeMeta}>
                                    {attr.verified && (
                                        <RNView style={styles.verifiedBadge}>
                                            <Ionicons
                                                name="checkmark-circle"
                                                size={12}
                                                color="#34E89E"
                                            />
                                            <Text style={styles.verifiedText}>Verified</Text>
                                        </RNView>
                                    )}
                                    {attr.sourceProvider && (
                                        <Text style={styles.sourceText}>
                                            via {attr.sourceProvider}
                                        </Text>
                                    )}
                                </RNView>
                            </RNView>
                            <Pressable
                                onPress={() => {
                                    Alert.alert(
                                        `Remove ${attr.label}?`,
                                        'This attribute will no longer be available for sharing.',
                                        [
                                            { text: 'Cancel', style: 'cancel' },
                                            {
                                                text: 'Remove',
                                                style: 'destructive',
                                                onPress: () => removeAttribute(attr.key)
                                            }
                                        ]
                                    );
                                }}
                            >
                                <Ionicons name="close-circle" size={20} color="#FF3B30" />
                            </Pressable>
                        </RNView>
                    ))
                )}

                {/* Data Sharing */}
                <Text style={styles.sectionTitle}>DATA SHARING</Text>
                <Text style={styles.sectionDescription}>
                    Review what you've shared and manage auto-share rules.
                </Text>

                <Pressable
                    style={styles.sharingCard}
                    onPress={() => router.push('/consent-history')}
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

                <Pressable
                    style={styles.sharingCard}
                    onPress={() => router.push('/consent-history')}
                >
                    <RNView style={styles.sharingRow}>
                        <RNView style={styles.sharingIconContainer}>
                            <Ionicons name="repeat-outline" size={20} color="#34E89E" />
                        </RNView>
                        <RNView style={{ flex: 1 }}>
                            <Text style={styles.sharingLabel}>Auto-share Rules</Text>
                            <Text style={styles.sharingDetail}>
                                {standingConsentCount === 0
                                    ? 'None active'
                                    : `${standingConsentCount} active rule${standingConsentCount !== 1 ? 's' : ''}`}
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
                        <Text style={styles.metaLabel}>Linked providers</Text>
                        <Text style={styles.metaValue}>{profile.linkedProviders.length}</Text>
                    </RNView>
                    <RNView style={styles.metaRow}>
                        <Text style={styles.metaLabel}>Data attributes</Text>
                        <Text style={styles.metaValue}>{profile.attributes.length}</Text>
                    </RNView>
                </RNView>
            </ScrollView>
        </RNView>
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
    editButton: {
        fontSize: 16,
        fontWeight: '600',
        color: '#00BCF2'
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
    avatarInitial: {
        fontSize: 32,
        fontWeight: '700',
        color: '#FFFFFF'
    },
    editFields: { width: '100%', gap: 8 },
    editInput: {
        backgroundColor: '#F1F5F9',
        borderRadius: 10,
        paddingHorizontal: 14,
        paddingVertical: 12,
        fontSize: 16,
        color: '#0F172A'
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
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 8
    },
    providerInfo: { flex: 1 },
    providerName: { fontSize: 16, fontWeight: '600', color: '#0F172A', marginBottom: 2 },
    providerDetail: { fontSize: 13, color: '#64748B' },

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
    attributeMeta: { flexDirection: 'row', alignItems: 'center', gap: 8 },
    verifiedBadge: { flexDirection: 'row', alignItems: 'center', gap: 4 },
    verifiedText: { fontSize: 11, color: '#34E89E', fontWeight: '600' },
    sourceText: { fontSize: 11, color: '#94A3B8' },

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
    sharingDetail: { fontSize: 13, color: '#64748B' }
});
