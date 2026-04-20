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
    Alert,
    ActivityIndicator,
    Image,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text } from '@/components/Themed';
import { exportAttributesForAudit } from '@/services/attributes';
import { generateDid, generatePairwiseSeed, generateCanonicalDid } from '@/services/did';
import { useAuthStore } from '@/stores/auth';
import { useConsentStore } from '@/stores/consent';
import { useProfileStore } from '@/stores/profile';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

export default function ProfileScreen() {
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const { profile, updateProfile, clearProfile } =
        useProfileStore();
    const { credentials, removeCredential } = useAuthStore();
    const { apps, remove: removeTrustedApp } = useTrustedAppsStore();
    const consentRecordCount = useConsentStore((s) => s.records.length);

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
                    <Pressable
                        style={styles.recoverButton}
                        onPress={() => router.push('/recover-account' as never)}
                    >
                        <Ionicons name="key-outline" size={16} color="#00BCF2" />
                        <Text style={styles.recoverButtonText}>Recover Existing Account</Text>
                    </Pressable>
                </RNView>
            </RNView>
        );
    }

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
                    Manage your identity attributes and import data from external accounts.
                </Text>

                <Pressable
                    style={styles.sharingCard}
                    onPress={() => router.push('/personal-data' as never)}
                >
                    <RNView style={styles.sharingRow}>
                        <RNView style={styles.sharingIconContainer}>
                            <Ionicons name="document-text-outline" size={20} color="#00BCF2" />
                        </RNView>
                        <RNView style={{ flex: 1 }}>
                            <Text style={styles.sharingLabel}>Manage Attributes</Text>
                            <Text style={styles.sharingDetail}>
                                {profile.attributes.length === 0
                                    ? 'No attributes yet'
                                    : `${profile.attributes.length} attribute${profile.attributes.length !== 1 ? 's' : ''}`}
                            </Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color="#94A3B8" />
                    </RNView>
                </Pressable>

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

                {/* Account Recovery */}
                <Text style={styles.sectionTitle}>ACCOUNT RECOVERY</Text>
                <Text style={styles.sectionDescription}>
                    Set up recovery options in case you lose access to your device.
                </Text>

                <Pressable
                    style={styles.sharingCard}
                    onPress={() => router.push('/account-recovery' as never)}
                >
                    <RNView style={styles.sharingRow}>
                        <RNView style={styles.sharingIconContainer}>
                            <Ionicons name="shield-checkmark-outline" size={20} color="#00BCF2" />
                        </RNView>
                        <RNView style={{ flex: 1 }}>
                            <Text style={styles.sharingLabel}>Recovery Settings</Text>
                            <Text style={styles.sharingDetail}>
                                Backup codes, guardians & devices
                            </Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color="#94A3B8" />
                    </RNView>
                </Pressable>

                <Pressable
                    style={styles.sharingCard}
                    onPress={() => router.push('/recover-account' as never)}
                >
                    <RNView style={styles.sharingRow}>
                        <RNView style={styles.sharingIconContainer}>
                            <Ionicons name="key-outline" size={20} color="#F59E0B" />
                        </RNView>
                        <RNView style={{ flex: 1 }}>
                            <Text style={styles.sharingLabel}>Recover Account</Text>
                            <Text style={styles.sharingDetail}>
                                Lost access? Start recovery here
                            </Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color="#94A3B8" />
                    </RNView>
                </Pressable>

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
    recoverButton: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 6,
        paddingVertical: 10,
        marginTop: 4,
    },
    recoverButtonText: {
        color: '#00BCF2',
        fontSize: 14,
        fontWeight: '500',
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
});
