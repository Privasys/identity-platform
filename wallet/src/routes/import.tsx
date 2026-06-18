// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Import Data sub-page. Government-verified import (scan an ID document in the
 * enclave-backed KYC flow) is the first, highest-assurance option; below it,
 * link an external IdP (Google / LinkedIn / Microsoft / GitHub) and choose
 * which returned attributes to import.
 */

import { Ionicons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';
import { useState } from 'react';
import { ActivityIndicator, Alert, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';

import { ConflictResolutionSheet, type AttributeConflict } from '@/components/ConflictResolutionSheet';
import { ImportSelectionSheet } from '@/components/ImportSelectionSheet';
import { SubPageHeader } from '@/components/SubPageHeader';
import { Text } from '@/components/Themed';
import { ATTRIBUTE_MAP } from '@/services/attributes';
import { linkProviderViaIdP, PROVIDERS } from '@/services/identity';
import { useProfileStore, type LinkedProvider, type ProfileAttribute } from '@/stores/profile';

const PROVIDER_ICONS: Record<string, keyof typeof Ionicons.glyphMap> = {
    github: 'logo-github',
    google: 'logo-google',
    microsoft: 'logo-microsoft',
    linkedin: 'logo-linkedin',
};

export default function ImportDataScreen() {
    const router = useRouter();
    const { profile, updateProfile, linkProvider, mergeAttribute, resolveConflict } = useProfileStore();

    const [linkingProvider, setLinkingProvider] = useState<string | null>(null);
    const [pendingImport, setPendingImport] = useState<{ linked: LinkedProvider; attributes: ProfileAttribute[] } | null>(null);
    const [importSelected, setImportSelected] = useState<Set<string>>(new Set());
    const [conflicts, setConflicts] = useState<AttributeConflict[]>([]);
    const [conflictIndex, setConflictIndex] = useState(0);
    const [tally, setTally] = useState({ added: 0, strengthened: 0, kept: 0 });

    const startImport = async (providerKey: string) => {
        setLinkingProvider(providerKey);
        try {
            const result = await linkProviderViaIdP(providerKey);
            if (result.seedAttributes.length === 0) {
                linkProvider(result.provider);
                return;
            }
            setPendingImport({ linked: result.provider, attributes: result.seedAttributes });
            setImportSelected(new Set(result.seedAttributes.map((a) => a.key)));
        } catch (e: any) {
            if (e.message !== 'Authentication cancelled') Alert.alert('Import failed', e.message);
        } finally {
            setLinkingProvider(null);
        }
    };

    const toggleImport = (key: string) =>
        setImportSelected((prev) => {
            const next = new Set(prev);
            if (next.has(key)) next.delete(key);
            else next.add(key);
            return next;
        });

    // Mirror the primary value of the canonical attributes that also live as
    // top-level profile fields, so the rest of the app stays in sync.
    const syncTopLevel = (attr: ProfileAttribute) => {
        if (attr.key === 'email' && attr.value) updateProfile({ email: attr.value });
        if (attr.key === 'name' && attr.value) updateProfile({ displayName: attr.value });
        if (attr.key === 'picture' && attr.value) updateProfile({ avatarUri: attr.value });
        if (attr.key === 'locale' && attr.value) updateProfile({ locale: attr.value });
    };

    const finish = (t: { added: number; strengthened: number; kept: number }) => {
        setPendingImport(null);
        setConflicts([]);
        setConflictIndex(0);
        const parts: string[] = [];
        if (t.added) parts.push(`${t.added} added`);
        if (t.strengthened) parts.push(`${t.strengthened} confirmed`);
        if (t.kept) parts.push(`${t.kept} kept`);
        Alert.alert('Import complete', parts.length ? parts.join(', ') + '.' : 'No changes.');
    };

    const applyImport = () => {
        if (!pendingImport || !profile) return;
        linkProvider(pendingImport.linked);
        let added = 0;
        let strengthened = 0;
        const pending: AttributeConflict[] = [];
        for (const attr of pendingImport.attributes) {
            if (!importSelected.has(attr.key)) continue;
            const multiValued = ATTRIBUTE_MAP[attr.key]?.multiValued ?? false;
            const res = mergeAttribute(attr, multiValued);
            if (res.status === 'conflict') {
                pending.push({ existing: res.existing, incoming: res.incoming, multiValued });
            } else if (res.status === 'strengthened') {
                strengthened++;
            } else {
                added++;
                if (res.status === 'added') syncTopLevel(attr);
            }
        }
        if (pending.length > 0) {
            setTally({ added, strengthened, kept: 0 });
            setConflicts(pending);
            setConflictIndex(0);
            setPendingImport(null);
            return;
        }
        finish({ added, strengthened, kept: 0 });
    };

    const handleResolve = (choice: 'keep' | 'replace' | 'both') => {
        const current = conflicts[conflictIndex];
        if (!current) return;
        resolveConflict(current.existing, current.incoming, choice);
        if (choice === 'replace') syncTopLevel(current.incoming);

        const next = {
            added: tally.added + (choice === 'keep' ? 0 : 1),
            strengthened: tally.strengthened,
            kept: tally.kept + (choice === 'keep' ? 1 : 0),
        };
        if (conflictIndex + 1 >= conflicts.length) {
            finish(next);
            return;
        }
        setTally(next);
        setConflictIndex(conflictIndex + 1);
    };

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title="Import Data" />
            <ScrollView contentContainerStyle={styles.content}>
                {conflicts.length > 0 ? (
                    <ConflictResolutionSheet
                        conflict={conflicts[conflictIndex]}
                        index={conflictIndex}
                        total={conflicts.length}
                        onResolve={handleResolve}
                    />
                ) : pendingImport ? (
                    <ImportSelectionSheet
                        providerName={pendingImport.linked.displayName}
                        attributes={pendingImport.attributes}
                        selected={importSelected}
                        onToggle={toggleImport}
                        onConfirm={applyImport}
                        onCancel={() => setPendingImport(null)}
                    />
                ) : (
                    <>
                        {/* Government-verified — highest assurance, first. */}
                        <Pressable style={styles.govCard} onPress={() => router.push('/kyc-capture' as never)}>
                            <RNView style={styles.govIcon}>
                                <Ionicons name="shield-checkmark" size={22} color="#FFFFFF" />
                            </RNView>
                            <RNView style={{ flex: 1 }}>
                                <Text style={styles.govTitle}>Import from ID</Text>
                                <Text style={styles.govSub}>
                                    Scan your passport or national ID to add government-verified
                                    attributes (name, date of birth, nationality).
                                </Text>
                            </RNView>
                            <Ionicons name="chevron-forward" size={18} color="#94A3B8" />
                        </Pressable>

                        <Text style={styles.sectionTitle}>Import from an account</Text>
                        <Text style={styles.sectionSub}>
                            Sign in once to fill your profile. The provider cannot access your
                            Privasys data, and you choose what to import.
                        </Text>
                        {Object.entries(PROVIDERS).map(([key, config]) => {
                            const isLinking = linkingProvider === key;
                            return (
                                <Pressable
                                    key={key}
                                    style={styles.providerRow}
                                    onPress={() => startImport(key)}
                                    disabled={isLinking || linkingProvider !== null}
                                >
                                    <Ionicons name={PROVIDER_ICONS[key] ?? 'globe-outline'} size={22} color="#64748B" />
                                    <Text style={styles.providerName}>{config.displayName}</Text>
                                    {isLinking ? (
                                        <ActivityIndicator size="small" color="#00BCF2" />
                                    ) : (
                                        <Ionicons name="chevron-forward" size={18} color="#94A3B8" />
                                    )}
                                </Pressable>
                            );
                        })}
                    </>
                )}
            </ScrollView>
        </RNView>
    );
}

const styles = StyleSheet.create({
    screen: { flex: 1, backgroundColor: '#F8FAFB' },
    content: { padding: 20 },
    govCard: {
        flexDirection: 'row', alignItems: 'center', gap: 12, backgroundColor: '#FFFFFF',
        borderRadius: 14, padding: 16, marginBottom: 20,
        borderWidth: 1, borderColor: '#D1FADF',
    },
    govIcon: {
        width: 40, height: 40, borderRadius: 20, backgroundColor: '#34C759',
        alignItems: 'center', justifyContent: 'center',
    },
    govTitle: { fontSize: 16, fontWeight: '700', color: '#0F172A' },
    govSub: { fontSize: 13, color: '#64748B', lineHeight: 18, marginTop: 2 },
    sectionTitle: { fontSize: 15, fontWeight: '600', color: '#0F172A', marginBottom: 4 },
    sectionSub: { fontSize: 13, color: '#64748B', lineHeight: 18, marginBottom: 12 },
    providerRow: {
        flexDirection: 'row', alignItems: 'center', gap: 12, backgroundColor: '#FFFFFF',
        borderRadius: 12, paddingHorizontal: 16, paddingVertical: 16, marginBottom: 8,
    },
    providerName: { flex: 1, fontSize: 15, fontWeight: '500', color: '#0F172A' },
});
