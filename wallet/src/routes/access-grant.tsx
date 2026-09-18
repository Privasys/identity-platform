// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * One standing grant, and the button that ends it.
 *
 * Three things on this screen are load-bearing, and all three are about not
 * overclaiming:
 *
 * 1. The state is what the RESOURCE SERVICE says, or it is labelled as this
 *    device's own record. The wallet asks on open and never presents its cache
 *    as fact.
 * 2. Revoking is recorded only after the service confirms it. A row that reads
 *    "removed" while the service still holds the grant is worse than no screen.
 * 3. Where the holder handed over a credential for an account elsewhere,
 *    revoking stops the service and destroys its sealed copy, and the
 *    credential itself stays valid at the provider until the holder removes it
 *    there. That sentence appears before they tap, not after.
 */

import { Ionicons } from '@expo/vector-icons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ActivityIndicator, Alert, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { resolveApp } from '@/services/app-resolve';
import {
    isFolderBusy,
    listCapabilities,
    revokeAtCallingApp,
    revokeCapability,
    serviceUrlHost,
} from '@/services/capabilities';
import { syncGrantsIndex } from '@/services/grants-index';
import { capabilityKey, useCapabilitiesStore, type CapabilityRecord } from '@/stores/capabilities';
import { groupOf, isLive } from '@/utils/access-rows';

/** What the wallet has managed to learn about this grant from the service. */
type Checked = 'checking' | 'held' | 'gone' | 'unreachable' | 'unsupported';

export default function AccessGrantScreen() {
    const params = useLocalSearchParams<{ key?: string }>();
    const key = String(params.key ?? '');
    const records = useCapabilitiesStore((s) => s.records);
    const markChecked = useCapabilitiesStore((s) => s.markChecked);
    const markRevoked = useCapabilitiesStore((s) => s.markRevoked);
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { t } = useTranslation();

    const record = useMemo(
        () => records.find((r) => capabilityKey(r) === key),
        [records, key],
    );
    const [checked, setChecked] = useState<Checked>('checking');
    const [host, setHost] = useState<string>('');
    const [busy, setBusy] = useState(false);

    const nowSeconds = Math.floor(Date.now() / 1000);
    const live = record ? isLive(record, nowSeconds) : false;
    const group = record ? groupOf(record) : 'data';

    /**
     * Ask the service what it actually holds. Resolved by identity, like the
     * mint was: the wallet does not keep a hostname from an old approval and
     * dial it later.
     */
    const check = useCallback(async () => {
        // Read at call time, not from a render. This ends by writing the
        // answer into the store (markChecked), which makes a new record
        // object; a check that depended on that object re-ran on its own
        // write and flapped "checking" forever while asking the service in a
        // loop (2026-09-18).
        const current = useCapabilitiesStore
            .getState()
            .records.find((r) => capabilityKey(r) === key);
        if (!current?.capabilityId || !current.resourceAppId) {
            setChecked('unreachable');
            return;
        }
        setChecked('checking');
        try {
            // A capability minted at a service_url is asked about there, on the
            // host that was attested when it was minted. Resolving the app id
            // again would find the app, not the storage the grant lives in.
            let targetHost: string;
            if (current.serviceUrl) {
                targetHost = serviceUrlHost(current.serviceUrl);
            } else {
                const resolved = await resolveApp(current.resourceAppId);
                if (!resolved?.hostname) {
                    console.warn(`[ACCESS] the control plane could not resolve ${current.resourceAppId}`);
                    setChecked('unreachable');
                    return;
                }
                targetHost = resolved.hostname;
            }
            setHost(targetHost);
            const held = await listCapabilities(targetHost, current.serviceUrl);
            if (held === null) {
                // The service does not serve the list, so it cannot be asked
                // and must not be revoked from here either.
                setChecked('unsupported');
                return;
            }
            const found = held.some((c) => c.capability_id === current.capabilityId);
            setChecked(found ? 'held' : 'gone');
            markChecked(key, found ? 'held' : 'gone');
        } catch (e) {
            // Offline, the service is down, or it refused the wallet. The row
            // stays as this device's record. Logged with the reason, because
            // "could not be reached" on the screen is all the holder needs and
            // not all anyone diagnosing it does (2026-09-18: a Remove access
            // that did nothing, and nothing in the log to say why).
            console.warn(
                `[ACCESS] could not ask the service about ${current.capabilityId}: ${e instanceof Error ? e.message : String(e)}`,
            );
            setChecked('unreachable');
        }
    }, [key, markChecked]);

    // Once per grant opened. Deliberately not on every change to the record:
    // the check itself changes the record.
    const startedFor = useRef<string | null>(null);
    useEffect(() => {
        if (!record) return;
        if (startedFor.current === key) return;
        startedFor.current = key;
        if (live) void check();
        else setChecked(record.revokedAt ? 'gone' : 'unreachable');
    }, [record, live, key, check]);

    const onRevoke = () => {
        // Never a silent return behind a button that looks live. The button is
        // only drawn once the service has answered, so this should not happen;
        // if it does, the holder is told nothing was changed.
        if (!record?.capabilityId || !host) {
            Alert.alert(t('access.revokeFailedTitle'), t('access.revokeFailedBody'));
            return;
        }
        const app = record.appName || t('capability.unnamedApp');
        Alert.alert(
            t(group === 'account' ? 'access.disconnectTitle' : 'access.removeTitle', { app }),
            group === 'account'
                ? t('access.disconnectBody', { app, resource: record.resourceLabel })
                : t('access.removeBody', { app }),
            [
                { text: t('common.cancel'), style: 'cancel' },
                {
                    text: t(group === 'account' ? 'access.disconnect' : 'access.remove'),
                    style: 'destructive',
                    onPress: async () => {
                        setBusy(true);
                        try {
                            await revokeCapability(host, record.capabilityId!, record.serviceUrl);
                            // Only now. The service has confirmed.
                            markRevoked(key);
                            setChecked('gone');
                            // Then the app that asked, so it stops saying
                            // "approved". After, not before, and never instead.
                            await revokeAtCallingApp({
                                callingAppId: record.appId,
                                capabilityId: record.capabilityId!,
                                resourceHost: host,
                                resolve: resolveApp,
                            });
                            void syncGrantsIndex();
                        } catch (e) {
                            // Files still open: nothing was revoked and nothing
                            // is wrong. Say that, rather than a status code.
                            if (isFolderBusy(e)) {
                                Alert.alert(t('access.revokeFailedTitle'), t('access.revokeBusy'));
                                return;
                            }
                            console.warn(
                                `[ACCESS] revoke failed for ${record.capabilityId} on ${host}: ${e instanceof Error ? e.message : String(e)}`,
                            );
                            Alert.alert(
                                t('access.revokeFailedTitle'),
                                e instanceof Error ? e.message : t('access.revokeFailedBody'),
                            );
                        } finally {
                            setBusy(false);
                        }
                    },
                },
            ],
        );
    };

    if (!record) {
        return (
            <RNView style={styles.screen}>
                <SubPageHeader title={t('access.grantTitle')} />
                <RNView style={styles.centre}>
                    <Text style={styles.body}>{t('access.grantGone')}</Text>
                    <Pressable style={styles.secondary} onPress={() => router.back()}>
                        <Text style={styles.secondaryText}>{t('common.close')}</Text>
                    </Pressable>
                </RNView>
            </RNView>
        );
    }

    const permissions = record.permissions
        .map((perm) => t(`capability.permission.${perm}`))
        .join(t('capability.permissionJoin'));

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t('access.grantTitle')} />
            <ScrollView
                contentContainerStyle={[styles.content, { paddingBottom: insets.bottom + 32 }]}
                showsVerticalScrollIndicator={false}
            >
                <StateBanner checked={checked} record={record} styles={styles} p={p} />

                <RNView style={styles.card}>
                    <Text style={styles.label}>{t('capability.whoLabel')}</Text>
                    <Text style={styles.value}>{record.appName || t('capability.unnamedApp')}</Text>
                    <Text style={styles.mono}>{record.appId}</Text>
                </RNView>

                <RNView style={styles.card}>
                    <Text style={styles.label}>{t('capability.whatLabel')}</Text>
                    {/* The same sentence the approval screen used, from the same
                        wallet-owned vocabulary, so the holder reads back what
                        they agreed to rather than a paraphrase of it. */}
                    <Text style={styles.value}>
                        {t(
                            [
                                `capability.resourceLineByKind.${record.kind}`,
                                'capability.resourceLine',
                            ],
                            {
                                permissions,
                                resource: record.resourceLabel,
                                service: record.resourceAppName || t('capability.unnamedApp'),
                            },
                        )}
                    </Text>
                    <Text style={styles.muted}>
                        {t('access.grantedOn', { when: new Date(record.grantedAt * 1000) })}
                    </Text>
                    {!!record.expiresAt && (
                        <Text style={styles.muted}>
                            {t('access.expiresOn', { when: new Date(record.expiresAt * 1000) })}
                        </Text>
                    )}
                    {!!record.revokedAt && (
                        <Text style={styles.muted}>
                            {t('access.revokedOn', { when: new Date(record.revokedAt * 1000) })}
                        </Text>
                    )}
                    {/* The part of a holder-folder approval most worth being
                        reminded of: the app can carry on without the phone. */}
                    {record.kind === 'app_storage' && record.unattended && (
                        <Text style={styles.muted}>{t('capability.appStorageUnattended')}</Text>
                    )}
                </RNView>

                {/* The credential, where there is one. Named, never shown: the
                    wallet held it for one request and never wrote it down. */}
                {group === 'account' && (
                    <RNView style={styles.card}>
                        <Text style={styles.label}>{t('access.credentialLabel')}</Text>
                        <Text style={styles.value}>
                            {record.secretLabels?.length
                                ? t('access.credentialGiven', {
                                    what: record.secretLabels.join(t('capability.permissionJoin')),
                                })
                                : t('access.credentialGivenGeneric')}
                        </Text>
                        {/* The asymmetry that matters: what was handed over is
                            wider than what was granted, and attestation is the
                            only thing narrowing it. */}
                        <Text style={styles.muted}>{t('access.credentialWider')}</Text>
                    </RNView>
                )}

                {/* Remove only once the service has said it holds this grant.
                    That is also what makes the revoke's answer readable: from
                    a service whose list just answered, a 404 means "not held";
                    from one the wallet could not reach, the same 404 might mean
                    the route is absent, and recording that as "you removed
                    this" would claim a revocation that never happened. The
                    button used to show whenever the check had not said
                    "unsupported", looked live, and did nothing when the service
                    had not answered (2026-09-18). */}
                {live && checked === 'held' && (
                    <Pressable
                        style={[styles.danger, busy && styles.busy]}
                        onPress={onRevoke}
                        disabled={busy}
                    >
                        {busy ? (
                            <ActivityIndicator color="#FFFFFF" />
                        ) : (
                            <Text style={styles.dangerText}>
                                {t(group === 'account' ? 'access.disconnect' : 'access.remove')}
                            </Text>
                        )}
                    </Pressable>
                )}
                {/* Could not ask: say so, and offer the one thing that can help. */}
                {live && checked === 'unreachable' && (
                    <Pressable style={styles.retry} onPress={() => void check()}>
                        <Text style={styles.retryText}>{t('common.retry')}</Text>
                    </Pressable>
                )}

                {/* Said before the tap, not after it. */}
                <Text style={styles.footnote}>
                    {t(group === 'account' ? 'access.disconnectNote' : 'access.removeNote')}
                </Text>
            </ScrollView>
        </RNView>
    );
}

function StateBanner({
    checked,
    record,
    styles,
    p,
}: {
    checked: Checked;
    record: CapabilityRecord;
    styles: ReturnType<typeof makeStyles>;
    p: Palette;
}) {
    const { t } = useTranslation();
    if (record.revokedAt) {
        return <Banner tone="muted" icon="close-circle" text={t('access.stateRevoked')} styles={styles} p={p} />;
    }
    switch (checked) {
        case 'checking':
            return <Banner tone="muted" icon="sync" text={t('access.stateChecking')} styles={styles} p={p} />;
        case 'held':
            return <Banner tone="good" icon="checkmark-circle" text={t('access.stateConfirmed')} styles={styles} p={p} />;
        case 'gone':
            return <Banner tone="muted" icon="close-circle" text={t('access.stateGone')} styles={styles} p={p} />;
        case 'unsupported':
            return <Banner tone="warn" icon="information-circle" text={t('access.stateUnsupported')} styles={styles} p={p} />;
        default:
            return <Banner tone="warn" icon="cloud-offline" text={t('access.stateLocal')} styles={styles} p={p} />;
    }
}

function Banner({
    tone,
    icon,
    text,
    styles,
    p,
}: {
    tone: 'good' | 'warn' | 'muted';
    icon: keyof typeof Ionicons.glyphMap;
    text: string;
    styles: ReturnType<typeof makeStyles>;
    p: Palette;
}) {
    const colour = tone === 'good' ? p.successText : tone === 'warn' ? p.warnText : p.textMuted;
    const background = tone === 'good' ? p.successBg : tone === 'warn' ? p.warnBg : p.cardAlt;
    return (
        <RNView style={[styles.banner, { backgroundColor: background }]}>
            <Ionicons name={icon} size={16} color={colour} />
            <Text style={[styles.bannerText, { color: colour }]}>{text}</Text>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    content: { padding: 20 },
    centre: { alignItems: 'center', padding: 40, gap: 16 },
    banner: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 8,
        borderRadius: 10,
        paddingHorizontal: 12,
        paddingVertical: 10,
        marginBottom: 16,
    },
    bannerText: { fontSize: 13, flex: 1, lineHeight: 18 },
    card: {
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 16,
        marginBottom: 12,
        gap: 4,
    },
    label: { fontSize: 12, color: p.textSecondary, marginBottom: 2 },
    value: { fontSize: 16, fontWeight: '600', color: p.textPrimary, lineHeight: 23 },
    mono: { fontSize: 12, fontFamily: 'SpaceMono', color: p.textMuted },
    muted: { fontSize: 13, color: p.textMuted, lineHeight: 19 },
    body: { fontSize: 14, color: p.textSecondary, lineHeight: 21, textAlign: 'center' },
    footnote: { fontSize: 12, color: p.textMuted, lineHeight: 18, marginTop: 12 },
    danger: {
        backgroundColor: p.danger,
        borderRadius: 12,
        paddingVertical: 14,
        alignItems: 'center',
        justifyContent: 'center',
        marginTop: 8,
    },
    dangerText: { fontSize: 16, fontWeight: '600', color: '#FFFFFF' },
    retry: {
        backgroundColor: p.card,
        borderWidth: 1,
        borderColor: p.border,
        borderRadius: 12,
        paddingVertical: 14,
        alignItems: 'center',
        marginTop: 8,
    },
    retryText: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
    busy: { opacity: 0.7 },
    secondary: {
        backgroundColor: p.card,
        borderWidth: 1,
        borderColor: p.border,
        borderRadius: 12,
        paddingVertical: 14,
        paddingHorizontal: 32,
        alignItems: 'center',
    },
    secondaryText: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
});
