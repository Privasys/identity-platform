// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Capability approval: an attested app asking for scoped, revocable authority
 * over a resource the holder owns.
 *
 * The screen answers three questions in this order: who is asking, what of
 * yours, and for how long. Two identities appear, not one, because the app
 * asking and the service holding the data are different parties, and both must
 * be verified from attestation rather than taken from the request.
 *
 * Nothing here knows what a tenant or a folder is. The resource service does
 * its own domain work from a request body the wallet forwards without reading.
 */

import { Ionicons } from '@expo/vector-icons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
    ActivityIndicator,
    Alert,
    Pressable,
    ScrollView,
    StyleSheet,
    View as RNView,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { inspectAttestation, isAttestableHost } from '@/services/attestation';
import { attestationMatchesResolution, resolveApp, type ResolvedApp } from '@/services/app-resolve';
import {
    createCapability,
    deliverCapabilityOutcome,
    expiryFor,
    fetchPendingCapability,
    isStaleTenantKey,
    type PendingCapability,
} from '@/services/capabilities';
import { rearmTenantKeyAt } from '@/services/drive';
import { appIdFromOids } from '@/services/release-provenance';
import { useCapabilitiesStore } from '@/stores/capabilities';

type Phase = 'loading' | 'ready' | 'refused' | 'working' | 'done';

export default function CapabilityRequestScreen() {
    const { t } = useTranslation();
    const p = usePalette();
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const styles = useMemo(() => makeStyles(p), [p]);
    const params = useLocalSearchParams<{ app_host?: string; nonce?: string }>();

    const appHost = String(params.app_host ?? '');
    const nonce = String(params.nonce ?? '');

    const [phase, setPhase] = useState<Phase>('loading');
    const [refusal, setRefusal] = useState<string>('');
    const [pending, setPending] = useState<PendingCapability | null>(null);
    const [requesterAppId, setRequesterAppId] = useState<string>('');
    const [requesterName, setRequesterName] = useState<string>('');
    const [resource, setResource] = useState<ResolvedApp | null>(null);

    const refuse = useCallback((reason: string) => {
        setRefusal(reason);
        setPhase('refused');
    }, []);

    useEffect(() => {
        let cancelled = false;
        (async () => {
            try {
                if (!appHost || !nonce) return refuse(t('capability.refusedMalformed'));

                // The requesting app must be an enclave. It is asking for
                // durable authority over data, which is not a claim a host we
                // cannot attest gets to make.
                if (!isAttestableHost(appHost)) return refuse(t('capability.refusedRequester'));

                // Attest FIRST, then read the request from inside that channel.
                const att = await inspectAttestation(appHost);
                const appId = appIdFromOids(att.custom_oids);
                if (!appId) return refuse(t('capability.refusedRequester'));

                const req = await fetchPendingCapability(appHost, nonce);

                // Resolve the resource service by IDENTITY, never from a URL in
                // the request: otherwise the wallet would post a
                // user-authenticated call wherever it was told.
                const resolved = await resolveApp(req.resource_app, appHost);
                if (!resolved?.hostname) return refuse(t('capability.refusedResource'));
                if (!isAttestableHost(resolved.hostname)) {
                    return refuse(t('capability.refusedResource'));
                }

                // And check the host that answered IS the app we resolved.
                const resourceAtt = await inspectAttestation(resolved.hostname);
                if (!attestationMatchesResolution(resourceAtt, resolved)) {
                    return refuse(t('capability.refusedResource'));
                }

                if (cancelled) return;
                const requester = await resolveApp(appId, appHost);
                setRequesterAppId(appId);
                setRequesterName(requester?.display_name || requester?.name || '');
                setPending(req);
                setResource(resolved);
                setPhase('ready');
            } catch (e) {
                if (!cancelled) refuse(e instanceof Error ? e.message : String(e));
            }
        })();
        return () => {
            cancelled = true;
        };
    }, [appHost, nonce, refuse, t]);

    const permissionLine = useMemo(() => {
        if (!pending) return '';
        return pending.capability.permissions
            .map((perm) => t(`capability.permission.${perm}`))
            .join(t('capability.permissionJoin'));
    }, [pending, t]);

    const onDeny = async () => {
        setPhase('working');
        try {
            await deliverCapabilityOutcome({ appHost, nonce, status: 'denied' });
        } catch {
            // The holder's decision stands whatever the app heard. Telling them
            // the denial "failed" would suggest access was granted.
        }
        if (pending && resource) {
            useCapabilitiesStore.getState().record({
                appId: requesterAppId,
                appName: requesterName || undefined,
                resourceAppId: resource.app_id ?? '',
                resourceAppName: resource.display_name,
                kind: pending.capability.kind,
                resourceLabel: pending.capability.resource_label,
                permissions: pending.capability.permissions,
                decision: 'denied',
                grantedAt: Math.floor(Date.now() / 1000),
            });
        }
        router.back();
    };

    const onApprove = async () => {
        if (!pending || !resource?.hostname) return;
        setPhase('working');
        try {
            const expiresUnix = expiryFor(pending.capability.kind);
            const mint = () =>
                createCapability({
                    resourceHost: resource.hostname,
                    subjectAppId: requesterAppId,
                    pending,
                    expiresUnix,
                });
            let granted;
            try {
                granted = await mint();
            } catch (e) {
                // The resource service was upgraded and this holder has not
                // yet approved its new measurement for their own vault key.
                // That approval is what a Drive login does; the holder is
                // right here, so do it now and mint once more, instead of
                // showing them a vault error they can only fix by signing
                // in to Drive again.
                if (!isStaleTenantKey(e) || !resource.app_id) throw e;
                console.warn(
                    `[CAPABILITY] ${resource.hostname} reports a stale tenant key (${e.message}); approving its measurement and retrying`,
                );
                const key = await rearmTenantKeyAt({
                    host: resource.hostname,
                    appId: resource.app_id,
                    appHost,
                });
                console.log(`[CAPABILITY] tenant key ${key.status} on ${resource.hostname}`);
                granted = await mint();
            }
            await deliverCapabilityOutcome({ appHost, nonce, status: 'approved', granted });

            useCapabilitiesStore.getState().record({
                appId: requesterAppId,
                appName: requesterName || undefined,
                resourceAppId: resource.app_id ?? '',
                resourceAppName: resource.display_name,
                kind: pending.capability.kind,
                resourceLabel: pending.capability.resource_label,
                permissions: pending.capability.permissions,
                decision: 'approved',
                capabilityId: granted.capability_id,
                grantedAt: Math.floor(Date.now() / 1000),
                expiresAt: expiresUnix,
            });
            setPhase('done');
        } catch (e) {
            // Visibly failed. The app must not be told it succeeded. Logged
            // too: the alert is the only place this used to appear, and a
            // holder's exported log then said nothing about why the grant
            // was refused.
            console.warn(
                `[CAPABILITY] approval failed for ${requesterAppId} on ${resource.hostname}: ${e instanceof Error ? e.message : String(e)}`,
            );
            setPhase('ready');
            Alert.alert(
                t('capability.failedTitle'),
                e instanceof Error ? e.message : t('capability.failedBody'),
            );
        }
    };

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t('capability.title')} />
            <ScrollView
                contentContainerStyle={[styles.content, { paddingBottom: insets.bottom + 24 }]}
                showsVerticalScrollIndicator={false}
            >
                {phase === 'loading' && (
                    <RNView style={styles.centre}>
                        <ActivityIndicator size="large" color={p.blue} />
                        <Text style={styles.muted}>{t('capability.verifying')}</Text>
                    </RNView>
                )}

                {phase === 'refused' && (
                    <>
                        <RNView style={styles.centre}>
                            <Ionicons name="alert-circle-outline" size={48} color={p.danger} />
                        </RNView>
                        <Text style={styles.heading}>{t('capability.refusedTitle')}</Text>
                        {/* No approve button, deliberately: durable authority
                            over data must not be approvable against a claimant
                            the wallet could not verify. */}
                        <Text style={styles.body}>{refusal}</Text>
                        <Pressable style={styles.secondary} onPress={() => router.back()}>
                            <Text style={styles.secondaryText}>{t('common.close')}</Text>
                        </Pressable>
                    </>
                )}

                {phase === 'done' && (
                    <>
                        <RNView style={styles.centre}>
                            <Ionicons name="checkmark-circle" size={48} color={p.green} />
                        </RNView>
                        <Text style={styles.heading}>{t('capability.doneTitle')}</Text>
                        <Text style={styles.body}>
                            {t('capability.doneBody', { app: requesterName || requesterAppId.slice(0, 8) })}
                        </Text>
                        <Pressable style={styles.primary} onPress={() => router.back()}>
                            <Text style={styles.primaryText}>{t('common.done')}</Text>
                        </Pressable>
                    </>
                )}

                {(phase === 'ready' || phase === 'working') && pending && resource && (
                    <>
                        <Text style={styles.heading}>{t('capability.heading')}</Text>

                        {/* Who is asking. Verified, never echoed from the request. */}
                        <RNView style={styles.card}>
                            <Text style={styles.label}>{t('capability.whoLabel')}</Text>
                            <Text style={styles.value}>
                                {requesterName || t('capability.unnamedApp')}
                            </Text>
                            <Text style={styles.mono}>{requesterAppId}</Text>
                            <Text style={styles.attested}>
                                <Ionicons name="shield-checkmark" size={13} color={p.green} />{' '}
                                {t('capability.attested')}
                            </Text>
                        </RNView>

                        {/* What of yours. The second identity. */}
                        <RNView style={styles.card}>
                            <Text style={styles.label}>{t('capability.whatLabel')}</Text>
                            <Text style={styles.value}>
                                {t('capability.resourceLine', {
                                    permissions: permissionLine,
                                    resource: pending.capability.resource_label,
                                    service: resource.display_name || resource.name,
                                })}
                            </Text>
                            <Text style={styles.attested}>
                                <Ionicons name="shield-checkmark" size={13} color={p.green} />{' '}
                                {t('capability.resourceAttested', {
                                    service: resource.display_name || resource.name,
                                })}
                            </Text>
                        </RNView>

                        <Text style={styles.body}>{t(`capability.explain.${pending.capability.kind}`)}</Text>

                        <RNView style={styles.card}>
                            <Text style={styles.label}>{t('capability.howLongLabel')}</Text>
                            <Text style={styles.value}>
                                {new Date(expiryFor(pending.capability.kind) * 1000).toLocaleDateString()}
                            </Text>
                            {/* Name the service that holds the data, which is
                                where the revoke button lives. Saying "the service
                                that holds your data" sent someone to the app that
                                was ASKING, which has no such option. */}
                            <Text style={styles.muted}>
                                {t('capability.revokeHint', {
                                    service: resource.display_name || resource.name,
                                })}
                            </Text>
                        </RNView>

                        <Pressable
                            style={[styles.primary, phase === 'working' && styles.busy]}
                            onPress={onApprove}
                            disabled={phase === 'working'}
                        >
                            {phase === 'working' ? (
                                <ActivityIndicator color="#FFFFFF" />
                            ) : (
                                <Text style={styles.primaryText}>{t('capability.approve')}</Text>
                            )}
                        </Pressable>
                        {/* Deny is a first-class action, not a dismissal. */}
                        <Pressable
                            style={styles.secondary}
                            onPress={onDeny}
                            disabled={phase === 'working'}
                        >
                            <Text style={styles.secondaryText}>{t('capability.deny')}</Text>
                        </Pressable>
                    </>
                )}
            </ScrollView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    // 20 to match credentials, personal-data and the other sub-pages; this sat
    // at 8 and read as cramped under the header.
    content: { paddingHorizontal: 20, paddingTop: 20 },
    centre: { alignItems: 'center', marginVertical: 24, gap: 12 },
    heading: { fontSize: 20, fontWeight: '700', color: p.textPrimary, marginBottom: 12 },
    body: { fontSize: 14, color: p.textSecondary, lineHeight: 21, marginBottom: 16 },
    muted: { fontSize: 13, color: p.textMuted, lineHeight: 19 },
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
    attested: { fontSize: 12, color: p.textSecondary, marginTop: 4 },
    primary: {
        backgroundColor: p.blue,
        borderRadius: 12,
        paddingVertical: 14,
        alignItems: 'center',
        justifyContent: 'center',
        marginTop: 8,
    },
    primaryText: { fontSize: 16, fontWeight: '600', color: '#FFFFFF' },
    busy: { opacity: 0.7 },
    secondary: {
        backgroundColor: p.card,
        borderWidth: 1,
        borderColor: p.border,
        borderRadius: 12,
        paddingVertical: 14,
        alignItems: 'center',
        marginTop: 10,
    },
    secondaryText: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
});
