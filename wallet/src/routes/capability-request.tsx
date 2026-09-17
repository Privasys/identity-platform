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
 * A service may also need something from the holder before the capability can
 * exist: an approval of its own, and values to type. Both happen here, on the
 * same tap, because this is the only screen in the chain where the holder can
 * see the far end being verified, and because what they type then makes one
 * attested hop to the service that seals it.
 *
 * Nothing here knows what a tenant, a folder or a mailbox is. The resource
 * service does its own domain work from a request body the wallet forwards
 * without reading, and draws its own form from a schema the wallet renders
 * without interpreting.
 */

import { Ionicons } from '@expo/vector-icons';
import { useFocusEffect } from '@react-navigation/native';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
    ActivityIndicator,
    Alert,
    KeyboardAvoidingView,
    Platform,
    Pressable,
    ScrollView,
    StyleSheet,
    View as RNView,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { SetupForm } from '@/components/SetupForm';
import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { inspectAttestation, isAttestableHost } from '@/services/attestation';
import { attestationMatchesResolution, resolveApp, type ResolvedApp } from '@/services/app-resolve';
import {
    createCapability,
    deliverCapabilityOutcome,
    expiryFor,
    fetchPendingCapability,
    isProviderRefusal,
    isStaleTenantKey,
    type PendingCapability,
} from '@/services/capabilities';
import {
    initialAnswers,
    missingRequired,
    setupPayload,
    type SetupAnswers,
    type SetupPrerequisite,
    type SetupRequirement,
} from '@/services/capability-setup';
import { rearmTenantKeyAt } from '@/services/drive';
import { appIdFromOids } from '@/services/release-provenance';
import { useCapabilitiesStore } from '@/stores/capabilities';
import { useConsentStore } from '@/stores/consent';
import { useProfileStore } from '@/stores/profile';
import { recordChainOutcome, takeChainOutcome } from '@/utils/capability-chain';

type Phase = 'loading' | 'prerequisite' | 'ready' | 'refused' | 'working' | 'done';

/**
 * The holder's own address, but only where the app that asked has already been
 * allowed to see it. An address the holder chose to keep from this app is not
 * one the wallet volunteers on its behalf.
 */
function prefillEmailFor(appHost: string): string {
    const disclosed = useConsentStore
        .getState()
        .getRecordsForApp(appHost)
        .some((r) => r.approvedAttributes.includes('email'));
    if (!disclosed) return '';
    const profile = useProfileStore.getState().profile;
    return profile?.attributes.find((a) => a.key === 'email')?.value || profile?.email || '';
}

export default function CapabilityRequestScreen() {
    const { t } = useTranslation();
    const p = usePalette();
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const styles = useMemo(() => makeStyles(p), [p]);
    const params = useLocalSearchParams<{ app_host?: string; nonce?: string; chain?: string }>();

    const appHost = String(params.app_host ?? '');
    const nonce = String(params.nonce ?? '');
    /** This screen is a prerequisite of another approval, running under it. */
    const chained = String(params.chain ?? '') === '1';

    const [phase, setPhase] = useState<Phase>('loading');
    const [refusal, setRefusal] = useState<string>('');
    const [pending, setPending] = useState<PendingCapability | null>(null);
    const [requesterAppId, setRequesterAppId] = useState<string>('');
    const [requesterName, setRequesterName] = useState<string>('');
    const [resource, setResource] = useState<ResolvedApp | null>(null);

    // What the service needs from the holder. `setup` is the step being shown;
    // `answered` is everything accepted by earlier steps, which a later one
    // must not ask for again. Both live in component state only: they hold a
    // secret, so they are never persisted and never logged.
    const [setup, setSetup] = useState<SetupRequirement | null>(null);
    const [answers, setAnswers] = useState<SetupAnswers>({});
    const [answered, setAnswered] = useState<Record<string, unknown>>({});
    const [missing, setMissing] = useState<string[]>([]);
    const [serviceMessage, setServiceMessage] = useState<string>('');
    /**
     * The service's labels for the secret fields the holder has filled in so
     * far, across every step. Labels, never values: this is what lets the
     * Access screen later say "you gave this service an app password" without
     * the wallet ever having kept one.
     */
    const [secretsSoFar, setSecretsSoFar] = useState<string[]>([]);

    // Where the prerequisite chain has got to. Refs, not state, so that the
    // effect driving it can have no dependencies: it must re-run when this
    // screen is focused again and at no other time, because "focused again" is
    // exactly the event it reads as "the screen we pushed has closed".
    const chain = useRef({ queue: [] as SetupPrerequisite[], index: 0, awaiting: '', running: false });
    const leftScreen = useRef(false);

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

                // A prerequisite may not have prerequisites of its own. One
                // level is what the flow needs, and it bounds the stack: a
                // service that kept naming another approval would otherwise
                // push screens under the holder without end.
                if (chained && req.setup?.prerequisites.length) {
                    return refuse(t('capability.setup.refusedNested'));
                }

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
                if (req.setup) {
                    setSetup(req.setup);
                    setAnswers(
                        initialAnswers(req.setup.fields, { email: prefillEmailFor(appHost) }),
                    );
                }
                // The service's own approvals come first, so the holder is not
                // asked to type a credential into a service that has nowhere
                // to keep it yet.
                const queue = req.setup?.prerequisites ?? [];
                chain.current = { queue, index: 0, awaiting: '', running: queue.length > 0 };
                setPhase(queue.length > 0 ? 'prerequisite' : 'ready');
            } catch (e) {
                if (!cancelled) refuse(e instanceof Error ? e.message : String(e));
            }
        })();
        return () => {
            cancelled = true;
        };
    }, [appHost, nonce, chained, refuse, t]);

    /**
     * Deny the whole ask and leave. Used by the Deny button and by a
     * prerequisite the holder turned down: an approval the service cannot hold
     * the credential without is not one the wallet can go on to mint.
     */
    const denyAndLeave = useCallback(async () => {
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
        if (chained) recordChainOutcome(nonce, 'denied');
        router.back();
    }, [appHost, nonce, chained, pending, resource, requesterAppId, requesterName, router]);

    // Held in refs so `runChain` below can stay dependency-free: its identity
    // changing would fire the focus effect's cleanup, which is the one signal
    // that tells the chain this screen was really left.
    const denyRef = useRef(denyAndLeave);
    const routerRef = useRef(router);
    useEffect(() => {
        denyRef.current = denyAndLeave;
        routerRef.current = router;
    });

    /**
     * Run the service's own approvals, one at a time, on this stack.
     *
     * Each is an ordinary capability ask with its own nonce, so it is pushed as
     * another instance of this screen and reports its decision back under that
     * nonce. The step is only read once this screen has actually been left and
     * come back: a push does not blur synchronously, so reading straight after
     * one would find no decision and mistake it for a refusal.
     */
    const runChain = useCallback(() => {
        const c = chain.current;
        if (!c.running) return;

        if (c.awaiting) {
            if (!leftScreen.current) return;
            // Back from one. No decision recorded means the holder left that
            // screen without making one, which is a refusal, and a service
            // that cannot hold the credential cannot be given it.
            const outcome = takeChainOutcome(c.awaiting);
            c.awaiting = '';
            if (outcome !== 'approved') {
                c.running = false;
                console.log('[CAPABILITY] a prerequisite approval was not granted; denying the ask');
                void denyRef.current();
                return;
            }
            c.index += 1;
        }

        const next = c.queue[c.index];
        if (!next) {
            c.running = false;
            setPhase('ready');
            return;
        }
        c.awaiting = next.nonce;
        leftScreen.current = false;
        routerRef.current.push({
            pathname: '/capability-request',
            params: { app_host: next.app_host, nonce: next.nonce, chain: '1' },
        });
    }, []);

    // The first step. The screen is already focused when the request finishes
    // loading, so no focus event is coming to start it.
    useEffect(() => {
        if (phase === 'prerequisite') runChain();
    }, [phase, runChain]);

    useFocusEffect(
        useCallback(() => {
            runChain();
            // Only ever on a real blur, because this callback never changes.
            return () => {
                leftScreen.current = true;
            };
        }, [runChain]),
    );

    const permissionLine = useMemo(() => {
        if (!pending) return '';
        return pending.capability.permissions
            .map((perm) => t(`capability.permission.${perm}`))
            .join(t('capability.permissionJoin'));
    }, [pending, t]);

    const onApprove = async () => {
        if (!pending || !resource?.hostname) return;

        // Check what is required before the round trip. The service would
        // refuse an empty field anyway, and a network error is a poor way to
        // learn that something was not filled in.
        if (setup) {
            const gaps = missingRequired(setup.fields, answers);
            if (gaps.length > 0) {
                setMissing(gaps);
                return;
            }
        }
        setMissing([]);
        setServiceMessage('');
        setPhase('working');

        // Everything the holder has typed across every step of this approval.
        // Built here, sent once, and dropped when the screen closes.
        const payload = setup ? { ...answered, ...setupPayload(setup.fields, answers) } : undefined;

        const stepSecrets = (setup?.fields ?? [])
            .filter((f) => f.kind === 'secret' && String(answers[f.name] ?? '').length > 0)
            .map((f) => f.title);
        const secretsGiven = [
            ...secretsSoFar,
            ...stepSecrets.filter((s) => !secretsSoFar.includes(s)),
        ];

        try {
            const expiresUnix = expiryFor(pending.capability.kind);
            const mint = () =>
                createCapability({
                    resourceHost: resource.hostname,
                    subjectAppId: requesterAppId,
                    pending,
                    expiresUnix,
                    setup: payload,
                });
            let outcome;
            try {
                outcome = await mint();
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
                outcome = await mint();
            }

            // One more question: a mail server that could not be found from the
            // address, say. Keep what was answered, draw the new step, and stay
            // on this screen. Nothing was granted and nothing failed.
            if (outcome.status === 'incomplete') {
                console.log(
                    `[CAPABILITY] ${resource.hostname} needs more before it can grant this; asking`,
                );
                setAnswered(payload ?? {});
                setSecretsSoFar(secretsGiven);
                setSetup(outcome.requirement);
                setAnswers(
                    initialAnswers(outcome.requirement.fields, {
                        previous: answers,
                        email: prefillEmailFor(appHost),
                    }),
                );
                setPhase('ready');
                return;
            }

            const granted = outcome.granted;
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
                // That a credential was handed over, and what the service
                // called it. Never what it was: the values made one hop to the
                // service and are gone from here the moment this screen closes.
                setupProvided: secretsGiven.length > 0,
                secretLabels: secretsGiven.length > 0 ? secretsGiven : undefined,
            });

            if (chained) {
                // Running under another approval: report and return to it
                // rather than making the holder dismiss a screen mid-flow.
                recordChainOutcome(nonce, 'approved');
                router.back();
                return;
            }
            setPhase('done');
        } catch (e) {
            // The provider behind the service refused the details themselves.
            // Not a failure of the wallet or of the service, so the holder
            // stays on the form and edits. Deliberately not logged: the
            // service's sentence is the only account of why, and it can quote
            // back what was typed.
            if (isProviderRefusal(e)) {
                setServiceMessage(e.message || t('capability.setup.refusedFallback'));
                setPhase('ready');
                return;
            }
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

    const setAnswer = useCallback((name: string, value: string | boolean) => {
        setAnswers((prev) => ({ ...prev, [name]: value }));
        setMissing((prev) => prev.filter((n) => n !== name));
    }, []);

    const serviceName = resource?.display_name || resource?.name || '';

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t('capability.title')} />
            {/* The form can put a masked field low on a screen that already
                carries two identity cards. No offset: this view begins below
                the header, so its bottom is the screen bottom and the plain
                keyboard height is exactly right. */}
            <KeyboardAvoidingView
                style={styles.fill}
                behavior={Platform.OS === 'ios' ? 'padding' : undefined}
                keyboardVerticalOffset={0}
            >
            <ScrollView
                // Room for the last field to scroll clear of the keyboard, but
                // only when there is a form; otherwise this is empty scroll.
                contentContainerStyle={[
                    styles.content,
                    { paddingBottom: insets.bottom + (setup ? 120 : 24) },
                ]}
                showsVerticalScrollIndicator={false}
                keyboardShouldPersistTaps="handled"
            >
                {(phase === 'loading' || phase === 'prerequisite') && (
                    <RNView style={styles.centre}>
                        <ActivityIndicator size="large" color={p.blue} />
                        <Text style={styles.muted}>
                            {t(phase === 'prerequisite' ? 'capability.setup.preparing' : 'capability.verifying')}
                        </Text>
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

                        {/* Why a second screen appeared under the first one. */}
                        {chained && <Text style={styles.body}>{t('capability.setup.chainNote')}</Text>}

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
                                {/* The generic line was written for a folder
                                    ("Read and Create and change X in your Y")
                                    and reads like storage for everything else.
                                    A kind may therefore own its own line; the
                                    generic one is the fallback, so adding a
                                    kind never requires adding a sentence. */}
                                {t(
                                    [
                                        `capability.resourceLineByKind.${pending.capability.kind}`,
                                        'capability.resourceLine',
                                    ],
                                    {
                                        permissions: permissionLine,
                                        resource: pending.capability.resource_label,
                                        service: serviceName,
                                    },
                                )}
                            </Text>
                            <Text style={styles.attested}>
                                <Ionicons name="shield-checkmark" size={13} color={p.green} />{' '}
                                {t('capability.resourceAttested', { service: serviceName })}
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
                                {t('capability.revokeHint')}
                            </Text>
                        </RNView>

                        {/* What the service needs from the holder, drawn from
                            the schema it declared. Under the ask, so the grant
                            has been read before anything is typed. */}
                        {setup && setup.fields.length > 0 && (
                            <RNView style={styles.setup}>
                                <Text style={styles.label}>{t('capability.setup.formLabel')}</Text>
                                {!!setup.message && <Text style={styles.body}>{setup.message}</Text>}

                                <SetupForm
                                    fields={setup.fields}
                                    answers={answers}
                                    onChange={setAnswer}
                                    missing={missing}
                                    disabled={phase === 'working'}
                                />

                                {/* Where what is typed goes, and where it does
                                    not. The holder is entering a credential on
                                    a screen, and is owed that sentence. */}
                                <Text style={styles.muted}>
                                    {t('capability.setup.privacyNote', { service: serviceName })}
                                </Text>

                                {missing.length > 0 && (
                                    <Text style={styles.problem}>{t('capability.setup.incomplete')}</Text>
                                )}

                                {/* The provider's own words about why it said
                                    no. The fields above stay as they were. */}
                                {!!serviceMessage && (
                                    <RNView style={styles.refusal}>
                                        <Text style={styles.refusalTitle}>
                                            {t('capability.setup.refusedTitle', { service: serviceName })}
                                        </Text>
                                        <Text style={styles.refusalBody}>{serviceMessage}</Text>
                                    </RNView>
                                )}
                            </RNView>
                        )}

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
                            onPress={denyAndLeave}
                            disabled={phase === 'working'}
                        >
                            <Text style={styles.secondaryText}>{t('capability.deny')}</Text>
                        </Pressable>
                    </>
                )}
            </ScrollView>
            </KeyboardAvoidingView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    fill: { flex: 1 },
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
    setup: {
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 16,
        marginBottom: 12,
        gap: 12,
    },
    label: { fontSize: 12, color: p.textSecondary, marginBottom: 2 },
    value: { fontSize: 16, fontWeight: '600', color: p.textPrimary, lineHeight: 23 },
    mono: { fontSize: 12, fontFamily: 'SpaceMono', color: p.textMuted },
    attested: { fontSize: 12, color: p.textSecondary, marginTop: 4 },
    problem: { fontSize: 13, color: p.dangerText, lineHeight: 19 },
    refusal: {
        backgroundColor: p.dangerBg,
        borderWidth: 1,
        borderColor: p.dangerBorder,
        borderRadius: 10,
        padding: 12,
        gap: 4,
    },
    refusalTitle: { fontSize: 13, fontWeight: '600', color: p.dangerText },
    refusalBody: { fontSize: 13, color: p.dangerText, lineHeight: 19 },
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
