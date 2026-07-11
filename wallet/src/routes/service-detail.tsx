// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Service Details — one page per APP (serviceKey = OIDC client id / enclave
 * host), not per shared FIDO2 rpId. Shows the app's live sealed session, the
 * most recent enclave attestation, and the full session trail: every ceremony
 * the user authenticated in, with the attributes requested, what was consented
 * and the values as shared at that moment, and the datetimes.
 */

import { Ionicons } from '@expo/vector-icons';
import { useRouter, useLocalSearchParams, Stack } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { StyleSheet, Pressable, Alert, Linking, ScrollView, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text, usePalette, type Palette } from '@/components/Themed';
import { attributeLabel, ATTRIBUTE_MAP, getProfileValue } from '@/services/attributes';
import * as fido2 from '@/services/fido2';
import {
    fetchRunningAppReleases,
    type OsRelease,
    type WorkloadRelease
} from '@/services/release-provenance';
import { listMySessions, revokeSession } from '@/services/sessions-api';
import { useAuthStore } from '@/stores/auth';
import { useConsentStore } from '@/stores/consent';
import { useProfileStore } from '@/stores/profile';
import {
    IDENTITY_LABELS,
    KIND_LABELS,
    serviceHosts,
    type SessionTrace,
    useServiceSessionsStore
} from '@/stores/service-sessions';
import { useSessionsStore } from '@/stores/sessions';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

function appName(rpId: string): string {
    const dot = rpId.indexOf('.');
    return dot > 0 ? rpId.substring(0, dot) : rpId;
}

function formatWhen(ms: number): string {
    return new Date(ms).toLocaleDateString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function shortHex(v?: string): string {
    if (!v) return '—';
    return v.length > 20 ? `${v.slice(0, 10)}…${v.slice(-6)}` : v;
}

export default function ServiceDetailScreen() {
    const router = useRouter();
    // `serviceKey` is the app identity; `rpId` kept for legacy deep links.
    const params = useLocalSearchParams<{ serviceKey?: string; rpId?: string }>();
    const serviceKey = params.serviceKey || params.rpId || '';
    const insets = useSafeAreaInsets();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);

    const { apps, remove: removeTrustedApp } = useTrustedAppsStore();
    const { removeCredential, credentials } = useAuthStore();
    const sessions = useSessionsStore((s) => s.sessions);
    const allTraces = useServiceSessionsStore((s) => s.traces);
    const removeService = useServiceSessionsStore((s) => s.removeService);

    const traces = useMemo(
        () => allTraces.filter((t) => t.serviceKey === serviceKey),
        [allTraces, serviceKey]
    );
    const latest: SessionTrace | undefined = traces[0];
    const hosts = useMemo(() => {
        const h = serviceHosts(traces);
        if (serviceKey) h.add(serviceKey);
        return h;
    }, [traces, serviceKey]);

    // Legacy trusted-app row backing this card (attestation continuity), and
    // the credential used by this app's ceremonies.
    const app = apps.find((a) => hosts.has(a.rpId));
    const credential = credentials.find((c) =>
        latest ? c.rpId === latest.rpId : c.rpId === serviceKey
    );
    const session = sessions.find((s) => hosts.has(s.rpId) && s.expiresAt > Date.now());

    // Latest attestation snapshot: prefer the trace trail, fall back to the
    // legacy trusted-app row for pre-trail installs.
    const latestAtt = traces.find((t) => t.attestations?.length)?.attestations?.[0];
    const teeType = latestAtt?.teeType ?? app?.teeType ?? 'none';

    // "What have I shared with this app" at a glance: the latest ceremony
    // that shared anything. Pre-trace installs fall back to the consent
    // records (keyed per client, like serviceKey) with live profile values.
    const records = useConsentStore((s) => s.records);
    const profile = useProfileStore((s) => s.profile);
    const lastSharedTrace = traces.find((t) => (t.sharedAttributes?.length ?? 0) > 0);
    const legacyShared = !lastSharedTrace
        ? records.find(
              (r) =>
                  r.approvedAttributes.length > 0 &&
                  (r.rpId === serviceKey ||
                      r.origin === serviceKey ||
                      (app && (r.origin === app.rpId || r.appName === app.appName)))
          )
        : undefined;

    const name = latest?.displayName ?? app?.appName ?? appName(serviceKey);
    const primaryHost = latest?.appHost ?? latest?.rpId ?? app?.rpId ?? serviceKey;

    const [removing, setRemoving] = useState(false);
    const [signingOut, setSigningOut] = useState(false);
    const [expandedId, setExpandedId] = useState<string | null>(null);

    // Release provenance for the RUNNING app (its live /attest carries os_release
    // + workload_release with server-computed digest/measurement match), so the
    // user can see which published build this app is running and open the code.
    const runningAppId = latestAtt?.appId;
    const [releases, setReleases] = useState<{
        os?: OsRelease;
        workload?: WorkloadRelease;
    } | null>(null);
    useEffect(() => {
        if (!runningAppId) {
            setReleases(null);
            return;
        }
        let cancelled = false;
        void fetchRunningAppReleases(runningAppId, primaryHost).then((r) => {
            if (!cancelled && r) setReleases({ os: r.os_release, workload: r.workload_release });
        });
        return () => {
            cancelled = true;
        };
    }, [runningAppId, primaryHost]);

    // Server-side sign-out: revoke every IdP session issued to THIS app
    // (client_id-keyed rows), so its tokens stop working immediately — the
    // "lost a browser" case. Authenticates with the same credential this
    // app's ceremonies used, so the sessions listed/revoked are guaranteed to
    // belong to the identity that actually signed in here. Only offered when
    // both the client identity and the credential are known.
    const clientId = latest?.clientId;
    const handleServerSignOut = () => {
        if (!clientId || !credential) return;
        Alert.alert(
            'Sign out from server',
            `Revoke every server session for ${name}? Browsers and agents using them will need to sign in again.`,
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Sign out',
                    style: 'destructive',
                    onPress: async () => {
                        setSigningOut(true);
                        try {
                            const auth = await fido2.authenticate(
                                credential.rpId,
                                credential.keyAlias,
                                credential.credentialId,
                                '', // no browser relay — wallet-only session
                                credential.serverRpId
                            );
                            if (!auth.sessionToken) {
                                throw new Error('authentication did not return a session');
                            }
                            const sessions = await listMySessions(auth.sessionToken);
                            const mine = sessions.filter((s) => s.client_id === clientId);
                            for (const s of mine) {
                                await revokeSession(auth.sessionToken, s.sid);
                            }
                            Alert.alert(
                                'Signed out',
                                mine.length === 0
                                    ? 'No active server sessions for this app.'
                                    : `${mine.length} server session${mine.length !== 1 ? 's' : ''} revoked. Issued tokens stop working within a minute.`
                            );
                        } catch (e) {
                            Alert.alert(
                                'Sign out failed',
                                e instanceof Error ? e.message : 'Could not revoke the sessions.'
                            );
                        } finally {
                            setSigningOut(false);
                        }
                    }
                }
            ]
        );
    };

    const handleRemove = () => {
        Alert.alert(
            'Remove Service',
            `Disconnect from ${name}? You will need to scan the QR code again to reconnect.`,
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Remove',
                    style: 'destructive',
                    onPress: async () => {
                        setRemoving(true);
                        // Drop this app's trail + standing consent.
                        removeService(serviceKey);
                        useConsentStore.getState().removeStandingConsent(serviceKey);
                        // The passkey credential and the trust row can be shared
                        // with OTHER apps (every IdP-brokered client rides the
                        // privasys.id rpId + one credential) — only remove them
                        // when no other app still uses them.
                        const otherTraces = useServiceSessionsStore
                            .getState()
                            .traces.filter((t) => t.serviceKey !== serviceKey);
                        const otherHosts = serviceHosts(otherTraces);
                        if (credential && !otherHosts.has(credential.rpId)) {
                            removeCredential(credential.credentialId);
                        }
                        if (app && !otherHosts.has(app.rpId)) {
                            removeTrustedApp(app.rpId);
                        }
                        router.replace('/(tabs)');
                    }
                }
            ]
        );
    };

    if (!latest && !app) {
        return (
            <>
                <Stack.Screen options={{ headerShown: false }} />
                <RNView style={[styles.screen, { paddingTop: insets.top }]}>
                    <Text style={styles.notFound}>Service not found</Text>
                    <Pressable style={styles.backButton} onPress={() => router.back()}>
                        <Text style={styles.backButtonText}>Go back</Text>
                    </Pressable>
                </RNView>
            </>
        );
    }

    const headerMeta = latest
        ? `${KIND_LABELS[latest.kind]} · ${IDENTITY_LABELS[latest.identity]}`
        : `${teeType === 'none' ? 'Passkey' : teeType.toUpperCase()} · Connected ${
              app ? new Date(app.lastVerified * 1000).toLocaleDateString() : ''
          }`;

    return (
        <>
            <Stack.Screen options={{ headerShown: false }} />
            <RNView style={styles.screen}>
                {/* Header */}
                <RNView style={[styles.header, { paddingTop: insets.top + 12 }]}>
                    <Pressable onPress={() => router.back()} style={styles.backArrow}>
                        <Ionicons name="chevron-back" size={24} color="#FFFFFF" />
                    </Pressable>
                    <Text style={styles.headerTitle}>Service Details</Text>
                    <RNView style={{ width: 36 }} />
                </RNView>

                <ScrollView contentContainerStyle={styles.content}>
                    {/* Service icon + name */}
                    <RNView style={styles.serviceHeader}>
                        <RNView
                            style={[
                                styles.serviceIcon,
                                {
                                    backgroundColor:
                                        teeType === 'sgx'
                                            ? p.green
                                            : teeType === 'tdx'
                                              ? p.blue
                                              : '#8B5CF6'
                                }
                            ]}
                        >
                            <Ionicons
                                name={
                                    teeType === 'sgx'
                                        ? 'lock-closed'
                                        : teeType === 'tdx'
                                          ? 'shield-checkmark'
                                          : 'key'
                                }
                                size={28}
                                color="#FFFFFF"
                            />
                        </RNView>
                        <Text style={styles.serviceName}>{name}</Text>
                        <Text style={styles.serviceOrigin}>{primaryHost}</Text>
                        <Text style={styles.serviceMeta}>{headerMeta}</Text>
                    </RNView>

                    {/* Live sealed session */}
                    {session && (
                        <RNView style={styles.card}>
                            <RNView style={styles.cardTitleRow}>
                                <Text style={styles.cardTitle}>Sealed Session</Text>
                                <RNView style={styles.sealedBadge}>
                                    <RNView style={styles.sealedDot} />
                                    <Text style={styles.sealedText}>Active</Text>
                                </RNView>
                            </RNView>
                            <DetailRow label="Transport" value="AES-256-GCM (sealed CBOR)" />
                            <DetailRow label="Session ID" value={session.sessionId} mono />
                            <DetailRow label="Started" value={new Date(session.startedAt).toLocaleString()} />
                            <DetailRow label="Expires" value={new Date(session.expiresAt).toLocaleString()} />
                        </RNView>
                    )}

                    {/* Latest attestation */}
                    <RNView style={styles.card}>
                        <Text style={styles.cardTitle}>
                            {teeType === 'none' ? 'Connection' : 'Attestation'}
                        </Text>
                        <DetailRow
                            label="Type"
                            value={teeType === 'none' ? 'Passkey (no enclave)' : teeType.toUpperCase()}
                        />
                        {latestAtt ? (
                            <>
                                <DetailRow label="Enclave" value={latestAtt.host} />
                                {latestAtt.mrenclave && <DetailRow label="MRENCLAVE" value={latestAtt.mrenclave} mono />}
                                {latestAtt.mrtd && <DetailRow label="MRTD" value={latestAtt.mrtd} mono />}
                                {latestAtt.codeHash && <DetailRow label="Code Hash" value={latestAtt.codeHash} mono />}
                                {latestAtt.configRoot && <DetailRow label="Config Root" value={latestAtt.configRoot} mono />}
                                {latestAtt.imageRef && <DetailRow label="Image" value={latestAtt.imageRef} />}
                                <DetailRow label="Verified" value={new Date(latestAtt.verifiedAt).toLocaleString()} />
                            </>
                        ) : app ? (
                            <>
                                {app.mrenclave && <DetailRow label="MRENCLAVE" value={app.mrenclave} mono />}
                                {app.mrtd && <DetailRow label="MRTD" value={app.mrtd} mono />}
                                {app.codeHash && <DetailRow label="Code Hash" value={app.codeHash} mono />}
                                {app.configRoot && <DetailRow label="Config Root" value={app.configRoot} mono />}
                                <DetailRow label="Origin" value={app.origin} />
                            </>
                        ) : null}
                        {credential && (
                            <DetailRow
                                label="Registered"
                                value={new Date(credential.registeredAt * 1000).toLocaleDateString()}
                            />
                        )}
                    </RNView>

                    {/* Code provenance — which published build this app is
                        currently running (server-computed digest / measurement
                        match), with links to the release and the source. */}
                    {releases && (releases.workload?.url || releases.os?.url) && (
                        <RNView style={styles.card}>
                            <Text style={styles.cardTitle}>Code provenance</Text>
                            {releases.workload?.url ? (
                                <ReleaseLink
                                    label="App release"
                                    value={releases.workload.label ?? 'View'}
                                    url={releases.workload.url}
                                    match={releases.workload.matches}
                                />
                            ) : null}
                            {releases.os?.url ? (
                                <ReleaseLink
                                    label="Enclave OS"
                                    value={releases.os.tag ?? 'View'}
                                    url={releases.os.url}
                                    match={
                                        releases.os.status === 'verified'
                                            ? true
                                            : releases.os.status === 'mismatch'
                                              ? false
                                              : undefined
                                    }
                                />
                            ) : null}
                            <Text style={styles.provNote}>Verified by Privasys against the published release.</Text>
                        </RNView>
                    )}

                    {/* Shared attributes — the most recent share, at a glance
                        (the per-session breakdown lives in the trail below). */}
                    {(lastSharedTrace || legacyShared) && (
                        <RNView style={styles.card}>
                            <RNView style={styles.cardTitleRow}>
                                <Text style={styles.cardTitle}>Shared attributes</Text>
                                <Text style={styles.traceCount}>
                                    {formatWhen(
                                        lastSharedTrace
                                            ? lastSharedTrace.startedAt
                                            : legacyShared!.consentedAt * 1000
                                    )}
                                </Text>
                            </RNView>
                            {lastSharedTrace
                                ? lastSharedTrace.sharedAttributes!.map((s) => (
                                      <SharedAttributeRow
                                          key={s.key}
                                          label={ATTRIBUTE_MAP[s.key] ? attributeLabel(s.key) : s.key}
                                          value={s.gov ? 'Verified proof (raw value not shared)' : (s.value ?? '—')}
                                          gov={!!s.gov}
                                      />
                                  ))
                                : legacyShared!.approvedAttributes.map((key) => {
                                      const gov = !!ATTRIBUTE_MAP[key]?.identityVerifiable;
                                      return (
                                          <SharedAttributeRow
                                              key={key}
                                              label={attributeLabel(key)}
                                              value={
                                                  gov
                                                      ? 'Verified proof'
                                                      : (profile && getProfileValue(profile, key)) || '—'
                                              }
                                              gov={gov}
                                          />
                                      );
                                  })}
                        </RNView>
                    )}

                    {/* Session trail — every ceremony for this app. */}
                    {traces.length > 0 && (
                        <RNView style={styles.card}>
                            <RNView style={styles.cardTitleRow}>
                                <Text style={styles.cardTitle}>Sessions</Text>
                                <Text style={styles.traceCount}>{traces.length}</Text>
                            </RNView>
                            {traces.map((t) => (
                                <TraceRow
                                    key={t.id}
                                    trace={t}
                                    expanded={expandedId === t.id}
                                    onToggle={() => setExpandedId(expandedId === t.id ? null : t.id)}
                                />
                            ))}
                        </RNView>
                    )}

                    {/* Sign out from server (per-app token revocation) */}
                    {clientId && credential && (
                        <Pressable
                            style={[styles.signOutButton, signingOut && styles.removeButtonDisabled]}
                            onPress={handleServerSignOut}
                            disabled={signingOut}
                        >
                            <Ionicons name="log-out-outline" size={18} color={p.infoText} />
                            <Text style={styles.signOutButtonText}>
                                {signingOut ? 'Signing out…' : 'Sign Out from Server'}
                            </Text>
                        </Pressable>
                    )}

                    {/* Remove */}
                    <Pressable
                        style={[styles.removeButton, removing && styles.removeButtonDisabled]}
                        onPress={handleRemove}
                        disabled={removing}
                    >
                        <Ionicons name="trash-outline" size={18} color={p.danger} />
                        <Text style={styles.removeButtonText}>Remove Service</Text>
                    </Pressable>
                </ScrollView>
            </RNView>
        </>
    );
}

/** One ceremony in the trail: collapsed = one line (kind + when); expanded =
 *  the full audit record for that session. */
function TraceRow({
    trace,
    expanded,
    onToggle
}: {
    trace: SessionTrace;
    expanded: boolean;
    onToggle: () => void;
}) {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const shared = trace.sharedAttributes ?? [];
    const denied = trace.deniedAttributes ?? [];
    return (
        <RNView style={styles.traceRow}>
            <Pressable style={styles.traceHeader} onPress={onToggle}>
                <RNView style={styles.traceInfo}>
                    <Text style={styles.traceKind}>{KIND_LABELS[trace.kind]}</Text>
                    <Text style={styles.traceWhen}>{formatWhen(trace.startedAt)}</Text>
                </RNView>
                <RNView style={styles.traceRight}>
                    {shared.length > 0 && (
                        <Text style={styles.traceShared}>
                            {shared.length} shared
                        </Text>
                    )}
                    <Ionicons
                        name={expanded ? 'chevron-up' : 'chevron-down'}
                        size={16}
                        color={p.textMuted}
                    />
                </RNView>
            </Pressable>
            {expanded && (
                <RNView style={styles.traceBody}>
                    {trace.requestedBy && (
                        <Text style={styles.traceAgent}>
                            Requested by “{trace.requestedBy}” (unverified label)
                        </Text>
                    )}
                    {trace.detail && <Text style={styles.traceDetail}>{trace.detail}</Text>}
                    <DetailRow label="Identity" value={IDENTITY_LABELS[trace.identity]} />
                    {trace.channel && (
                        <DetailRow label="Via" value={trace.channel === 'qr' ? 'QR scan' : 'Push notification'} />
                    )}
                    <DetailRow label="Signed in" value={new Date(trace.startedAt).toLocaleString()} />
                    {trace.expiresAt ? (
                        <DetailRow
                            label={trace.expiresAt > Date.now() ? 'Session expires' : 'Session expired'}
                            value={new Date(trace.expiresAt).toLocaleString()}
                        />
                    ) : trace.oneShot ? (
                        <DetailRow label="Session" value="One-time (completed on approval)" />
                    ) : null}
                    {trace.requestedAttributes && trace.requestedAttributes.length > 0 && (
                        <DetailRow
                            label="Requested"
                            value={trace.requestedAttributes.map((k) => attributeLabel(k)).join(', ')}
                        />
                    )}
                    {shared.length > 0 && (
                        <RNView style={styles.sharedBlock}>
                            <Text style={styles.sharedBlockTitle}>Shared with this session</Text>
                            {shared.map((s) => (
                                <RNView key={s.key} style={styles.sharedRow}>
                                    <RNView style={styles.sharedInfo}>
                                        <Text style={styles.sharedLabel}>
                                            {ATTRIBUTE_MAP[s.key] ? attributeLabel(s.key) : s.key}
                                        </Text>
                                        <Text style={styles.sharedValue} numberOfLines={1}>
                                            {s.gov ? 'Verified proof (raw value not shared)' : (s.value ?? '—')}
                                        </Text>
                                    </RNView>
                                    {s.gov && (
                                        <RNView style={styles.verifiedBadge}>
                                            <Ionicons name="shield-checkmark" size={12} color={p.infoText} />
                                            <Text style={styles.verifiedText}>Proof</Text>
                                        </RNView>
                                    )}
                                </RNView>
                            ))}
                        </RNView>
                    )}
                    {denied.length > 0 && (
                        <DetailRow
                            label="Not shared"
                            value={denied.map((k) => attributeLabel(k)).join(', ')}
                        />
                    )}
                    {(trace.attestations ?? []).map((a) => (
                        <RNView key={`${a.host}-${a.verifiedAt}`} style={styles.attBlock}>
                            <Text style={styles.sharedBlockTitle}>Enclave · {a.host}</Text>
                            <DetailRow label="TEE" value={a.teeType.toUpperCase()} />
                            {a.mrenclave && <DetailRow label="MRENCLAVE" value={shortHex(a.mrenclave)} mono />}
                            {a.mrtd && <DetailRow label="MRTD" value={shortHex(a.mrtd)} mono />}
                            {a.codeHash && <DetailRow label="Code Hash" value={shortHex(a.codeHash)} mono />}
                            <DetailRow label="Verified" value={new Date(a.verifiedAt).toLocaleString()} />
                        </RNView>
                    ))}
                </RNView>
            )}
        </RNView>
    );
}

function SharedAttributeRow({ label, value, gov }: { label: string; value: string; gov: boolean }) {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    return (
        <RNView style={styles.sharedRow}>
            <RNView style={styles.sharedInfo}>
                <Text style={styles.sharedLabel}>{label}</Text>
                <Text style={styles.sharedValue} numberOfLines={1}>
                    {value}
                </Text>
            </RNView>
            {gov && (
                <RNView style={styles.verifiedBadge}>
                    <Ionicons name="shield-checkmark" size={12} color={p.infoText} />
                    <Text style={styles.verifiedText}>Proof</Text>
                </RNView>
            )}
        </RNView>
    );
}

/** A release/source link with an optional server-computed match badge. */
function ReleaseLink({
    label,
    value,
    url,
    match
}: {
    label: string;
    value: string;
    url: string;
    match?: boolean;
}) {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    return (
        <Pressable style={styles.detailRow} onPress={() => void Linking.openURL(url)}>
            <Text style={styles.detailLabel}>{label}</Text>
            <RNView style={styles.provValueWrap}>
                {match === true ? (
                    <Ionicons name="checkmark-circle" size={14} color={p.infoText} />
                ) : match === false ? (
                    <Ionicons name="alert-circle" size={14} color={p.danger} />
                ) : null}
                <Text style={styles.provLink} numberOfLines={1}>
                    {value}
                </Text>
                <Ionicons name="open-outline" size={13} color={p.infoText} />
            </RNView>
        </Pressable>
    );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    return (
        <RNView style={styles.detailRow}>
            <Text style={styles.detailLabel}>{label}</Text>
            <Text style={[styles.detailValue, mono && styles.mono]} selectable numberOfLines={2}>
                {value}
            </Text>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    header: {
        backgroundColor: p.green,
        paddingHorizontal: 16,
        paddingBottom: 16,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderBottomLeftRadius: 28,
        borderBottomRightRadius: 28
    },
    backArrow: {
        width: 36,
        height: 36,
        borderRadius: 18,
        backgroundColor: 'rgba(255,255,255,0.2)',
        alignItems: 'center',
        justifyContent: 'center'
    },
    headerTitle: {
        fontSize: 17,
        fontWeight: '600',
        color: '#FFFFFF'
    },
    content: { padding: 20, paddingTop: 32 },
    serviceHeader: { alignItems: 'center', marginBottom: 28 },
    serviceIcon: {
        width: 56,
        height: 56,
        borderRadius: 16,
        alignItems: 'center',
        justifyContent: 'center',
        marginBottom: 12
    },
    serviceName: {
        fontSize: 20,
        fontWeight: '700',
        color: p.textPrimary,
        textAlign: 'center',
        marginBottom: 2
    },
    serviceOrigin: {
        fontSize: 12,
        color: p.textMuted,
        textAlign: 'center',
        fontFamily: 'Inter',
        marginBottom: 4
    },
    serviceMeta: { fontSize: 13, color: p.textSecondary },
    card: {
        backgroundColor: p.card,
        borderRadius: 16,
        padding: 16,
        marginBottom: 24,
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.06,
        shadowRadius: 8,
        elevation: 2
    },
    cardTitle: {
        fontSize: 14,
        fontWeight: '700',
        color: p.textSecondary,
        letterSpacing: 0.5,
        marginBottom: 12
    },
    cardTitleRow: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 12
    },
    traceCount: { fontSize: 12, fontWeight: '700', color: p.textMuted },
    traceRow: {
        borderTopWidth: 0.5,
        borderTopColor: p.cardAlt
    },
    traceHeader: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingVertical: 12
    },
    traceInfo: { flex: 1 },
    traceKind: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
    traceWhen: { fontSize: 12, color: p.textMuted, marginTop: 1 },
    traceRight: { flexDirection: 'row', alignItems: 'center', gap: 8 },
    traceShared: { fontSize: 12, fontWeight: '600', color: p.infoText },
    traceBody: { paddingBottom: 12 },
    traceAgent: {
        fontSize: 13,
        color: p.warnText,
        backgroundColor: p.warnBg,
        borderRadius: 8,
        paddingVertical: 8,
        paddingHorizontal: 10,
        marginBottom: 8
    },
    traceDetail: { fontSize: 13, color: p.textSecondary, marginBottom: 8 },
    sharedBlock: { marginTop: 8 },
    sharedBlockTitle: {
        fontSize: 12,
        fontWeight: '700',
        color: p.textMuted,
        letterSpacing: 0.4,
        textTransform: 'uppercase',
        marginBottom: 4
    },
    attBlock: { marginTop: 10 },
    sealedBadge: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 6,
        backgroundColor: p.successBg,
        paddingHorizontal: 8,
        paddingVertical: 3,
        borderRadius: 10
    },
    sealedDot: {
        width: 6,
        height: 6,
        borderRadius: 3,
        backgroundColor: p.green
    },
    sealedText: {
        fontSize: 11,
        fontWeight: '600',
        color: p.successText
    },
    sharedRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 10,
        paddingVertical: 8,
        borderTopWidth: 0.5,
        borderTopColor: p.cardAlt
    },
    sharedInfo: { flex: 1 },
    sharedLabel: { fontSize: 14, fontWeight: '600', color: p.textPrimary },
    sharedValue: { fontSize: 13, color: p.textSecondary, marginTop: 1 },
    verifiedBadge: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 4,
        backgroundColor: p.infoBg,
        borderRadius: 8,
        paddingVertical: 4,
        paddingHorizontal: 8
    },
    verifiedText: { fontSize: 11, fontWeight: '700', color: p.infoText },
    detailRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        paddingVertical: 10,
        borderBottomWidth: StyleSheet.hairlineWidth,
        borderBottomColor: p.border
    },
    detailLabel: { fontSize: 13, color: p.textSecondary, flex: 1 },
    detailValue: { fontSize: 13, color: p.textPrimary, flex: 2, textAlign: 'right' },
    mono: { fontFamily: 'Inter' },
    provValueWrap: { flexDirection: 'row', alignItems: 'center', gap: 5, flex: 2, justifyContent: 'flex-end' },
    provLink: { fontSize: 13, fontWeight: '600', color: p.infoText, flexShrink: 1 },
    provNote: { fontSize: 11, color: p.textMuted, marginTop: 8 },
    signOutButton: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        backgroundColor: p.card,
        borderRadius: 12,
        paddingVertical: 14,
        borderWidth: 1,
        borderColor: p.infoText,
        marginBottom: 12
    },
    signOutButtonText: { fontSize: 16, fontWeight: '600', color: p.infoText },
    removeButton: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        backgroundColor: p.card,
        borderRadius: 12,
        paddingVertical: 14,
        borderWidth: 1,
        borderColor: p.danger
    },
    removeButtonDisabled: { opacity: 0.5 },
    removeButtonText: { fontSize: 16, fontWeight: '600', color: p.danger },
    notFound: { fontSize: 18, textAlign: 'center', marginTop: 100, color: p.textSecondary },
    backButton: {
        alignSelf: 'center',
        marginTop: 20,
        backgroundColor: p.action,
        borderRadius: 12,
        paddingHorizontal: 24,
        paddingVertical: 12
    },
    backButtonText: { color: '#fff', fontSize: 16, fontWeight: '600' }
});
