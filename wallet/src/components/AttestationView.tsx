// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Enclave attestation viewer — the "Verify Enclave" screen the user sees during
 * every sign-in ceremony (RA-TLS attestation result + full TEE properties, with
 * Approve / Reject). Shared so other flows that send data to an enclave (e.g. the
 * KYC identity-verifier flow) present the *same* familiar verification step.
 */

import { useMemo, useState } from 'react';
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { ExternalLink } from '@/components/ExternalLink';
import { Text, View, usePalette, type Palette } from '@/components/Themed';
import type { AttestationDiff } from '@/services/attestation-diff';
import type { OsRelease, WorkloadRelease } from '@/services/release-provenance';
import type { AttestationResult } from '../../modules/native-ratls/src/NativeRaTls.types';

/**
 * The outcome of the enclave verification the screen is showing, so the view
 * can render the right recovery UX:
 *  - `verified`   — trusted; normal Approve/Reject.
 *  - `unreachable`— the attestation service could not be reached (no verdict).
 *    We offer a plain "Continue anyway", since this is an availability issue.
 *  - `invalid`    — a definite bad verdict (bad quote, or the service rejected
 *    it). We show the problem and bury the override in an "Advanced" section,
 *    like a browser's invalid-certificate "proceed anyway".
 *  - `error`      — could not reach/handshake the enclave; nothing to proceed to.
 */
export interface VerificationState {
    status: 'verified' | 'unreachable' | 'invalid' | 'error';
    mode: 'deterministic' | 'challenge';
    /** True when a fresh nonce + TLS channel binder were folded in this run. */
    challenged: boolean;
    /** Human-readable problem, for the non-verified states. */
    message?: string;
}

/**
 * Why we trust the current attestation.
 *
 * - `fresh-as-verified`: just round-tripped to as.privasys.org with an
 *   App Attest-bound token. Highest assurance; required on first connect
 *   to a new enclave and periodically after that.
 * - `cached-trusted`: the cert measurements match a previously-verified
 *   record in the trusted-apps store and the cache is still within TTL.
 *   We did not re-contact the attestation server.
 * - `non-enclave`: the cert carried no TEE measurements (e.g. github.com
 *   behind a Let's Encrypt cert). The wallet supports FIDO2 sign-in to
 *   non-enclave RPs; attestation simply does not apply.
 */
export type AttestationVerificationLevel =
    | 'fresh-as-verified'
    | 'cached-trusted'
    | 'non-enclave';

const CHANGED_TITLES: Record<AttestationDiff['kind'], string> = {
    'app-update': 'App Updated',
    'platform-update': 'Platform Updated',
    'app-and-platform-update': 'App & Platform Changed',
};

export function AttestationView({
    attestation,
    rpId,
    displayName,
    isChanged,
    diff,
    verificationLevel,
    verification,
    releases,
    dependencies,
    onApprove,
    onReject,
    onChallenge,
    challengeInFlight,
}: {
    attestation: AttestationResult;
    rpId: string;
    /** Human-readable app name shown above the origin (caller-derived). */
    displayName: string;
    isChanged: boolean;
    /**
     * Field-level change breakdown vs the trusted record (attestation-changed
     * step only). Drives the kind-specific title, the summary sentence and the
     * "What changed" card; without it the changed state falls back to the
     * generic warning.
     */
    diff?: AttestationDiff | null;
    verificationLevel: AttestationVerificationLevel | null;
    /**
     * The verification outcome, driving the status banner and recovery UX. When
     * omitted the screen falls back to `attestation.valid` (legacy behaviour).
     */
    verification?: VerificationState;
    /**
     * Published-release links (mgmt release provenance) so the user can review
     * the actual code behind the measurements before approving — the app's
     * GitHub release and, for platform changes, the enclave-OS release.
     */
    releases?: { workload?: WorkloadRelease; os?: OsRelease } | null;
    /**
     * Attested cross-enclave dependencies this app declares (OID 6.1). Shown so
     * the user sees what the app pulls in before approving. `published` is the
     * transparency-log gate; `status` reflects the approval cache
     * (approved/denied/new).
     */
    dependencies?: Array<{ name: string; label?: string; url?: string; status: string; published: boolean }>;
    onApprove: () => void;
    onReject: () => void;
    /** When provided (deterministic mode), shows a "Challenge this enclave"
     *  button that forces a fresh challenge-mode re-verification. */
    onChallenge?: () => void;
    /** True while a challenge re-verification is in flight. */
    challengeInFlight?: boolean;
}) {
    const [detailsOpen, setDetailsOpen] = useState(false);
    const [advancedOpen, setAdvancedOpen] = useState(false);
    const insets = useSafeAreaInsets();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const appType = attestation.tee_type === 'sgx' ? 'WASM Application' : 'Container Application';
    const teeColor = attestation.tee_type === 'sgx' ? p.green : p.blue;
    const changedTitle = (diff && CHANGED_TITLES[diff.kind]) || 'App Changed';

    // Effective verification status. When no `verification` is supplied we keep
    // the legacy behaviour driven by the parsed cert's `valid` flag.
    const status: VerificationState['status'] =
        verification?.status ?? (attestation.valid ? 'verified' : 'invalid');
    const isVerified = status === 'verified';
    const isUnreachable = status === 'unreachable';
    const isInvalid = status === 'invalid' || status === 'error';
    // The challenge button only makes sense in deterministic mode on a result we
    // could actually verify — challenging an already-challenged or unverifiable
    // enclave has nothing to add.
    const showChallenge =
        !!onChallenge &&
        isVerified &&
        !verification?.challenged &&
        (verification?.mode ?? 'deterministic') === 'deterministic';

    // How the current trust was established, folded into the status banner (a
    // separate badge just repeated "Attestation Valid" in different words).
    const provenanceLine = !isVerified
        ? null
        : verification?.challenged
            ? '⚡ Challenged just now and bound to this session'
            : verificationLevel === 'fresh-as-verified'
                ? 'Verified just now by as.privasys.org'
                : verificationLevel === 'cached-trusted'
                    ? 'Trusted from a recent verification on this device'
                    : null;

    return (
        // Paint the standard screen background ourselves: the hosting route may
        // sit on a themed (white) view, and the fixed bottom bar below shares
        // this exact colour — without this the bar reads as an off-white patch
        // between the buttons and around their border radius.
        <RNView style={{ flex: 1, backgroundColor: p.screenBg }}>
            <ScrollView contentContainerStyle={[styles.attestationContainer, { paddingBottom: 100 + insets.bottom }]}>
                {isChanged && (
                    <View style={styles.warningBanner}>
                        <Text style={styles.warningText}>
                            {diff
                                ? `⚠ ${diff.summary}`
                                : "⚠ This app's attestation has changed since you last verified it."}
                        </Text>
                    </View>
                )}

                <Text style={styles.title}>{isChanged ? changedTitle : 'Verify Enclave'}</Text>
                <Text style={styles.attestationAppName}>{displayName}</Text>
                <Text style={styles.attestationOrigin}>{rpId}</Text>

                {/* Verification Status */}
                <View
                    style={[
                        styles.statusBanner,
                        isVerified && styles.statusBannerValid,
                        isUnreachable && styles.statusBannerUnknown,
                        isInvalid && styles.statusBannerInvalid,
                    ]}
                >
                    <Text style={styles.statusIcon}>
                        {isVerified ? '✓' : isUnreachable ? '?' : '✕'}
                    </Text>
                    <View style={styles.statusInfo}>
                        <Text
                            style={[
                                styles.statusTitle,
                                isVerified && styles.statusTitleValid,
                                isUnreachable && styles.statusTitleUnknown,
                                isInvalid && styles.statusTitleInvalid,
                            ]}
                        >
                            {isVerified
                                ? 'Attestation Valid'
                                : isUnreachable
                                    ? 'Could Not Verify'
                                    : 'Attestation Invalid'}
                        </Text>
                        <Text style={styles.statusDetail}>
                            {appType} · {attestation.tee_type?.toUpperCase()} enclave
                        </Text>
                        {provenanceLine && (
                            <Text style={styles.statusProvenance}>{provenanceLine}</Text>
                        )}
                    </View>
                    <View style={[styles.teeBadge, { backgroundColor: teeColor }]}>
                        <Text style={styles.teeBadgeText}>{attestation.tee_type?.toUpperCase()}</Text>
                    </View>
                </View>

                {/* Unreachable — no verdict from the attestation service. This is
                    an availability issue, so we offer a plain continue. */}
                {isUnreachable && (
                    <View style={styles.unknownBanner}>
                        <Text style={styles.unknownText}>
                            We couldn&apos;t verify this enclave&apos;s quote with the attestation
                            service{verification?.message ? ` (${verification.message})` : ''}. You
                            can continue anyway, or cancel and try again.
                        </Text>
                    </View>
                )}

                {/* Invalid — a definite bad verdict. Show the problem plainly. The
                    override lives in the Advanced section below. */}
                {isInvalid && (
                    <View style={styles.problemBanner}>
                        <Text style={styles.problemTitle}>⚠ This enclave failed verification</Text>
                        {verification?.message ? (
                            <Text style={styles.problemDetail} selectable>{verification.message}</Text>
                        ) : null}
                        <Text style={styles.problemHint}>
                            Do not continue unless you understand and accept the risk.
                        </Text>
                    </View>
                )}

                {/* Challenge-this-enclave — deterministic mode only. Lets the user
                    demand a fresh liveness proof for this one connection. */}
                {showChallenge && (
                    <Pressable
                        style={styles.challengeButton}
                        onPress={onChallenge}
                        disabled={challengeInFlight}
                    >
                        {challengeInFlight ? (
                            <ActivityIndicator size="small" color={p.infoText} />
                        ) : (
                            <Text style={styles.challengeIcon}>⚡</Text>
                        )}
                        <Text style={styles.challengeText}>
                            {challengeInFlight ? 'Challenging…' : 'Challenge this enclave'}
                        </Text>
                    </Pressable>
                )}

                {/* What changed — always visible on the changed step, so the
                    user approves a specific, named change rather than a
                    generic warning. */}
                {isChanged && diff && diff.changes.length > 0 && (
                    <>
                        <Text style={styles.sectionHeader}>What Changed</Text>
                        <View style={styles.attestationCard}>
                            {diff.changes.map((c) => (
                                <View key={c.label} style={styles.changeRow}>
                                    <Text style={styles.changeLabel}>{c.label}</Text>
                                    <View style={styles.changeValues}>
                                        <Text style={styles.changeOld} selectable>
                                            {c.previous ? truncateHex(c.previous) : 'not recorded'}
                                        </Text>
                                        <Text style={styles.changeArrow}>→</Text>
                                        <Text style={styles.changeNew} selectable>
                                            {c.current ? truncateHex(c.current) : 'removed'}
                                        </Text>
                                    </View>
                                </View>
                            ))}
                        </View>
                    </>
                )}

                {/* Published release — the human-reviewable code behind the
                    measurements. On a change this is how the user actually
                    inspects what they are being asked to approve. */}
                {(releases?.workload?.url || releases?.os?.url) && (
                    <>
                        <Text style={styles.sectionHeader}>Published Release</Text>
                        <View style={styles.attestationCard}>
                            {releases?.workload?.url && (
                                <ExternalLink href={releases.workload.url}>
                                    <View style={styles.releaseRow}>
                                        <Text style={styles.releaseLabel}>
                                            Review the app code
                                            {releases.workload.label ? ` (${releases.workload.label})` : ''}
                                        </Text>
                                        <Text style={styles.releaseLink}>GitHub ↗</Text>
                                    </View>
                                </ExternalLink>
                            )}
                            {releases?.os?.url && (
                                <ExternalLink href={releases.os.url}>
                                    <View style={styles.releaseRow}>
                                        <Text style={styles.releaseLabel}>
                                            Review the enclave platform
                                            {releases.os.tag ? ` (${releases.os.tag})` : ''}
                                        </Text>
                                        <Text style={styles.releaseLink}>GitHub ↗</Text>
                                    </View>
                                </ExternalLink>
                            )}
                        </View>
                    </>
                )}

                {/* Attested cross-enclave dependencies — what this app pulls in.
                    Approving the app also approves these (cached and reused);
                    "verify" flags a build not resolvable to a published release. */}
                {dependencies && dependencies.length > 0 && (
                    <>
                        <Text style={styles.sectionHeader}>Depends on</Text>
                        <View style={styles.attestationCard}>
                            {dependencies.map((d, i) => {
                                const badge = !d.published
                                    ? 'verify'
                                    : d.status === 'approved'
                                      ? 'approved'
                                      : d.status === 'denied'
                                        ? 'denied before'
                                        : 'new';
                                const row = (
                                    <View style={styles.releaseRow}>
                                        <Text style={styles.releaseLabel}>
                                            {d.name}
                                            {d.label ? ` (${d.label})` : ''}
                                        </Text>
                                        <Text style={styles.releaseLink}>
                                            {d.url ? `${badge} ↗` : badge}
                                        </Text>
                                    </View>
                                );
                                return d.url ? (
                                    <ExternalLink key={i} href={d.url}>
                                        {row}
                                    </ExternalLink>
                                ) : (
                                    <View key={i}>{row}</View>
                                );
                            })}
                        </View>
                    </>
                )}

                {/* The change is the user's to accept: nudge them to actually
                    review it before approving, since everything above reads as
                    reassuring green. */}
                {isChanged && (
                    <Text style={styles.reviewPrompt}>
                        Please review the changes and approve only if you accept them.
                    </Text>
                )}

                {/* Collapsible details toggle */}
                <Pressable style={styles.detailsToggle} onPress={() => setDetailsOpen(!detailsOpen)}>
                    <Text style={styles.detailsToggleText}>
                        {detailsOpen ? 'Hide details' : 'Show attestation details'}
                    </Text>
                    <Text style={styles.detailsToggleIcon}>{detailsOpen ? '▲' : '▼'}</Text>
                </Pressable>

                {detailsOpen && (
                    <>
                        {/* Verification Details */}
                        {(attestation.quote_verification_status ||
                            attestation.attestation_servers_hash ||
                            attestation.workload_key_source) && (
                            <>
                                <Text style={styles.sectionHeader}>Verification</Text>
                                <View style={styles.attestationCard}>
                                    {attestation.quote_verification_status && (
                                        <AttestationRow label="Quote Status" value={attestation.quote_verification_status} />
                                    )}
                                    {attestation.attestation_servers_hash && (
                                        <AttestationRow label="Attestation Server" value={truncateHex(attestation.attestation_servers_hash)} />
                                    )}
                                    {attestation.workload_key_source && (
                                        <AttestationRow label="Key Source" value={attestation.workload_key_source} />
                                    )}
                                </View>
                            </>
                        )}

                        {/* Enclave Identity */}
                        <Text style={styles.sectionHeader}>Enclave Identity</Text>
                        <View style={styles.attestationCard}>
                            {attestation.mrenclave && (
                                <AttestationRow label="MRENCLAVE" value={truncateHex(attestation.mrenclave)} />
                            )}
                            {attestation.mrsigner && (
                                <AttestationRow label="MRSIGNER" value={truncateHex(attestation.mrsigner)} />
                            )}
                            {attestation.mrtd && <AttestationRow label="MRTD" value={truncateHex(attestation.mrtd)} />}
                            {attestation.workload_code_hash && (
                                <AttestationRow label="Code Hash" value={truncateHex(attestation.workload_code_hash)} />
                            )}
                            {attestation.workload_config_merkle_root && (
                                <AttestationRow label="Config Root" value={truncateHex(attestation.workload_config_merkle_root)} />
                            )}
                        </View>

                        {/* Certificate */}
                        <Text style={styles.sectionHeader}>Certificate</Text>
                        <View style={styles.attestationCard}>
                            <AttestationRow label="Subject" value={attestation.cert_subject} />
                            <AttestationRow label="Valid From" value={attestation.cert_not_before} />
                            <AttestationRow label="Valid Until" value={attestation.cert_not_after} />
                        </View>

                        {/* Advisory IDs */}
                        {attestation.advisory_ids && attestation.advisory_ids.length > 0 && (
                            <>
                                <Text style={styles.sectionHeader}>Advisories</Text>
                                <View style={styles.attestationCard}>
                                    {attestation.advisory_ids.map((id) => (
                                        <AttestationRow key={id} label={id} value="Known advisory" />
                                    ))}
                                </View>
                            </>
                        )}

                        {/* Custom OIDs */}
                        {attestation.custom_oids && attestation.custom_oids.length > 0 && (
                            <>
                                <Text style={styles.sectionHeader}>Custom Extensions</Text>
                                <View style={styles.attestationCard}>
                                    {attestation.custom_oids.map((oid) => (
                                        <AttestationRow key={oid.oid} label={oid.label || oid.oid} value={truncateHex(oid.value_hex)} />
                                    ))}
                                </View>
                            </>
                        )}
                    </>
                )}
            </ScrollView>

            {/* Fixed bottom action buttons. The proceed action adapts to the
                verification status: a normal Approve when verified, a plain
                Continue when the service was unreachable, and — when the verdict
                is a definite failure — an override buried behind Advanced. */}
            <RNView style={[styles.bottomActions, { paddingBottom: Math.max(insets.bottom, 20) }]}>
                {isInvalid && (
                    <>
                        <Pressable
                            style={styles.advancedToggle}
                            onPress={() => setAdvancedOpen((o) => !o)}
                        >
                            <Text style={styles.advancedToggleText}>Advanced</Text>
                            <Text style={styles.detailsToggleIcon}>{advancedOpen ? '▲' : '▼'}</Text>
                        </Pressable>
                        {advancedOpen && (
                            <View style={styles.advancedBox}>
                                <Text style={styles.advancedWarning}>
                                    Verification failed. Continuing sends your request to an enclave
                                    that could not prove its identity — its code and data may not be
                                    what they claim. Only proceed if you understand the risk.
                                </Text>
                                <Pressable style={styles.dangerButton} onPress={onApprove}>
                                    <Text style={styles.dangerButtonText}>Connect anyway</Text>
                                </Pressable>
                            </View>
                        )}
                    </>
                )}
                <View style={styles.buttonRow}>
                    <Pressable style={styles.rejectButton} onPress={onReject}>
                        <Text style={styles.rejectButtonText}>{isInvalid ? 'Cancel' : 'Reject'}</Text>
                    </Pressable>
                    {isUnreachable ? (
                        <Pressable style={styles.continueButton} onPress={onApprove}>
                            <Text style={styles.approveButtonText}>Continue anyway</Text>
                        </Pressable>
                    ) : !isInvalid ? (
                        <Pressable style={styles.approveButton} onPress={onApprove}>
                            <Text style={styles.approveButtonText}>
                                {isChanged ? (diff ? 'Approve Changes' : 'Trust Anyway') : 'Approve'}
                            </Text>
                        </Pressable>
                    ) : null}
                </View>
            </RNView>
        </RNView>
    );
}

function AttestationRow({ label, value }: { label: string; value?: string }) {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    if (!value) return null;
    return (
        <View style={styles.attestationRow}>
            <Text style={styles.attestationLabel}>{label}</Text>
            <Text style={styles.attestationValue} selectable>
                {value}
            </Text>
        </View>
    );
}

export function truncateHex(hex: string): string {
    if (hex.length <= 16) return hex;
    return `${hex.slice(0, 8)}…${hex.slice(-8)}`;
}

const makeStyles = (p: Palette) => StyleSheet.create({
    attestationContainer: { padding: 20, paddingTop: 80 },
    title: { fontSize: 24, fontWeight: 'bold', textAlign: 'center', marginBottom: 8 },
    attestationAppName: { fontSize: 22, fontWeight: '700', textAlign: 'center', marginBottom: 4 },
    attestationOrigin: { fontSize: 12, color: p.textMuted, textAlign: 'center', fontFamily: 'Inter', marginBottom: 20 },
    detailsToggle: {
        flexDirection: 'row', alignItems: 'center', justifyContent: 'center', paddingVertical: 14,
        marginBottom: 8, borderRadius: 10, backgroundColor: p.buttonNeutral, gap: 8,
    },
    reviewPrompt: { fontSize: 14, color: p.textSecondary, textAlign: 'center', lineHeight: 20, marginTop: 4, marginBottom: 16 },
    detailsToggleText: { fontSize: 14, fontWeight: '500', color: p.textSecondary },
    detailsToggleIcon: { fontSize: 10, color: p.textMuted },
    bottomActions: {
        position: 'absolute', bottom: 0, left: 0, right: 0, paddingHorizontal: 20, paddingTop: 16,
        backgroundColor: p.screenBg, borderTopWidth: StyleSheet.hairlineWidth, borderTopColor: p.border,
    },
    warningBanner: { backgroundColor: p.warnBg, borderRadius: 8, padding: 12, marginBottom: 16 },
    warningText: { color: p.warnText, fontSize: 14, textAlign: 'center' },
    statusBanner: { flexDirection: 'row', alignItems: 'center', borderRadius: 12, padding: 16, marginBottom: 24, gap: 12 },
    statusBannerValid: { backgroundColor: p.successBg },
    statusBannerInvalid: { backgroundColor: p.dangerBg },
    statusBannerUnknown: { backgroundColor: p.warnBg },
    statusIcon: { fontSize: 28, fontWeight: '700' },
    statusInfo: { flex: 1, backgroundColor: 'transparent' },
    statusTitle: { fontSize: 16, fontWeight: '700' },
    statusTitleValid: { color: p.successText },
    statusTitleInvalid: { color: p.dangerText },
    statusTitleUnknown: { color: p.warnText },
    statusDetail: { fontSize: 13, color: p.textSecondary, marginTop: 2 },
    statusProvenance: { fontSize: 12, color: p.infoText, fontWeight: '500', marginTop: 4 },

    releaseRow: {
        flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between',
        paddingVertical: 10, backgroundColor: 'transparent',
    },
    releaseLabel: { fontSize: 14, color: p.textPrimary, flex: 1 },
    releaseLink: { fontSize: 14, fontWeight: '600', color: p.blue },

    // Unreachable (amber) — availability issue, plain continue.
    unknownBanner: { backgroundColor: p.warnBg, borderRadius: 12, borderWidth: 1, borderColor: p.warnBorder, padding: 14, marginBottom: 16 },
    unknownText: { fontSize: 14, color: p.warnText, lineHeight: 20 },

    // Invalid (red) — definite bad verdict, override buried in Advanced.
    problemBanner: { backgroundColor: p.dangerBg, borderRadius: 12, borderWidth: 1, borderColor: p.dangerBorder, padding: 14, marginBottom: 16, gap: 6 },
    problemTitle: { fontSize: 15, fontWeight: '700', color: p.dangerText },
    problemDetail: { fontSize: 12, fontFamily: 'Inter', color: p.dangerText, lineHeight: 18 },
    problemHint: { fontSize: 13, color: p.dangerText, marginTop: 2 },

    // Challenge affordances.
    challengeButton: {
        flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8,
        paddingVertical: 12, borderRadius: 10, marginBottom: 16,
        backgroundColor: p.infoBg, borderWidth: 1, borderColor: p.infoBorder,
    },
    challengeIcon: { fontSize: 15, color: p.infoText },
    challengeText: { fontSize: 14, fontWeight: '600', color: p.infoText },
    teeBadge: { paddingHorizontal: 10, paddingVertical: 4, borderRadius: 6 },
    teeBadgeText: { color: '#fff', fontSize: 12, fontWeight: '700', letterSpacing: 0.5 },
    sectionHeader: {
        fontSize: 13, fontWeight: '600', color: p.textMuted, textTransform: 'uppercase',
        letterSpacing: 0.5, marginBottom: 8, marginTop: 4,
    },
    attestationCard: { backgroundColor: p.card, borderRadius: 12, padding: 16, marginBottom: 16 },
    attestationRow: {
        flexDirection: 'row', justifyContent: 'space-between', paddingVertical: 8,
        borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: p.border, backgroundColor: 'transparent',
    },
    attestationLabel: { fontSize: 13, opacity: 0.6, flex: 1 },
    attestationValue: { fontSize: 13, fontFamily: 'Inter', flex: 2, textAlign: 'right' },
    changeRow: {
        paddingVertical: 8, borderBottomWidth: StyleSheet.hairlineWidth,
        borderBottomColor: p.border, backgroundColor: 'transparent',
    },
    changeLabel: { fontSize: 13, fontWeight: '600', marginBottom: 4 },
    changeValues: { flexDirection: 'row', alignItems: 'center', gap: 6, backgroundColor: 'transparent' },
    changeOld: { fontSize: 12, fontFamily: 'Inter', color: p.textMuted, textDecorationLine: 'line-through' },
    changeArrow: { fontSize: 12, color: p.textSecondary },
    changeNew: { fontSize: 12, fontFamily: 'Inter', fontWeight: '600' },
    buttonRow: { flexDirection: 'row', justifyContent: 'space-between', gap: 12 },
    approveButton: { flex: 1, backgroundColor: p.approve, borderRadius: 12, paddingVertical: 14, alignItems: 'center' },
    approveButtonText: { color: '#fff', fontSize: 17, fontWeight: '600' },
    continueButton: { flex: 1, backgroundColor: '#D99A00', borderRadius: 12, paddingVertical: 14, alignItems: 'center' },
    rejectButton: { flex: 1, backgroundColor: p.buttonNeutral, borderRadius: 12, paddingVertical: 14, alignItems: 'center' },
    rejectButtonText: { fontSize: 17, fontWeight: '600' },

    // Advanced (browser invalid-SSL style) override for a failed verdict.
    advancedToggle: {
        flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 6,
        paddingVertical: 10, marginBottom: 8,
    },
    advancedToggleText: { fontSize: 14, fontWeight: '500', color: p.textMuted },
    advancedBox: {
        backgroundColor: p.dangerBg, borderRadius: 12, borderWidth: 1, borderColor: p.dangerBorder,
        padding: 14, marginBottom: 12, gap: 12,
    },
    advancedWarning: { fontSize: 13, color: p.dangerText, lineHeight: 19 },
    dangerButton: {
        backgroundColor: p.danger, borderRadius: 10, paddingVertical: 12, alignItems: 'center',
    },
    dangerButtonText: { color: '#fff', fontSize: 15, fontWeight: '700' },
});
