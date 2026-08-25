// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The approval screen: "Authentication request".
 *
 * Shown whenever the wallet is about to let an app in, and shared by every
 * flow that sends data to an enclave (sign-in, Drive, the KYC verifier) so all
 * of them present the same familiar step.
 *
 * STRUCTURE, which is the whole design:
 *
 *   header      "Authentication request", and nothing else. The situation,
 *               named, in the same green-and-white band every other screen in
 *               the wallet uses.
 *   the app     The ask as a sentence, then one card of properties (address,
 *               publisher, workload hash, source code, enclave) closed by the
 *               verdict row. The verdict sits INSIDE the card so it reads as a
 *               conclusion drawn over those facts rather than a badge stuck on
 *               top, and so that a failed verification changes one row instead
 *               of reshuffling the screen.
 *   your data   Only when attributes are requested. A checklist: required rows
 *               locked on, optional rows tickable.
 *   also uses   Declared cross-enclave dependencies.
 *   details     Everything else, EXPANDED. The action bar is fixed, so length
 *               costs nothing and a collapsed section would read as "we would
 *               rather you did not look".
 *
 * There is deliberately no app icon and no identity block. They cost about
 * eighty vertical pixels before the reader learns anything actionable, and the
 * app name is already carried in bold by the sentence. What could not be
 * dropped is the ADDRESS, which is the one field an impostor cannot fake, so
 * it is the first properties row, directly above the publisher.
 */

import { Ionicons } from '@expo/vector-icons';
import { useMemo, useState, type ReactNode } from 'react';
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { ExternalLink } from '@/components/ExternalLink';
import { Text, View, usePalette, type Palette } from '@/components/Themed';
import type { AttestationDiff } from '@/services/attestation-diff';
import type { OsRelease, WorkloadRelease } from '@/services/release-provenance';
import { sourceLabel, sourceUrl, type StoreListing } from '@/services/store-listing';
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

/** One row of the requested-data checklist. */
export interface AttributeRow {
    key: string;
    label: string;
    /** The relying party requires it: locked on, never tickable. */
    essential: boolean;
    /** The value that will actually be sent, when the wallet can resolve one. */
    preview?: string;
    /** Assurance or acquisition note, shown when there is no preview. */
    note?: string;
}

/** "Intel SGX" / "Intel TDX" are product names and stay verbatim everywhere. */
function teeLabel(teeType?: string): string | undefined {
    if (teeType === 'sgx') return 'Intel SGX';
    if (teeType === 'tdx') return 'Intel TDX';
    if (teeType === 'sev-snp') return 'AMD SEV-SNP';
    if (teeType === 'nvidia-gpu') return 'NVIDIA GPU CC';
    return undefined;
}

export function truncateHex(hex: string): string {
    if (hex.length <= 16) return hex;
    return `${hex.slice(0, 8)}…${hex.slice(-8)}`;
}

/** Date part of an X.509 timestamp, which is all a properties row has room for. */
function shortDate(value?: string): string | undefined {
    if (!value) return undefined;
    const t = Date.parse(value);
    if (Number.isNaN(t)) return value;
    return new Date(t).toISOString().slice(0, 10);
}

export function AttestationView({
    attestation,
    rpId,
    displayName,
    listing,
    isChanged,
    diff,
    verificationLevel,
    verification,
    releases,
    dependencies,
    attributes,
    onApprove,
    onReject,
    onChallenge,
    challengeInFlight,
}: {
    attestation: AttestationResult;
    rpId: string;
    /**
     * Human-readable app name. Undefined when nothing can name the app, which
     * is a real state: the sentence drops to "This app wants to sign you in"
     * rather than showing a DNS fragment dressed up as a name.
     */
    displayName?: string;
    /** Public store listing, when the app published one. */
    listing?: StoreListing | null;
    isChanged: boolean;
    /**
     * Field-level change breakdown vs the trusted record (attestation-changed
     * step only). Drives the kind-specific banner and the "What changed" card.
     */
    diff?: AttestationDiff | null;
    verificationLevel: AttestationVerificationLevel | null;
    verification?: VerificationState;
    /**
     * Published-release links (mgmt release provenance) so the user can review
     * the actual code behind the measurements before approving.
     */
    releases?: { workload?: WorkloadRelease; os?: OsRelease } | null;
    /**
     * Attested cross-enclave dependencies this app declares (OID 6.1).
     * `published` is the transparency-log gate; `status` reflects the approval
     * cache (approved/denied/new).
     */
    dependencies?: Array<{ name: string; label?: string; url?: string; status: string; published: boolean }>;
    /**
     * The requested-attribute checklist. Supplying this makes the approval
     * screen the consent gate for the ceremony, so the caller must NOT then
     * show a separate consent screen: that would ask the same question twice
     * and the second answer would be the one that counted.
     */
    attributes?: {
        /** App name used in the section's explanatory line. */
        appLabel: string;
        items: AttributeRow[];
        selected: Set<string>;
        onToggle: (key: string) => void;
    };
    onApprove: () => void;
    onReject: () => void;
    /** When provided (deterministic mode), offers a fresh challenge-mode run. */
    onChallenge?: () => void;
    challengeInFlight?: boolean;
}) {
    const { t } = useTranslation();
    const [advancedOpen, setAdvancedOpen] = useState(false);
    const insets = useSafeAreaInsets();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);

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
    // On an availability failure the same control is a plain retry: there is no
    // verdict to challenge, only a service that did not answer.
    const showRetry = !!onChallenge && isUnreachable;

    const hasAttributes = !!attributes && attributes.items.length > 0;
    const allRequired = hasAttributes && attributes!.items.every((i) => i.essential);

    // The ask. Four variants rather than a base sentence with an appended
    // clause: several languages want to restructure the whole sentence, and a
    // concatenation gives them nowhere to do it.
    const askKey = displayName
        ? hasAttributes ? 'attestation.asksSignInAndData' : 'attestation.asksSignIn'
        : hasAttributes ? 'attestation.asksSignInAndDataUnnamed' : 'attestation.asksSignInUnnamed';

    const workloadHash = attestation.workload_code_hash;
    const source = sourceUrl(listing, releases?.workload?.url);
    const tee = teeLabel(attestation.tee_type);

    return (
        <RNView style={styles.screen}>
            {/* Same green band and white type as every other screen header. */}
            <RNView style={[styles.header, { paddingTop: insets.top + 14 }]}>
                <Text style={styles.headerTitle}>{t('attestation.requestTitle')}</Text>
            </RNView>

            <ScrollView
                style={styles.scroll}
                contentContainerStyle={[styles.content, { paddingBottom: 24 }]}
            >
                {isChanged && (
                    <View style={styles.warningBanner}>
                        <Text style={styles.warningText}>
                            {diff
                                ? t(diff.summaryKey)
                                : t('attestation.warningGeneric')}
                        </Text>
                    </View>
                )}

                <Text style={styles.ask}>
                    {t(askKey, { app: displayName ?? '' })}
                </Text>

                {/* ── The app ─────────────────────────────────────────────── */}
                <View style={styles.card}>
                    <View style={styles.cardBody}>
                        <PropRow
                            label={t('attestation.propAddress')}
                            value={rpId}
                            // The one value that must never be truncated: an
                            // ellipsis is exactly what an impostor host wants,
                            // since `…privasys.org` and `…privasys.org.evil.tld`
                            // would render identically. It wraps instead.
                            wrap
                            mono
                            styles={styles}
                        />
                        <PropRow
                            label={t('attestation.propPublisher')}
                            value={listing?.developer || t('attestation.propPublisherNone')}
                            muted={!listing?.developer}
                            styles={styles}
                        />
                        {workloadHash ? (
                            <PropRow
                                label={t('attestation.propWorkloadHash')}
                                value={truncateHex(workloadHash)}
                                mono
                                selectable
                                styles={styles}
                            />
                        ) : null}
                        {source ? (
                            <PropRow
                                label={t('attestation.propSourceCode')}
                                link={{ url: source, label: sourceLabel(source) }}
                                styles={styles}
                            />
                        ) : null}
                        {tee ? (
                            <PropRow label={t('attestation.propEnclave')} value={tee} styles={styles} last />
                        ) : null}
                    </View>

                    {/* The verdict closes the card. One row changes; the rest of
                        the screen stays exactly where it is. */}
                    <RNView
                        style={[
                            styles.verdict,
                            isVerified && styles.verdictOk,
                            isUnreachable && styles.verdictWarn,
                            isInvalid && styles.verdictBad,
                        ]}
                    >
                        <Ionicons
                            name={isVerified ? 'checkmark-circle' : isUnreachable ? 'alert-circle' : 'close-circle'}
                            size={16}
                            color={isVerified ? p.successText : isUnreachable ? p.warnText : p.dangerText}
                        />
                        <Text
                            style={[
                                styles.verdictText,
                                isVerified && { color: p.successText },
                                isUnreachable && { color: p.warnText },
                                isInvalid && { color: p.dangerText },
                            ]}
                        >
                            {isVerified
                                ? t('attestation.verdictVerified')
                                : isUnreachable
                                    ? t('attestation.verdictUnverified')
                                    : t('attestation.verdictFailed')}
                        </Text>
                        {(showChallenge || showRetry) && (
                            <Pressable
                                style={styles.verdictButton}
                                onPress={onChallenge}
                                disabled={challengeInFlight}
                                accessibilityRole="button"
                            >
                                {challengeInFlight ? (
                                    <ActivityIndicator size="small" color={p.infoText} />
                                ) : (
                                    <Text style={styles.verdictButtonText}>
                                        {showRetry ? t('attestation.retryShort') : t('attestation.challengeShort')}
                                    </Text>
                                )}
                            </Pressable>
                        )}
                    </RNView>

                    {/* Explanation of a non-verified verdict, inside the card,
                        directly under the row it explains. */}
                    {(isUnreachable || isInvalid) && (
                        <RNView style={styles.verdictExplain}>
                            <Text style={styles.verdictExplainText} selectable>
                                {isUnreachable
                                    ? verification?.message
                                        ? t('attestation.unreachableWithReason', { reason: verification.message })
                                        : t('attestation.unreachable')
                                    : verification?.message
                                        ? `${t('attestation.failedHint')} (${verification.message})`
                                        : t('attestation.failedHint')}
                            </Text>
                        </RNView>
                    )}

                    {/* How the current trust was established. Small, factual,
                        and only meaningful once the verdict is good. */}
                    {isVerified && verificationLevel ? (
                        <RNView style={styles.verdictExplain}>
                            <Text style={styles.provenance}>
                                {verification?.challenged
                                    ? t('attestation.provenanceChallenged')
                                    : verificationLevel === 'cached-trusted'
                                        ? t('attestation.provenanceCached')
                                        : t('attestation.provenanceFresh')}
                            </Text>
                        </RNView>
                    ) : null}
                </View>

                {/* ── What changed ───────────────────────────────────────── */}
                {isChanged && diff && diff.changes.length > 0 && (
                    <>
                        <Text style={styles.sectionHeader}>{t('attestation.whatChanged')}</Text>
                        <View style={styles.card}>
                            <View style={styles.cardBody}>
                                {diff.changes.map((c) => (
                                    <PropRow
                                        key={c.labelKey}
                                        label={t(c.labelKey)}
                                        value={`${c.previous ? truncateHex(c.previous) : t('attestation.notRecordedLower')} → ${c.current ? truncateHex(c.current) : t('attestation.removed')}`}
                                        mono
                                        wrap
                                        styles={styles}
                                    />
                                ))}
                            </View>
                        </View>
                    </>
                )}

                {/* ── Requested access to your data ──────────────────────── */}
                {hasAttributes && (
                    <>
                        <Text style={styles.sectionHeader}>{t('attestation.dataHeader')}</Text>
                        <Text style={styles.sectionNote}>
                            {t(allRequired ? 'attestation.dataNoteAllRequired' : 'attestation.dataNote', {
                                app: attributes!.appLabel,
                            })}
                        </Text>
                        <View style={styles.card}>
                            <View style={styles.cardBody}>
                                {attributes!.items.map((item, i) => {
                                    const on = item.essential || attributes!.selected.has(item.key);
                                    return (
                                        <Pressable
                                            key={item.key}
                                            onPress={() => !item.essential && attributes!.onToggle(item.key)}
                                            disabled={item.essential}
                                            accessibilityRole="checkbox"
                                            accessibilityState={{ checked: on, disabled: item.essential }}
                                            accessibilityLabel={item.label}
                                            style={[
                                                styles.attrRow,
                                                i === attributes!.items.length - 1 && styles.rowLast,
                                            ]}
                                        >
                                            <Ionicons
                                                name={
                                                    item.essential
                                                        ? 'checkmark-circle'
                                                        : on
                                                            ? 'checkbox'
                                                            : 'square-outline'
                                                }
                                                size={18}
                                                color={
                                                    item.essential ? p.approve : on ? p.action : p.textMuted
                                                }
                                            />
                                            <View style={styles.attrLabelWrap}>
                                                <Text
                                                    style={[styles.attrLabel, !on && styles.attrLabelOff]}
                                                    numberOfLines={1}
                                                >
                                                    {item.label}
                                                </Text>
                                                {item.essential ? (
                                                    <Text style={styles.attrRequired}>
                                                        {t('attestation.requiredMark')}
                                                    </Text>
                                                ) : null}
                                            </View>
                                            <Text
                                                style={[
                                                    styles.attrValue,
                                                    !item.preview && styles.attrValueNote,
                                                    // Struck through rather than
                                                    // removed: the app asked and
                                                    // the user declined, and both
                                                    // facts belong on screen.
                                                    !on && styles.attrValueOff,
                                                ]}
                                                numberOfLines={1}
                                            >
                                                {item.preview ?? item.note ?? ''}
                                            </Text>
                                        </Pressable>
                                    );
                                })}
                            </View>
                        </View>
                        <Text style={styles.sectionFootnote}>{t('attestation.dataRemember')}</Text>
                    </>
                )}

                {/* ── This app also uses ─────────────────────────────────── */}
                {dependencies && dependencies.length > 0 && (
                    <>
                        <Text style={styles.sectionHeader}>{t('attestation.dependenciesHeader')}</Text>
                        <View style={styles.card}>
                            <View style={styles.cardBody}>
                                {dependencies.map((d, i) => {
                                    const badge = !d.published
                                        ? t('attestation.depBadgeVerify')
                                        : d.status === 'approved'
                                            ? t('attestation.depBadgeApproved')
                                            : d.status === 'denied'
                                                ? t('attestation.depBadgeDenied')
                                                : t('attestation.depBadgeNew');
                                    return (
                                        <PropRow
                                            key={`${d.name}-${i}`}
                                            label={d.label || d.name}
                                            {...(d.url
                                                ? { link: { url: d.url, label: badge } }
                                                : { value: badge })}
                                            last={i === dependencies.length - 1}
                                            styles={styles}
                                        />
                                    );
                                })}
                            </View>
                        </View>
                    </>
                )}

                {/* ── All other details ──────────────────────────────────── */}
                <Text style={styles.sectionHeader}>{t('attestation.otherDetails')}</Text>
                <View style={styles.card}>
                    <View style={styles.cardBody}>
                        {listing?.category ? (
                            <PropRow label={t('attestation.propCategory')} value={listing.category} styles={styles} />
                        ) : null}
                        {listing?.tagline ? (
                            <PropRow label={t('attestation.propDescription')} value={listing.tagline} wrap styles={styles} />
                        ) : null}
                        {releases?.workload?.label ? (
                            <PropRow label={t('attestation.propVersion')} value={releases.workload.label} styles={styles} />
                        ) : null}
                        {listing?.reproducibility?.build_run_url ? (
                            <PropRow
                                label={t('attestation.propBuildRun')}
                                link={{ url: listing.reproducibility.build_run_url, label: t('attestation.openLink') }}
                                styles={styles}
                            />
                        ) : null}
                        {releases?.os?.url ? (
                            <PropRow
                                label={t('attestation.propPlatform')}
                                link={{ url: releases.os.url, label: releases.os.tag || t('attestation.openLink') }}
                                styles={styles}
                            />
                        ) : null}
                        {attestation.attestation_servers_hash ? (
                            <PropRow
                                label={t('attestation.attestationServer')}
                                value={truncateHex(attestation.attestation_servers_hash)}
                                mono
                                styles={styles}
                            />
                        ) : null}
                        {attestation.quote_verification_status ? (
                            <PropRow
                                label={t('attestation.quoteStatus')}
                                value={attestation.quote_verification_status}
                                styles={styles}
                            />
                        ) : null}
                        {attestation.workload_key_source ? (
                            <PropRow label={t('attestation.keySource')} value={attestation.workload_key_source} styles={styles} />
                        ) : null}
                        {attestation.mrenclave ? (
                            <PropRow label="MRENCLAVE" value={truncateHex(attestation.mrenclave)} mono selectable styles={styles} />
                        ) : null}
                        {attestation.mrsigner ? (
                            <PropRow label="MRSIGNER" value={truncateHex(attestation.mrsigner)} mono selectable styles={styles} />
                        ) : null}
                        {attestation.mrtd ? (
                            <PropRow label="MRTD" value={truncateHex(attestation.mrtd)} mono selectable styles={styles} />
                        ) : null}
                        {attestation.workload_config_merkle_root ? (
                            <PropRow
                                label={t('attestation.configRoot')}
                                value={truncateHex(attestation.workload_config_merkle_root)}
                                mono
                                selectable
                                styles={styles}
                            />
                        ) : null}
                        {attestation.cert_subject ? (
                            <PropRow label={t('attestation.subject')} value={attestation.cert_subject} wrap styles={styles} />
                        ) : null}
                        {attestation.cert_not_after ? (
                            <PropRow label={t('attestation.validUntil')} value={shortDate(attestation.cert_not_after)} styles={styles} />
                        ) : null}
                        {(attestation.advisory_ids ?? []).map((id) => (
                            <PropRow key={id} label={t('attestation.advisories')} value={id} mono styles={styles} />
                        ))}
                        {(attestation.custom_oids ?? []).map((oid) => (
                            <PropRow
                                key={oid.oid}
                                label={oid.label || oid.oid}
                                value={truncateHex(oid.value_hex)}
                                mono
                                styles={styles}
                            />
                        ))}
                        {listing?.privacy_url ? (
                            <PropRow
                                label={t('attestation.propPrivacy')}
                                link={{ url: listing.privacy_url, label: t('attestation.openLink') }}
                                styles={styles}
                            />
                        ) : null}
                        {listing?.website_url ? (
                            <PropRow
                                label={t('attestation.propWebsite')}
                                link={{ url: listing.website_url, label: t('attestation.openLink') }}
                                styles={styles}
                            />
                        ) : null}
                        {listing?.support_email ? (
                            <PropRow label={t('attestation.propSupport')} value={listing.support_email} last styles={styles} />
                        ) : null}
                    </View>
                </View>
            </ScrollView>

            {/* Fixed action bar. The proceed action adapts to the verification
                status: Approve when verified, Continue anyway when the service
                was unreachable, and — when the verdict is a definite failure —
                an override buried behind Advanced. */}
            <RNView style={[styles.bottomActions, { paddingBottom: Math.max(insets.bottom, 20) }]}>
                {isInvalid && (
                    <>
                        <Pressable style={styles.advancedToggle} onPress={() => setAdvancedOpen((o) => !o)}>
                            <Text style={styles.advancedToggleText}>{t('attestation.advanced')}</Text>
                            <Text style={styles.advancedToggleIcon}>{advancedOpen ? '▲' : '▼'}</Text>
                        </Pressable>
                        {advancedOpen && (
                            <View style={styles.advancedBox}>
                                <Text style={styles.advancedWarning}>{t('attestation.advancedWarning')}</Text>
                                <Pressable style={styles.dangerButton} onPress={onApprove}>
                                    <Text style={styles.dangerButtonText}>{t('attestation.connectAnyway')}</Text>
                                </Pressable>
                            </View>
                        )}
                    </>
                )}
                <RNView style={styles.buttonRow}>
                    <Pressable style={styles.rejectButton} onPress={onReject}>
                        <Text style={styles.rejectButtonText}>
                            {isInvalid ? t('common.cancel') : t('attestation.reject')}
                        </Text>
                    </Pressable>
                    {isUnreachable ? (
                        <Pressable style={styles.continueButton} onPress={onApprove}>
                            <Text style={styles.approveButtonText}>{t('attestation.continueAnyway')}</Text>
                        </Pressable>
                    ) : !isInvalid ? (
                        <Pressable style={styles.approveButton} onPress={onApprove}>
                            <Text style={styles.approveButtonText}>
                                {isChanged
                                    ? diff
                                        ? t('attestation.approveChanges')
                                        : t('attestation.trustAnyway')
                                    : t('attestation.approve')}
                            </Text>
                        </Pressable>
                    ) : null}
                </RNView>
            </RNView>
        </RNView>
    );
}

/**
 * One properties row: label left, value right.
 *
 * `wrap` is for values where an ellipsis would lose information that matters —
 * the address above all, where a truncated hostname is precisely what an
 * impostor would want.
 */
function PropRow({
    label,
    value,
    link,
    mono,
    wrap,
    muted,
    selectable,
    last,
    styles,
}: {
    label: string;
    value?: string;
    link?: { url: string; label: string };
    mono?: boolean;
    wrap?: boolean;
    muted?: boolean;
    selectable?: boolean;
    last?: boolean;
    styles: ReturnType<typeof makeStyles>;
}) {
    if (!value && !link) return null;
    const body: ReactNode = link ? (
        <ExternalLink href={link.url}>
            <Text style={[styles.propValue, styles.propLink]} numberOfLines={1}>
                {link.label} ↗
            </Text>
        </ExternalLink>
    ) : (
        <Text
            style={[
                styles.propValue,
                mono && styles.propMono,
                muted && styles.propMuted,
                wrap && styles.propWrap,
            ]}
            numberOfLines={wrap ? undefined : 1}
            selectable={selectable}
        >
            {value}
        </Text>
    );
    return (
        <View style={[styles.propRow, last && styles.rowLast]}>
            <Text style={styles.propLabel}>{label}</Text>
            <View style={styles.propValueWrap}>{body}</View>
        </View>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },

    header: {
        backgroundColor: p.green,
        paddingHorizontal: 20,
        paddingBottom: 20,
        borderBottomLeftRadius: 28,
        borderBottomRightRadius: 28,
    },
    headerTitle: { fontSize: 22, fontWeight: '700', color: '#FFFFFF', letterSpacing: -0.4 },

    scroll: { flex: 1 },
    content: { paddingHorizontal: 20, paddingTop: 18 },

    warningBanner: {
        backgroundColor: p.warnBg,
        borderWidth: StyleSheet.hairlineWidth,
        borderColor: p.warnBorder,
        borderRadius: 10,
        padding: 12,
        marginBottom: 14,
    },
    warningText: { color: p.warnText, fontSize: 13, lineHeight: 19, backgroundColor: 'transparent' },

    ask: { fontSize: 17, lineHeight: 25, color: p.textPrimary, fontWeight: '500', marginBottom: 16 },

    card: {
        backgroundColor: p.card,
        borderRadius: 12,
        borderWidth: StyleSheet.hairlineWidth,
        borderColor: p.border,
        overflow: 'hidden',
    },
    cardBody: { paddingHorizontal: 14, backgroundColor: 'transparent' },

    propRow: {
        flexDirection: 'row',
        alignItems: 'flex-start',
        gap: 12,
        paddingVertical: 10,
        borderBottomWidth: StyleSheet.hairlineWidth,
        borderBottomColor: p.border,
        backgroundColor: 'transparent',
    },
    rowLast: { borderBottomWidth: 0 },
    propLabel: { fontSize: 13, color: p.textSecondary, flexShrink: 0 },
    propValueWrap: { flex: 1, alignItems: 'flex-end', backgroundColor: 'transparent' },
    propValue: { fontSize: 13, color: p.textPrimary, fontWeight: '500', textAlign: 'right' },
    propMono: { fontSize: 12, fontWeight: '400' },
    propMuted: { color: p.textMuted, fontWeight: '400' },
    propWrap: { fontSize: 12 },
    propLink: { color: p.action, fontWeight: '400' },

    verdict: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 8,
        paddingHorizontal: 14,
        paddingVertical: 11,
        borderTopWidth: StyleSheet.hairlineWidth,
        borderTopColor: p.border,
    },
    verdictOk: { backgroundColor: p.successBg, borderTopColor: p.successBorder },
    verdictWarn: { backgroundColor: p.warnBg, borderTopColor: p.warnBorder },
    verdictBad: { backgroundColor: p.dangerBg, borderTopColor: p.dangerBorder },
    verdictText: { flex: 1, fontSize: 13, fontWeight: '600' },
    verdictButton: {
        borderWidth: StyleSheet.hairlineWidth,
        borderColor: p.infoBorder,
        backgroundColor: p.card,
        borderRadius: 14,
        paddingHorizontal: 11,
        paddingVertical: 5,
        minWidth: 62,
        alignItems: 'center',
    },
    verdictButtonText: { fontSize: 12, fontWeight: '700', color: p.infoText },
    verdictExplain: {
        paddingHorizontal: 14,
        paddingVertical: 9,
        borderTopWidth: StyleSheet.hairlineWidth,
        borderTopColor: p.border,
        backgroundColor: p.cardAlt,
    },
    verdictExplainText: { fontSize: 12, lineHeight: 18, color: p.textSecondary },
    provenance: { fontSize: 11.5, color: p.infoText, fontWeight: '500' },

    sectionHeader: {
        fontSize: 12,
        fontWeight: '700',
        letterSpacing: 0.6,
        textTransform: 'uppercase',
        color: p.textMuted,
        marginTop: 22,
        marginBottom: 8,
    },
    sectionNote: { fontSize: 12.5, lineHeight: 18, color: p.textSecondary, marginTop: -4, marginBottom: 9 },
    sectionFootnote: { fontSize: 11.5, lineHeight: 17, color: p.textMuted, marginTop: 8 },

    attrRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 10,
        paddingVertical: 11,
        borderBottomWidth: StyleSheet.hairlineWidth,
        borderBottomColor: p.border,
    },
    attrLabelWrap: { flexShrink: 0, backgroundColor: 'transparent' },
    attrLabel: { fontSize: 13, color: p.textPrimary },
    attrLabelOff: { color: p.textMuted },
    attrRequired: { fontSize: 10, color: p.textMuted, letterSpacing: 0.3, marginTop: 1 },
    attrValue: { flex: 1, fontSize: 12.5, color: p.textPrimary, fontWeight: '500', textAlign: 'right' },
    attrValueNote: { color: p.textSecondary, fontWeight: '400', fontSize: 11.5 },
    attrValueOff: { color: p.textMuted, textDecorationLine: 'line-through' },

    bottomActions: {
        paddingHorizontal: 20,
        paddingTop: 14,
        backgroundColor: p.screenBg,
        borderTopWidth: StyleSheet.hairlineWidth,
        borderTopColor: p.border,
    },
    buttonRow: { flexDirection: 'row', gap: 10 },
    rejectButton: {
        flex: 1,
        paddingVertical: 15,
        borderRadius: 12,
        alignItems: 'center',
        backgroundColor: p.buttonNeutral,
    },
    rejectButtonText: { fontSize: 16, fontWeight: '600', color: p.textPrimary },
    approveButton: {
        flex: 1.35,
        paddingVertical: 15,
        borderRadius: 12,
        alignItems: 'center',
        backgroundColor: p.approve,
    },
    continueButton: {
        flex: 1.35,
        paddingVertical: 15,
        borderRadius: 12,
        alignItems: 'center',
        backgroundColor: p.warnText,
    },
    approveButtonText: { fontSize: 16, fontWeight: '600', color: '#FFFFFF' },

    advancedToggle: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 6,
        paddingVertical: 10,
    },
    advancedToggleText: { fontSize: 13, fontWeight: '500', color: p.textSecondary },
    advancedToggleIcon: { fontSize: 10, color: p.textMuted },
    advancedBox: {
        backgroundColor: p.dangerBg,
        borderRadius: 10,
        padding: 14,
        marginBottom: 12,
        gap: 10,
    },
    advancedWarning: { fontSize: 12.5, lineHeight: 18, color: p.dangerText, backgroundColor: 'transparent' },
    dangerButton: { paddingVertical: 12, borderRadius: 10, alignItems: 'center', backgroundColor: p.danger },
    dangerButtonText: { fontSize: 14, fontWeight: '600', color: '#FFFFFF' },
});
