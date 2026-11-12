// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * KYC capture flow: read the ID document chip (NFC), capture a live selfie, and
 * hand both to the attested verifier enclave (services/kyc.ts), which returns a
 * signed receipt and auto-fills the wallet's gov-assurance attributes. Raw chip
 * + biometric data only leave the device for that RA-TLS hop to the enclave.
 *
 * The eMRTD chip read uses the native-emrtd module when the device supports it;
 * a dev build can proceed with stub document fields so the enclave round-trip is
 * exercisable before the chip-read protocol is device-integrated.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { CameraView, useCameraPermissions } from 'expo-camera';
import { Stack, useRouter } from 'expo-router';
import { useEffect, useMemo, useRef, useState } from 'react';
import { ActivityIndicator, Alert, Image, KeyboardAvoidingView, Platform, Pressable, ScrollView, StyleSheet, View as NativeView, useWindowDimensions } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { AttestationView } from '@/components/AttestationView';
import { fetchStoreListing, type StoreListing } from '@/services/store-listing';
import { FirstConnectExplainer } from '@/components/FirstConnectExplainer';
import { useSettingsStore } from '@/stores/settings';
import { DataRequestConsent } from '@/components/DataRequestConsent';
import { ChipScanArt, ChipSymbolArt, PhotoPageArt } from '@/components/IdCheckArt';
import { ImportSelectionSheet } from '@/components/ImportSelectionSheet';
import { Text, View, usePalette, type Palette } from '@/components/Themed';
import { getProfileValue, setProfileValue } from '@/services/attributes';
import { calendarDate } from '@/services/calendar-date';
import { placementFor, type ChipPosition } from '@/services/chip-placement';
import { currentPlacement, refreshPlacement } from '@/services/chip-placement-remote';
import { appIdFromOids } from '@/services/release-provenance';
import {
    applyGovAttributes, attestVerifier, getVerifierInfo, govAttributeCandidates, portraitDataUri, readDocumentMrz,
    verifyIdentity, isRetryableCapture, type KycRecord, type VerifierAttestation,
} from '@/services/kyc';
import { useProfileStore, type ProfileAttribute } from '@/stores/profile';
import { useServiceSessionsStore } from '@/stores/service-sessions';
import { useTrustedAppsStore } from '@/stores/trusted-apps';
import * as Emrtd from '../../modules/native-emrtd/src/index';

// intro: what is about to happen and why · doctype: which document · chip: does
// it have one · consent: what is sent and where, one approval · attest: the full
// enclave page, on request · photo · capture: the camera · read: scan the chip ·
// review: what the chip said, before anything is sent · selfie · verifying ·
// select · done.
type Step = 'intro' | 'doctype' | 'chip' | 'consent' | 'attest' | 'photo' | 'capture' | 'read' | 'review' | 'selfie' | 'verifying' | 'select' | 'done';
type DocType = 'passport' | 'id-card';
// positioning: looking for the lines · checking: the lines are in view ·
// enclave: the phone could not read them, the enclave is asked · captured.
type CaptureState = 'positioning' | 'checking' | 'enclave' | 'captured';
/** A rectangle on screen, in points. */
type ScreenBox = { left: number; top: number; width: number; height: number };

/** A sample of the lines, drawn in the slot so the holder knows what to find. */
const SAMPLE_LINES: Record<DocType, string[]> = {
    passport: ['P<ABC<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<', '0000000000ABC0000000A0000000<<<<<<<<<<<<<<00'],
    'id-card': ['I<ABC0000000000<<<<<<<<<<<<<<<', '0000000A0000000ABC<<<<<<<<<<<0', 'ABC<<ABC<<<<<<<<<<<<<<<<<<<<<<'],
};

// Data-page (TD3 photo page) aspect ≈ 125×88 mm ≈ 1.42:1.
const DOC_PAGE_RATIO = 1.42;
// An ID card (TD1) is 85.6×54 mm.
const ID_CARD_RATIO = 1.586;
// How long the camera may show a zone the phone cannot fully read before the
// frame is sent to the enclave regardless.
const UNREAD_BEFORE_SENDING_MS = 2500;
// The camera that reads the photo page as it films. Null in a build without it.
const MrzScanner = Emrtd.MrzScannerView;

// The raw inputs the verifier reads during capture, shown on the consent screen.
// These are transient processing inputs — consumed in the enclave and never
// stored — NOT disclosable profile attributes, so they are defined here (local to
// the capture flow) rather than in the shared canonical-attributes referential,
// which models stored/disclosed attributes (with scope + assurance). The verifier
// turns these into the gov-assured *output* attributes (birthdate_id,
// nationality_id, age_over_18, …) that the user picks in the "select" step; those
// outputs ARE in the referential. `doc` is the document noun (passport / ID card).
const KYC_INPUT_ITEMS: { key: string; icon: keyof typeof Ionicons.glyphMap; labelKey: string }[] = [
    { key: 'doc_page', icon: 'camera-outline', labelKey: 'kyc.inputDocPage' },
    { key: 'nfc_chip', icon: 'hardware-chip-outline', labelKey: 'kyc.inputNfcChip' },
    { key: 'live_selfie', icon: 'person-outline', labelKey: 'kyc.inputSelfie' },
];

type Placement = ReturnType<typeof placementFor>;

/** The heading of the chip scan: the place to scan, when it is known. */
function scanTitleKey(doc: DocType, placement: Placement): string {
    if (doc === 'id-card') return 'kyc.scanTitleCard';
    if (!placement.known) return 'kyc.scanTitle';
    const titles: Record<ChipPosition, string> = {
        'back-cover': 'kyc.scanTitleBackCover',
        'front-cover': 'kyc.scanTitleFrontCover',
        'photo-page': 'kyc.scanTitlePhotoPage',
        'chip-page': 'kyc.scanTitleChipPage',
        'inside-back-cover': 'kyc.scanTitleInsideBackCover',
        'inside-front-cover': 'kyc.scanTitleInsideFrontCover',
        card: 'kyc.scanTitle',
    };
    return titles[placement.positions[0]];
}

/** What to do with the document, or the order to try when its chip is not on the list. */
function scanBodyKey(doc: DocType, placement: Placement): string {
    if (doc === 'id-card') return 'kyc.scanBodyCard';
    if (!placement.known) return 'kyc.scanBodyUnknown';
    const bodies: Record<ChipPosition, string> = {
        'back-cover': 'kyc.scanBodyBackCover',
        'front-cover': 'kyc.scanBodyFrontCover',
        'photo-page': 'kyc.scanBodyPhotoPage',
        'chip-page': 'kyc.scanBodyChipPage',
        'inside-back-cover': 'kyc.scanBodyInsideBackCover',
        'inside-front-cover': 'kyc.scanBodyInsideFrontCover',
        card: 'kyc.scanBodyUnknown',
    };
    return bodies[placement.positions[0]];
}

/** The tip that names the second place to try. */
const TRY_NEXT_KEY: Partial<Record<ChipPosition, string>> = {
    'back-cover': 'kyc.scanTryBackCover',
    'front-cover': 'kyc.scanTryFrontCover',
    'photo-page': 'kyc.scanTryPhotoPage',
    'chip-page': 'kyc.scanTryChipPage',
    'inside-back-cover': 'kyc.scanTryInsideBackCover',
    'inside-front-cover': 'kyc.scanTryInsideFrontCover',
};

/** The places reached with the booklet open, which is how the drawing shows it. */
const OPEN_POSITIONS: ChipPosition[] = ['photo-page', 'chip-page', 'inside-back-cover', 'inside-front-cover'];

/** The raw fields the trusted-apps store compares (same set as Drive/sign-in). */
function verifierMeasurements(v: VerifierAttestation) {
    return {
        mrenclave: v.attestation.mrenclave,
        mrtd: v.attestation.mrtd,
        rtmr1: v.attestation.rtmr1,
        rtmr2: v.attestation.rtmr2,
        codeHash: v.attestation.workload_code_hash,
        configRoot: v.attestation.workload_config_merkle_root
    };
}

/** Record the approved verifier enclave so we don't re-prompt until it changes. */
function rememberVerifier(v: VerifierAttestation) {
    useTrustedAppsStore.getState().addOrUpdate({
        rpId: v.origin,
        origin: v.origin,
        appName: v.displayName,
        ...verifierMeasurements(v),
        teeType: v.attestation.tee_type ?? 'tdx',
        lastVerified: Math.floor(Date.now() / 1000),
        credentialId: ''
    });
}

export default function KycCaptureScreen() {
    const { t } = useTranslation();
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const [step, setStep] = useState<Step>('intro');
    const [docType, setDocType] = useState<DocType>('passport');
    const [support, setSupport] = useState<Emrtd.EmrtdSupport | null>(null);
    const [docNumber, setDocNumber] = useState('');
    const [dob, setDob] = useState('');
    const [expiry, setExpiry] = useState('');
    const [docRead, setDocRead] = useState<Emrtd.EmrtdReadResult | null>(null);
    // The chip photo can be JPEG 2000, which not every phone can draw: the
    // review screen then shows the details without it.
    const [portraitFailed, setPortraitFailed] = useState(false);
    // The captured data-page frame — sent to the enclave for the heavy OCR +
    // visual↔chip cross-reference (GPG45 box 3). The wallet stays thin (no OCR
    // lib); it just forwards the image.
    const [docImage, setDocImage] = useState('');
    const [busy, setBusy] = useState(false);
    const [permission, requestPermission] = useCameraPermissions();
    // The selfie camera.
    const cameraRef = useRef<CameraView>(null);
    // The photo-page camera, which reads as it films.
    const scannerRef = useRef<Emrtd.MrzScannerHandle>(null);
    const [captureState, setCaptureState] = useState<CaptureState>('positioning');
    const captureFinished = useRef(false);
    // Since when the camera has shown a zone the phone could not fully read
    // (0: it is not showing one).
    const unreadSince = useRef(0);
    // Where the lines are on screen, to draw a box round them.
    const [linesBox, setLinesBox] = useState<ScreenBox | null>(null);
    // The state that issued the document, as its lines write it: with the
    // expiry and the date of birth it says where the chip is likely to be.
    const [docCountry, setDocCountry] = useState('');
    // Whether the enclave has already been asked to read this photo, so a key
    // the chip refuses is not sent round twice.
    const enclaveRead = useRef(false);
    // The list of chip positions: the one in the build, then a newer one from
    // privasys.id if there is one.
    const [placementDoc, setPlacementDoc] = useState(currentPlacement);
    useEffect(() => {
        let live = true;
        void refreshPlacement().then((doc) => { if (live) setPlacementDoc(doc); });
        return () => { live = false; };
    }, []);
    // Post-verification: the user chooses which gov attributes to import.
    const [verifiedRecord, setVerifiedRecord] = useState<KycRecord | null>(null);
    const [candidates, setCandidates] = useState<ProfileAttribute[]>([]);
    const [selected, setSelected] = useState<Set<string>>(new Set());
    // Enclave verification step: the attested verifier is shown on its own page
    // (the same view as sign-in) before any document data is captured.
    const [verifierAtt, setVerifierAtt] = useState<VerifierAttestation | null>(null);
    const [attError, setAttError] = useState<string | null>(null);
    const [attRetry, setAttRetry] = useState(0);
    // Verifier identity (name + origin) for the consent card, resolved from the
    // store before the user agrees (the RA-TLS verification is the next page).
    const [verifierInfo, setVerifierInfo] = useState<{ origin: string; displayName: string } | null>(null);
    // Who publishes the verifier, from the public store. Without this the
    // approval screen said "Not published" about an app that IS published,
    // because this screen simply never asked (2026-08-26).
    const [verifierListing, setVerifierListing] = useState<StoreListing | null>(null);
    /**
     * The one-time "how connecting works" cards, shown OVER the enclave page
     * rather than as a step of their own so dismissing them does not re-run the
     * attestation underneath.
     *
     * Identity verification can be the very first approval a wallet is ever
     * asked for, and this screen used to walk straight into the enclave page
     * with nothing explaining it. Gated exactly as the sign-in flow gates it,
     * and on the SAME flag, so a user who has already seen the cards is never
     * shown them twice (2026-08-26).
     */
    const [showExplainer, setShowExplainer] = useState(false);

    const { width: winW, height: winH } = useWindowDimensions();

    useEffect(() => {
        Emrtd.isSupported().then(setSupport).catch(() => setSupport({ supported: false }));
    }, []);

    /**
     * Who is asking, from the public store. Best-effort and unauthenticated;
     * a null result is a real answer ("this app published no listing") that the
     * approval screen states rather than papering over.
     *
     * Keyed on the verifier's own origin, which IS the app host here, so the
     * slug derivation has nothing to disambiguate.
     */
    useEffect(() => {
        const host = verifierAtt?.origin;
        if (!host) return;
        let live = true;
        void fetchStoreListing(host).then((l) => {
            if (live) setVerifierListing(l);
        });
        return () => {
            live = false;
        };
    }, [verifierAtt?.origin]);

    // Resolve the verifier's name + origin for the consent card, which is on
    // show before the attestation below has finished.
    useEffect(() => {
        if (step !== 'consent' || verifierInfo) return;
        let cancelled = false;
        getVerifierInfo()
            .then((info) => { if (!cancelled) setVerifierInfo(info); })
            .catch(() => { if (!cancelled) setVerifierInfo({ origin: '', displayName: t('kyc.verifierName') }); });
        return () => { cancelled = true; };
    }, [step, verifierInfo]);

    // The enclave is attested while the consent screen is on show, and the
    // result sits on that screen under what is sent: one approval covers what
    // goes and where it goes. The full "Verify Enclave" page of sign-in is one
    // tap away from there. Nothing is captured until the holder has agreed with
    // a verified enclave in front of them, and the digest pin + attestation are
    // enforced again at send time.
    //
    // Whether this is the enclave approved before is REMEMBERED (trusted-apps
    // store, same as Drive and sign-in), and said on the screen: the same one,
    // a changed one, or the first.
    const [attIsChanged, setAttIsChanged] = useState(false);
    const [attIsSame, setAttIsSame] = useState(false);
    // Also while the full page is open, so coming back from it does not start
    // the check again.
    const attesting = step === 'consent' || step === 'attest';
    useEffect(() => {
        if (!attesting) return;
        let cancelled = false;
        setVerifierAtt(null);
        setAttError(null);
        attestVerifier()
            .then((res) => {
                if (cancelled) return;
                const { getApp, isAttestationMatch } = useTrustedAppsStore.getState();
                const trusted = getApp(res.origin);
                const same = !!trusted && isAttestationMatch(res.origin, verifierMeasurements(res));
                setAttIsSame(same);
                setAttIsChanged(!!trusted && !same);
                setVerifierAtt(res);
                if (same) return;
                // First approval this wallet has ever been asked for: explain
                // what just happened before asking them to act on it. Only here
                // — the cards say "your wallet checked the app", which must
                // never precede a check that did not complete, and the catch
                // below owns every other outcome. Read from the stores rather
                // than closed-over render values so a decision made moments ago
                // in another flow is respected.
                const { seenFirstConnect } = useSettingsStore.getState();
                if (useTrustedAppsStore.getState().apps.length === 0 && !seenFirstConnect) {
                    setShowExplainer(true);
                }
            })
            .catch((e) => {
                if (cancelled) return;
                console.warn('[KYC] enclave attestation failed:', e?.message);
                setAttError(e?.message ?? t('drive.challengeFailedBody'));
            });
        return () => { cancelled = true; };
    }, [attesting, attRetry]);

    /** The holder agreed, with a verified enclave on screen. */
    const agree = () => {
        if (!verifierAtt) return;
        rememberVerifier(verifierAtt);
        setStep('photo');
    };

    /**
     * "Challenge this enclave" on the Verify Enclave step: re-attest the
     * verifier in challenge mode (fresh random nonce + TLS channel binder) so
     * the holder gets a liveness proof bound to this exact session before any
     * document data is captured. A failed challenge keeps the prior view.
     */
    const [challengeInFlight, setChallengeInFlight] = useState(false);
    const handleChallengeVerifier = async () => {
        setChallengeInFlight(true);
        try {
            const res = await attestVerifier('challenge');
            setVerifierAtt(res);
        } catch (e: any) {
            console.warn('[KYC] challenge failed:', e?.message);
            Alert.alert(t('drive.challengeFailedTitle'), e?.message ?? t('drive.challengeFailedBody'));
        } finally {
            setChallengeInFlight(false);
        }
    };

    const close = () => {
        if (router.canGoBack()) router.back();
        else router.replace('/(tabs)');
    };

    const docLabel = docType === 'passport' ? t('kyc.docPassportNoun') : t('kyc.docIdCardNoun');
    const isPassport = docType === 'passport';

    // A chip date is a day, not an instant (services/calendar-date.ts).
    const longDate = (iso?: string) => {
        const when = calendarDate(iso);
        return when ? t('kyc.reviewDate', { when }) : (iso ?? '');
    };

    // Every screen has a way out. Close always leaves the check; these steps
    // can also go one step back. The consent and enclave steps carry their own
    // Cancel and Reject.
    const backFrom: Partial<Record<Step, () => void>> = {
        doctype: () => setStep('intro'),
        chip: () => setStep('doctype'),
        photo: () => setStep('chip'),
        capture: () => setStep('photo'),
        read: () => setStep('photo'),
        review: () => setStep('read'),
        selfie: () => setStep('review'),
    };
    const goBack = busy ? undefined : backFrom[step];
    const onCamera = step === 'capture' || step === 'selfie';

    // Where the chip is likely to be, from what the lines said.
    const placement = useMemo(
        () => placementFor(placementDoc, { document: docType, country: docCountry, expiry, birth: dob }),
        [placementDoc, docType, docCountry, expiry, dob],
    );

    // ── Step 2: read the document chip over NFC (or dev stub) ────────────────
    const handleScan = async (
        key: Emrtd.MrzKey = { documentNumber: docNumber.trim(), dateOfBirth: dob.trim(), dateOfExpiry: expiry.trim() },
    ) => {
        setBusy(true);
        // Log the access-field shapes (not values) so a rejected key vs a chip
        // failure is diagnosable from the in-app logs.
        console.log(
            `[KYC] reading ${docType} chip — doc=${key.documentNumber.length}c dob=${key.dateOfBirth.length}c exp=${key.dateOfExpiry.length}c`,
        );
        try {
            const read = await Emrtd.readDocument(key);
            setDocRead(read);
            setPortraitFailed(false);
            setStep('review');
        } catch (e: any) {
            console.warn('[KYC] chip read failed:', e?.message);
            // A rejected key (vs a chip/comms drop) is almost always a single
            // misread character in the document number.
            const rejectedKey = typeof e?.message === 'string' && e.message.includes('InvalidMRZKey');
            if (rejectedKey && docImage && !enclaveRead.current) {
                // The key came from the phone's own reading of the lines. Ask
                // the enclave to read the same photo, and try once more if it
                // reads them differently.
                enclaveRead.current = true;
                try {
                    const mrz = await readDocumentMrz(docImage);
                    const differs = mrz.documentNumber !== key.documentNumber
                        || mrz.dateOfBirth !== key.dateOfBirth || mrz.dateOfExpiry !== key.dateOfExpiry;
                    if (differs) {
                        console.log('[KYC] the enclave read the lines differently; scanning again with its reading');
                        setDocNumber(mrz.documentNumber);
                        setDob(mrz.dateOfBirth);
                        setExpiry(mrz.dateOfExpiry);
                        await handleScan({
                            documentNumber: mrz.documentNumber,
                            dateOfBirth: mrz.dateOfBirth,
                            dateOfExpiry: mrz.dateOfExpiry,
                        });
                        return;
                    }
                } catch (err: any) {
                    console.warn('[KYC] enclave reading of the lines failed:', err?.message);
                }
            }
            if (rejectedKey) {
                Alert.alert(
                    t('kyc.mrzMismatchTitle'),
                    t('kyc.mrzMismatchBody'),
                    [
                        { text: t('common.cancel'), style: 'cancel' },
                        { text: t('kyc.linesAgain'), onPress: () => { void openCapture(); } },
                    ],
                );
            } else {
                Alert.alert(
                    t('kyc.chipReadFailedTitle'),
                    `${e.message}\n\nHold your ${docLabel} flat against the top of your phone and keep it still.`,
                );
            }
        } finally {
            setBusy(false);
        }
    };

    // ── Step 1: photograph the data page ────────────────────────────────────
    const openCapture = async () => {
        // Always resolve permission via the hook before mounting the camera —
        // `permission` can still be null on the first tap, and CameraView shows a
        // blank/white preview until the hook itself has granted.
        let p = permission;
        if (!p || !p.granted) p = await requestPermission();
        if (!p?.granted) {
            Alert.alert(t('connect.cameraNeededTitle'), t('kyc.cameraNeededBody'));
            return;
        }
        if (!MrzScanner) {
            Alert.alert(t('connect.cameraNeededTitle'), t('kyc.cameraNeededBody'));
            return;
        }
        setDocNumber(''); setDob(''); setExpiry(''); setDocImage(''); setDocCountry('');
        setLinesBox(null);
        enclaveRead.current = false;
        captureFinished.current = false;
        unreadSince.current = 0;
        setCaptureState('positioning');
        setStep('capture');
    };

    /**
     * Where a part of a camera frame is on screen. The preview fills the screen
     * and is cut to fit it, so a frame position goes through that same cut.
     */
    const onScreen = (rows: Emrtd.TextLine[], frame: { width: number; height: number }): ScreenBox | null => {
        if (rows.length === 0 || !(frame.width > 0) || !(frame.height > 0)) return null;
        const scale = Math.max(winW / frame.width, winH / frame.height);
        const offX = (frame.width * scale - winW) / 2;
        const offY = (frame.height * scale - winH) / 2;
        const x0 = Math.min(...rows.map((r) => r.x)) * frame.width * scale - offX;
        const x1 = Math.max(...rows.map((r) => r.x + r.w)) * frame.width * scale - offX;
        const y0 = Math.min(...rows.map((r) => r.y)) * frame.height * scale - offY;
        const y1 = Math.max(...rows.map((r) => r.y + r.h)) * frame.height * scale - offY;
        const pad = 8;
        return { left: x0 - pad, top: y0 - pad, width: x1 - x0 + pad * 2, height: y1 - y0 + pad * 2 };
    };

    /** The camera has what it came for: on to the chip. */
    const linesDone = async (fields: Emrtd.MrzKey, country: string, image: string) => {
        setDocNumber(fields.documentNumber);
        setDob(fields.dateOfBirth);
        setExpiry(fields.dateOfExpiry);
        setDocCountry(country);
        setDocImage(image);
        setCaptureState('captured');
        // Keep the green confirmation visible long enough to register.
        await new Promise((resolve) => setTimeout(resolve, 500));
        setStep((s) => (s === 'capture' ? 'read' : s));
    };

    /** Nothing usable came of this frame: carry on looking. */
    const keepLooking = () => {
        unreadSince.current = 0;
        captureFinished.current = false;
        setLinesBox(null);
        setCaptureState('positioning');
    };

    // The camera reads the text of each frame as it arrives and reports it here
    // with where it is. The page can be anywhere in view: once the lines at the
    // bottom of it read as a machine readable zone, that same frame is cut to
    // the page around them and kept. The reading is what unlocks the chip
    // (BAC/PACE) and says which document this is; the picture goes to the
    // enclave with the chip's data for the visual↔chip cross-reference (GPG45
    // box 3).
    //
    // The phone's reading is used when every check digit passes. When the lines
    // are plainly there but the phone cannot read every character, the enclave
    // is asked to read the frame instead, from this same screen.
    const onFrameText = (frame: Emrtd.MrzFrame) => {
        if (step !== 'capture' || captureFinished.current) return;
        const rows = Emrtd.mrzRows(frame.lines);
        const seen = rows.length >= 2 && frame.held;
        if (!seen) {
            unreadSince.current = 0;
            setLinesBox(null);
            setCaptureState('positioning');
            return;
        }
        setLinesBox(onScreen(rows, frame));
        setCaptureState('checking');
        // Every check digit passing is what says the page is sharp and whole.
        const mrz = Emrtd.parseMrzLines(rows.map((r) => r.text));
        if (!mrz) {
            if (!unreadSince.current) unreadSince.current = Date.now();
            if (Date.now() - unreadSince.current < UNREAD_BEFORE_SENDING_MS) return;
        }
        captureFinished.current = true;
        setCaptureState(mrz ? 'captured' : 'enclave');
        void (async () => {
            // Only the page leaves the phone, not what is around it. If the
            // cut cannot be made the whole frame is sent, so a quirk in working
            // it out never stops the reading.
            const ratio = docType === 'id-card' ? ID_CARD_RATIO : DOC_PAGE_RATIO;
            const crop = Emrtd.pageCrop(rows, frame, ratio);
            const scanner = scannerRef.current;
            let image = '';
            try {
                image = (await scanner?.snapshot(crop)) ?? '';
                if (!image) image = (await scanner?.snapshot({ x: 0, y: 0, w: 1, h: 1 })) ?? '';
            } catch (e: any) {
                console.warn('[KYC] snapshot failed:', e?.message);
            }
            if (!image) {
                // Nothing was kept after all.
                keepLooking();
                return;
            }
            // The first of the rows that make up the zone: three on a card,
            // two on a passport.
            const texts = rows.map((r) => r.text.toUpperCase().replace(/\s/g, ''));
            const country = Emrtd.issuingState(texts.slice(docType === 'id-card' ? -3 : -2));
            if (mrz) {
                console.log('[KYC] lines read by the phone');
                await linesDone(mrz, mrz.issuingState || country, image);
                return;
            }
            // The phone could not read every character. The enclave reads the
            // same frame (OmniMRZ, check-digit validated).
            console.log('[KYC] lines seen but not read by the phone; asking the enclave');
            enclaveRead.current = true;
            try {
                const read = await readDocumentMrz(image);
                console.log('[KYC] lines read by the enclave');
                await linesDone(read, country, image);
            } catch (e: any) {
                console.warn('[KYC] enclave reading of the lines failed:', e?.message);
                // Only an unreadable frame is fixed by another one, and the
                // camera is still up, so it simply carries on. Everything else
                // (a rejected attestation, a gate refusal, the enclave out of
                // reach) must say so, or the holder films the page for ever
                // against a failure the camera cannot fix.
                if (isRetryableCapture(e)) {
                    keepLooking();
                    return;
                }
                Alert.alert(
                    t('kyc.unavailableTitle'),
                    t('kyc.unavailableBody', {
                        reason: e?.detail || e?.message || t('kyc.verifierRefused')
                    }),
                    [
                        { text: t('common.retry'), onPress: keepLooking },
                        { text: t('common.cancel'), style: 'cancel', onPress: () => setStep('photo') },
                    ],
                );
            }
        })();
    };

    // ── Step 2: capture a live selfie (for the enclave face match) ──────────
    // After verification the legal names are stored as given_name_id/family_name_id
    // (gov). Offer — never force — adopting them as the everyday first/last name,
    // since a passport's legal given names ("BERTRAND FRANCOIS") are often not the
    // name someone goes by ("Bertrand").
    const offerAdoptIdName = () => {
        const store = useProfileStore.getState();
        const profile = store.profile;
        if (!profile) return;
        const idGiven = getProfileValue(profile, 'given_name_id');
        const idFamily = getProfileValue(profile, 'family_name_id');
        if (!idGiven && !idFamily) return;
        const curGiven = getProfileValue(profile, 'given_name');
        const curFamily = getProfileValue(profile, 'family_name');
        if (idGiven === curGiven && idFamily === curFamily) return; // nothing to offer
        const current = curGiven || curFamily
            ? t('kyc.keepCurrentNameSuffix', { name: [curGiven, curFamily].filter(Boolean).join(' ') })
            : '';
        Alert.alert(
            t('kyc.useVerifiedNameTitle'),
            t('kyc.useVerifiedNameBody', {
                given: idGiven ?? t('common.notSet'),
                family: idFamily ?? t('common.notSet')
            }) + current,
            [
                { text: t('kyc.keepCurrentName'), style: 'cancel' },
                {
                    text: t('kyc.useIdName'),
                    onPress: () => {
                        const rec = [{
                            verifier: 'privasys-kyc', verifierDisplayName: t('kyc.verifierName'),
                            method: 'kyc_enclave' as const, assurance: 'gov' as const,
                            verifiedAt: Math.floor(Date.now() / 1000),
                        }];
                        if (idGiven) setProfileValue(store, 'given_name', idGiven, 'document', { verified: true, verifications: rec });
                        if (idFamily) setProfileValue(store, 'family_name', idFamily, 'document', { verified: true, verifications: rec });
                    },
                },
            ],
        );
    };

    const captureAndVerify = async (liveImageBase64?: string) => {
        if (!docRead) return;
        setStep('verifying');
        setBusy(true);
        try {
            const result = await verifyIdentity(docRead, { liveImageBase64, docImage: docImage || undefined });
            // Audit trail: the identity check is an authentication ceremony
            // against the verifier enclave — record what left the device and
            // the attestation the user approved before capture.
            const att = verifierAtt?.attestation;
            useServiceSessionsStore.getState().record({
                serviceKey: verifierAtt?.origin ?? 'privasys-identity-verifier',
                displayName: verifierAtt?.displayName ?? t('kyc.verifierName'),
                kind: 'identity-check',
                identity: 'privasys-id',
                rpId: verifierAtt?.origin ?? '',
                origin: verifierAtt?.origin ?? '',
                startedAt: Date.now(),
                oneShot: true,
                detail: `Verified a ${docLabel}; raw document and selfie processed in the enclave and discarded`,
                sharedAttributes: [
                    { key: 'document_chip', value: `${docLabel} chip (NFC)` },
                    ...(docImage ? [{ key: 'document_photo_page', value: t('kyc.photoPageImage') }] : []),
                    ...(liveImageBase64 ? [{ key: 'live_selfie', value: t('kyc.liveSelfie') }] : [])
                ],
                attestations: att
                    ? [
                          {
                              host: verifierAtt.origin,
                              teeType: att.tee_type ?? 'tdx',
                              mrenclave: att.mrenclave,
                              mrtd: att.mrtd,
                              codeHash: att.workload_code_hash,
                              configRoot: att.workload_config_merkle_root,
                              imageRef: att.workload_image_ref,
                              quoteStatus: att.quote_verification_status,
                              appId: appIdFromOids(att.custom_oids),
                              verifiedAt: Date.now()
                          }
                      ]
                    : undefined
            });
            // Present the verified attributes for the holder to choose what to
            // import (same pattern as the IdP import flow), including the ID photo.
            const cands = govAttributeCandidates(result.record, docRead.portraitBase64);
            setVerifiedRecord(result.record);
            setCandidates(cands);
            setSelected(new Set(cands.map((c) => c.key)));
            setStep('select');
        } catch (e: any) {
            Alert.alert(t('kyc.verificationFailed'), e.message);
            setStep('selfie');
        } finally {
            setBusy(false);
        }
    };

    const toggleAttr = (key: string) =>
        setSelected((prev) => {
            const next = new Set(prev);
            if (next.has(key)) next.delete(key);
            else next.add(key);
            return next;
        });

    const applySelectedAttributes = () => {
        if (!verifiedRecord) return;
        const filled = applyGovAttributes(verifiedRecord, selected, docRead?.portraitBase64);
        console.log('[KYC] imported:', filled.join(', '));
        setStep('done');
        offerAdoptIdName();
    };

    const handleSelfie = async () => {
        try {
            if (permission && !permission.granted) {
                const res = await requestPermission();
                if (!res.granted) {
                    // No camera — proceed without a live image (enclave decides).
                    await captureAndVerify(undefined);
                    return;
                }
            }
            const photo = await cameraRef.current?.takePictureAsync({ base64: true, quality: 0.6 });
            await captureAndVerify(photo?.base64 ?? undefined);
        } catch (e: any) {
            Alert.alert(t('connect.cameraError'), e.message);
        }
    };

    return (
        <KeyboardAvoidingView
            style={styles.container}
            behavior={Platform.OS === 'ios' ? 'padding' : undefined}
        >
            <Stack.Screen options={{ orientation: step === 'capture' ? 'landscape' : 'portrait' }} />

            {/* What is about to happen and why, once, so the screens after it
                are steps ticked off and not each a new explanation. */}
            {step === 'intro' && (
                <ScrollView
                    style={styles.flex}
                    contentContainerStyle={styles.padContent}
                    showsVerticalScrollIndicator={false}
                >
                    <Text style={styles.title}>{t('kyc.introTitle')}</Text>
                    <Text style={styles.body}>{t('kyc.introBody')}</Text>
                    <NativeView style={styles.plan}>
                        {([1, 2, 3] as const).map((n) => (
                            <NativeView key={n} style={styles.planRow}>
                                <NativeView style={styles.planNumber}>
                                    <Text style={styles.planNumberText}>{n}</Text>
                                </NativeView>
                                <NativeView style={styles.docOptionBody}>
                                    <Text style={styles.planTitle}>{t(`kyc.introStep${n}Title`)}</Text>
                                    <Text style={styles.planBody}>{t(`kyc.introStep${n}Body`)}</Text>
                                </NativeView>
                            </NativeView>
                        ))}
                    </NativeView>
                    <Text style={styles.small}>{t('kyc.introNote')}</Text>
                    <Pressable style={styles.primary} onPress={() => setStep('doctype')}>
                        <Text style={styles.primaryText}>{t('kyc.introStart')}</Text>
                    </Pressable>
                </ScrollView>
            )}

            {step === 'doctype' && (
                <ScrollView
                    style={styles.flex}
                    contentContainerStyle={styles.padContent}
                    showsVerticalScrollIndicator={false}
                >
                    <Text style={styles.title}>{t('kyc.chooseDocTitle')}</Text>
                    <Text style={styles.body}>{t('kyc.chooseDocHint')}</Text>

                    <Pressable
                        style={styles.docOption}
                        onPress={() => { setDocType('passport'); setStep('chip'); }}
                    >
                        <Ionicons name="airplane-outline" size={22} color={p.action} />
                        {/* NativeView: the themed View paints the screen background,
                            which shows as a grey patch inside the white card. */}
                        <NativeView style={styles.docOptionBody}>
                            <Text style={styles.docOptionTitle}>{t('kyc.docPassport')}</Text>
                            <Text style={styles.docOptionSub}>{t('kyc.docPassportHint')}</Text>
                        </NativeView>
                        <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                    </Pressable>

                    <Pressable
                        style={styles.docOption}
                        onPress={() => { setDocType('id-card'); setStep('chip'); }}
                    >
                        <Ionicons name="card-outline" size={22} color={p.action} />
                        <NativeView style={styles.docOptionBody}>
                            <Text style={styles.docOptionTitle}>{t('kyc.docIdCard')}</Text>
                            <Text style={styles.docOptionSub}>{t('kyc.docIdCardHint')}</Text>
                        </NativeView>
                        <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                    </Pressable>

                    <Text style={styles.note}>{t('kyc.noDrivingLicences')}</Text>
                    {support && !support.supported && (
                        <Text style={styles.note}>
                            {support.reason
                                ? t('kyc.nfcUnavailableWithReason', { reason: support.reason })
                                : t('kyc.nfcUnavailable')}
                        </Text>
                    )}
                </ScrollView>
            )}

            {/* A confirmation, nothing more: the document was chosen on the
                screen before. */}
            {step === 'chip' && (
                <ScrollView
                    style={styles.flex}
                    contentContainerStyle={styles.padContent}
                    showsVerticalScrollIndicator={false}
                >
                    <Text style={styles.title}>{t(isPassport ? 'kyc.chipCheckTitlePassport' : 'kyc.chipCheckTitleIdCard')}</Text>
                    <Text style={styles.body}>{t(isPassport ? 'kyc.chipBodyPassport' : 'kyc.chipBodyIdCard')}</Text>
                    <ChipSymbolArt doc={docType} label={t('kyc.artChipSymbol')} />
                    <Tips items={[t('kyc.chipTipOriginal'), t('kyc.chipTipNotExpired')]} />
                    <Pressable style={styles.primary} onPress={() => setStep('consent')}>
                        <Text style={styles.primaryText}>
                            {t(isPassport ? 'kyc.chipConfirmPassport' : 'kyc.chipConfirmIdCard')}
                        </Text>
                    </Pressable>
                </ScrollView>
            )}

            {/* One approval: what is sent, and where it runs. The enclave is
                checked while this is on show, and the holder cannot agree until
                it has been. The very first approval a wallet is asked for gets
                the "how connecting works" cards over it, once. */}
            {step === 'consent' && (
                showExplainer && verifierAtt ? (
                    <FirstConnectExplainer
                        appName={verifierAtt.displayName}
                        onDone={() => {
                            useSettingsStore.getState().setSeenFirstConnect(true);
                            setShowExplainer(false);
                        }}
                        onSkip={() => {
                            // A skip counts as seen. Replaying cards the user
                            // just dismissed trains them to dismiss the approval
                            // screen behind it too.
                            useSettingsStore.getState().setSeenFirstConnect(true);
                            setShowExplainer(false);
                        }}
                    />
                ) : (
                    <DataRequestConsent
                        appName={verifierInfo?.displayName ?? t('kyc.verifierName')}
                        origin={verifierInfo?.origin ?? ''}
                        appIcon="id-card-outline"
                        sectionTitle={t('kyc.sentToEnclave')}
                        sectionDescription={t('kyc.consentIntro', { doc: docLabel })}
                        items={KYC_INPUT_ITEMS.map((i) => ({
                            key: i.key,
                            icon: i.icon,
                            label: t(i.labelKey, { doc: docLabel })
                        }))}
                        footer={
                            <EnclaveBlock
                                state={attError ? 'failed' : !verifierAtt ? 'checking' : attIsChanged ? 'changed' : attIsSame ? 'same' : 'first'}
                                error={attError}
                                onDetails={() => setStep('attest')}
                                onRetry={() => setAttRetry((n) => n + 1)}
                            />
                        }
                        note={t('kyc.consentNothingYet')}
                        denyLabel={t('common.cancel')}
                        approveLabel={t('kyc.agreeAndContinue')}
                        approveDisabled={!verifierAtt || !!attError}
                        onDeny={close}
                        onApprove={agree}
                        contentTopInset={insets.top + 36}
                        actionsBottomInset={insets.bottom + 16}
                    />
                )
            )}

            {/* The full enclave page, as at sign-in, for a holder who asks to
                see it. Approving here is the same approval as on the screen it
                was opened from. */}
            {step === 'attest' && (
                !verifierAtt ? (
                    <View style={styles.pad}>
                        <ActivityIndicator size="large" color={p.action} />
                        <Text style={styles.body}>{t('kyc.verifyingEnclave')}</Text>
                    </View>
                ) : showExplainer ? (
                    <FirstConnectExplainer
                        appName={verifierAtt.displayName}
                        onDone={() => {
                            useSettingsStore.getState().setSeenFirstConnect(true);
                            setShowExplainer(false);
                        }}
                        onSkip={() => {
                            // A skip counts as seen. Replaying cards the user
                            // just dismissed trains them to dismiss the approval
                            // screen behind it too.
                            useSettingsStore.getState().setSeenFirstConnect(true);
                            setShowExplainer(false);
                        }}
                    />
                ) : (
                    <AttestationView
                        attestation={verifierAtt.attestation}
                        rpId={verifierAtt.origin}
                        displayName={verifierAtt.displayName}
                        listing={verifierListing}
                        isChanged={attIsChanged}
                        verificationLevel="fresh-as-verified"
                        verification={{
                            status: 'verified',
                            mode: verifierAtt.mode,
                            challenged: verifierAtt.challenged,
                        }}
                        onApprove={agree}
                        onReject={() => setStep('consent')}
                        onChallenge={handleChallengeVerifier}
                        challengeInFlight={challengeInFlight}
                    />
                )
            )}

            {step === 'photo' && (
                <ScrollView
                    style={styles.flex}
                    contentContainerStyle={styles.padContent}
                    showsVerticalScrollIndicator={false}
                >
                    <Text style={styles.progress}>{t('kyc.stepOf', { n: 1 })}</Text>
                    <Text style={styles.title}>{t(isPassport ? 'kyc.photoFirstTitlePassport' : 'kyc.photoFirstTitleIdCard')}</Text>
                    <Text style={styles.body}>{t(isPassport ? 'kyc.photoFirstBodyPassport' : 'kyc.photoFirstBodyIdCard')}</Text>
                    <PhotoPageArt doc={docType} label={t('kyc.artPhotoPage')} />
                    <Pressable style={styles.primary} onPress={() => { void openCapture(); }}>
                        <Text style={styles.primaryText}>{t('kyc.openCamera')}</Text>
                    </Pressable>
                </ScrollView>
            )}

            {step === 'capture' && (
                <NativeView style={[styles.flex, { backgroundColor: '#000' }]}>
                    {MrzScanner && (
                        <MrzScanner
                            ref={scannerRef}
                            style={styles.camera}
                            active={step === 'capture'}
                            onText={(e) => onFrameText(e.nativeEvent)}
                            onReady={() => console.log('[KYC] capture camera ready')}
                            onCameraError={(e) => {
                                console.warn('[KYC] capture camera error:', e.nativeEvent?.message);
                                Alert.alert(t('connect.cameraNeededTitle'), t('kyc.cameraNeededBody'));
                                setStep('photo');
                            }}
                        />
                    )}
                    {/* The camera looks for the lines and nothing else, so that
                        is all the screen shows: a slot with a sample of them
                        while it looks, then a box round the real ones, white
                        when seen and green when read. */}
                    {linesBox ? (
                        <NativeView
                            pointerEvents="none"
                            style={[
                                styles.linesBox,
                                linesBox,
                                captureState === 'captured' && styles.linesBoxRead,
                            ]}
                        />
                    ) : (
                        <NativeView pointerEvents="none" style={[styles.linesSlot, { bottom: insets.bottom + 64 }]}>
                            {SAMPLE_LINES[docType].map((line) => (
                                <Text key={line} allowFontScaling={false} numberOfLines={1} style={styles.linesSample}>
                                    {line}
                                </Text>
                            ))}
                        </NativeView>
                    )}
                    <NativeView style={[styles.capturePill, { top: insets.top + 14 }]} pointerEvents="none">
                        <Text style={styles.capturePillText} numberOfLines={2}>
                            {captureState === 'positioning'
                                ? t(isPassport ? 'kyc.camLookPassport' : 'kyc.camLookIdCard')
                                : t('kyc.camHold')}
                        </Text>
                    </NativeView>
                    <NativeView style={[styles.capturePill, { bottom: insets.bottom + 14 }]} pointerEvents="none">
                        {captureState === 'captured' ? (
                            <Ionicons name="checkmark-circle" size={20} color="#34C759" />
                        ) : (
                            <ActivityIndicator size="small" color="#FFFFFF" />
                        )}
                        <Text style={[styles.capturePillText, captureState === 'captured' && styles.capturePillRead]}>
                            {t(
                                captureState === 'captured' ? 'kyc.camRead'
                                    : captureState === 'enclave' ? 'kyc.camEnclave'
                                        : captureState === 'checking' ? 'kyc.camReading'
                                            : 'kyc.camLooking',
                            )}
                        </Text>
                    </NativeView>
                </NativeView>
            )}

            {step === 'read' && (
                <ScrollView
                    style={styles.flex}
                    contentContainerStyle={styles.padContent}
                    showsVerticalScrollIndicator={false}
                >
                    <NativeView style={styles.progressRow}>
                        <Ionicons name="checkmark-circle" size={16} color={p.approve} />
                        <Text style={[styles.progress, { color: p.approve }]}>{t('kyc.camRead')}</Text>
                        <Text style={styles.progress}>· {t('kyc.stepOf', { n: 2 })}</Text>
                    </NativeView>
                    <Text style={styles.title}>{t(scanTitleKey(docType, placement))}</Text>
                    <Text style={styles.body}>{t(scanBodyKey(docType, placement))}</Text>
                    <ChipScanArt
                        doc={docType}
                        label={t('kyc.artChipScan')}
                        open={isPassport && placement.known && OPEN_POSITIONS.includes(placement.positions[0])}
                        reader={Platform.OS === 'ios' ? 'top' : 'middle'}
                    />
                    <Tips
                        items={[
                            t(Platform.OS === 'ios' ? 'kyc.scanReaderTop' : 'kyc.scanReaderMiddle'),
                            t('kyc.scanTipCover'),
                            ...(placement.known && TRY_NEXT_KEY[placement.positions[1]] ? [t(TRY_NEXT_KEY[placement.positions[1]]!)] : []),
                        ]}
                    />
                    <Pressable
                        style={[styles.primary, busy && styles.disabled]}
                        onPress={() => { void handleScan(); }}
                        disabled={busy}
                    >
                        {busy ? (
                            <ActivityIndicator color="#FFFFFF" />
                        ) : (
                            <Text style={styles.primaryText}>{t('kyc.startScan')}</Text>
                        )}
                    </Pressable>
                </ScrollView>
            )}

            {/* What the chip said, shown before anything goes to the enclave:
                the holder sees exactly what is about to be sent, and can stop. */}
            {step === 'review' && docRead && (
                <ScrollView
                    style={styles.flex}
                    contentContainerStyle={styles.padContent}
                    showsVerticalScrollIndicator={false}
                >
                    <Text style={styles.title}>{t('kyc.reviewTitle')}</Text>
                    <Text style={styles.body}>{t('kyc.reviewBody')}</Text>
                    {docRead.portraitBase64 && !portraitFailed ? (
                        <Image
                            source={{ uri: portraitDataUri(docRead.portraitBase64) }}
                            style={styles.reviewPhoto}
                            onError={() => setPortraitFailed(true)}
                            accessibilityIgnoresInvertColors
                        />
                    ) : null}
                    <View style={styles.summaryCard}>
                        <SummaryRow
                            plain
                            label={t('kyc.reviewName')}
                            value={[docRead.fields.family_name?.toUpperCase(), docRead.fields.given_name].filter(Boolean).join(', ')}
                        />
                        <SummaryRow plain label={t('kyc.summaryDob')} value={longDate(docRead.fields.birthdate)} />
                        <SummaryRow plain label={t('kyc.reviewExpires')} value={longDate(docRead.fields.expiry_date)} />
                        <SummaryRow plain label={t('kyc.reviewNationality')} value={docRead.fields.nationality ?? ''} />
                    </View>
                    <Text style={styles.reviewSent}>{t('kyc.reviewSent')}</Text>
                    <Pressable style={styles.primary} onPress={() => setStep('selfie')}>
                        <Text style={styles.primaryText}>{t('kyc.continueToSelfie')}</Text>
                    </Pressable>
                    <Pressable style={styles.secondary} onPress={() => setStep('read')}>
                        <Text style={styles.secondaryText}>{t('kyc.scanAgain')}</Text>
                    </Pressable>
                </ScrollView>
            )}

            {step === 'selfie' && (
                <View style={styles.flex}>
                    <CameraView ref={cameraRef} style={styles.camera} facing="front" />
                    {/* Head outline so the user centres their face for the
                        enclave's match against the document photo. */}
                    <NativeView pointerEvents="none" style={styles.selfieFaceGuide} />
                    <View style={styles.selfieOverlay}>
                        <Text style={styles.selfieText}>{t('kyc.selfieBody')}</Text>
                        <Pressable style={styles.primary} onPress={handleSelfie}>
                            <Text style={styles.primaryText}>{t('kyc.captureAndVerify')}</Text>
                        </Pressable>
                    </View>
                </View>
            )}

            {step === 'verifying' && (
                <View style={styles.pad}>
                    <ActivityIndicator size="large" color={p.action} />
                    <Text style={styles.body}>{t('kyc.verifyingInEnclave')}</Text>
                </View>
            )}

            {step === 'select' && (
                <ScrollView
                    style={styles.flex}
                    contentContainerStyle={styles.padContent}
                    showsVerticalScrollIndicator={false}
                >
                    <Ionicons name="shield-checkmark" size={40} color={p.approve} />
                    <Text style={styles.title}>{t('kyc.identityVerified')}</Text>
                    <Text style={styles.body}>{t('kyc.chooseDetails')}</Text>
                    <ImportSelectionSheet
                        providerName={t('kyc.providerYourId')}
                        attributes={candidates}
                        selected={selected}
                        onToggle={toggleAttr}
                        onConfirm={applySelectedAttributes}
                        onCancel={() => setStep('done')}
                    />
                </ScrollView>
            )}

            {step === 'done' && (
                <View style={styles.pad}>
                    <Ionicons name="checkmark-circle" size={48} color={p.approve} />
                    <Text style={styles.title}>{t('kyc.allSet')}</Text>
                    <Text style={styles.body}>{t('kyc.allSetBody')}</Text>
                    <Pressable style={styles.primary} onPress={close}>
                        <Text style={styles.primaryText}>{t('common.done')}</Text>
                    </Pressable>
                </View>
            )}

            {/* Back and Close, drawn last so they sit above the camera preview
                on both platforms, and inset from the notch in either
                orientation. Over the camera they get a dark disc to stay
                visible on any background. */}
            {goBack && (
                <Pressable
                    style={[styles.nav, onCamera && styles.navOnCamera, { top: insets.top + 12, left: insets.left + 16 }]}
                    onPress={goBack}
                    hitSlop={12}
                    accessibilityRole="button"
                    accessibilityLabel={t('common.goBack')}
                >
                    <Ionicons name="chevron-back" size={24} color={onCamera ? '#FFFFFF' : p.textMuted} />
                </Pressable>
            )}
            <Pressable
                style={[styles.nav, onCamera && styles.navOnCamera, { top: insets.top + 12, right: insets.right + 16 }]}
                onPress={close}
                hitSlop={12}
                accessibilityRole="button"
                accessibilityLabel={t('common.close')}
            >
                <Ionicons name="close" size={26} color={onCamera ? '#FFFFFF' : p.textMuted} />
            </Pressable>
        </KeyboardAvoidingView>
    );
}

/**
 * Where the check runs, on the consent screen: the result of attesting the
 * enclave, in a sentence, with the full page one tap away.
 *
 * `first`: verified, never approved on this phone · `same`: verified, and the
 * one approved before · `changed`: verified, but not the one approved before ·
 * `checking` · `failed`.
 */
function EnclaveBlock({ state, error, onDetails, onRetry }: {
    state: 'checking' | 'first' | 'same' | 'changed' | 'failed';
    error: string | null;
    onDetails: () => void;
    onRetry: () => void;
}) {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const tone = state === 'changed' ? { bg: p.warnBg, border: p.warnBorder, text: p.warnText }
        : state === 'failed' ? { bg: p.dangerBg, border: p.dangerBorder, text: p.dangerText }
            : state === 'checking' ? { bg: p.cardAlt, border: p.border, text: p.textSecondary }
                : { bg: p.successBg, border: p.successBorder, text: p.successText };
    const title = state === 'checking' ? t('kyc.enclaveChecking')
        : state === 'failed' ? t('kyc.enclaveVerifyFailed')
            : state === 'changed' ? t('kyc.enclaveChangedTitle')
                : t('kyc.enclaveVerified');
    const body = state === 'checking' ? t('kyc.enclaveCheckingBody')
        : state === 'failed' ? (error ?? '')
            : state === 'changed' ? t('kyc.enclaveChangedBody')
                : state === 'same' ? t('kyc.enclaveSameBody')
                    : t('kyc.enclaveFirstBody');
    return (
        <NativeView>
            <Text style={styles.enclaveHeading}>{t('kyc.whereItRuns')}</Text>
            <NativeView style={[styles.enclave, { backgroundColor: tone.bg, borderColor: tone.border }]}>
                <NativeView style={styles.enclaveTitleRow}>
                    {state === 'checking' ? (
                        <ActivityIndicator size="small" color={tone.text} />
                    ) : (
                        <Ionicons
                            name={state === 'failed' ? 'alert-circle' : state === 'changed' ? 'warning' : 'shield-checkmark'}
                            size={18}
                            color={tone.text}
                        />
                    )}
                    <Text style={[styles.enclaveTitle, { color: tone.text }]}>{title}</Text>
                </NativeView>
                {body ? <Text style={[styles.enclaveBody, { color: tone.text }]}>{body}</Text> : null}
                {state === 'failed' ? (
                    <Pressable onPress={onRetry} hitSlop={8} accessibilityRole="button">
                        <Text style={styles.enclaveLink}>{t('common.retry')}</Text>
                    </Pressable>
                ) : state !== 'checking' ? (
                    <Pressable onPress={onDetails} hitSlop={8} accessibilityRole="button">
                        <Text style={styles.enclaveLink}>
                            {t(state === 'changed' ? 'kyc.seeWhatChanged' : 'kyc.seeAttestation')}
                        </Text>
                    </Pressable>
                ) : null}
            </NativeView>
        </NativeView>
    );
}

/** `plain` is for words (a name, a date) rather than a code: no letter-spacing, and it wraps. */
function SummaryRow({ label, value, plain }: { label: string; value: string; plain?: boolean }) {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    return (
        <View style={styles.summaryRow}>
            <Text style={styles.summaryLabel}>{label}</Text>
            <Text style={plain ? styles.summaryValuePlain : styles.summaryValue}>{value || t('common.notSet')}</Text>
        </View>
    );
}

/** The two or three things to get right on a screen, under its drawing. */
function Tips({ items }: { items: string[] }) {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    return (
        <NativeView style={styles.tips}>
            {items.map((item) => (
                <NativeView key={item} style={styles.tip}>
                    <Ionicons name="checkmark-circle-outline" size={18} color={p.textSecondary} />
                    <Text style={styles.tipText}>{item}</Text>
                </NativeView>
            ))}
        </NativeView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    container: { flex: 1, backgroundColor: p.screenBg },
    flex: { flex: 1 },
    pad: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 28, gap: 14 },
    padContent: { flexGrow: 1, alignItems: 'center', justifyContent: 'center', padding: 28, gap: 14, paddingTop: 72 },
    nav: { position: 'absolute', zIndex: 10, width: 40, height: 40, borderRadius: 20, alignItems: 'center', justifyContent: 'center' },
    navOnCamera: { backgroundColor: 'rgba(0,0,0,0.55)' },
    tips: { alignSelf: 'stretch', gap: 8 },
    tip: { flexDirection: 'row', alignItems: 'flex-start', gap: 10 },
    // Sizes follow the sign-in and approval screens, whose lead sentence is 17.
    tipText: { flex: 1, fontSize: 15, lineHeight: 21, color: p.textSecondary },
    reviewPhoto: { width: 108, height: 138, borderRadius: 10, backgroundColor: p.cardAlt },
    reviewSent: { fontSize: 14, lineHeight: 20, textAlign: 'center', color: p.textSecondary },
    title: { fontSize: 22, fontWeight: '700', textAlign: 'center', color: p.textPrimary },
    body: { fontSize: 17, lineHeight: 26, textAlign: 'center', color: p.textSecondary },
    small: { fontSize: 14, lineHeight: 20, textAlign: 'center', color: p.textMuted },
    progressRow: { flexDirection: 'row', alignItems: 'center', gap: 6 },
    progress: { fontSize: 13, fontWeight: '700', letterSpacing: 0.6, textTransform: 'uppercase', color: p.textMuted },
    plan: { alignSelf: 'stretch', gap: 14, marginVertical: 4 },
    planRow: { flexDirection: 'row', alignItems: 'flex-start', gap: 12 },
    planNumber: {
        width: 28, height: 28, borderRadius: 14, alignItems: 'center', justifyContent: 'center',
        backgroundColor: p.cardAlt,
    },
    planNumberText: { fontSize: 14, fontWeight: '700', color: p.action },
    planTitle: { fontSize: 16, fontWeight: '600', color: p.textPrimary },
    planBody: { fontSize: 14, lineHeight: 20, color: p.textSecondary, marginTop: 2 },
    enclaveHeading: {
        fontSize: 12, fontWeight: '700', letterSpacing: 0.6, textTransform: 'uppercase',
        color: p.textMuted, marginTop: 20, marginBottom: 8,
    },
    enclave: { borderWidth: 1, borderRadius: 12, padding: 14, gap: 6 },
    enclaveTitleRow: { flexDirection: 'row', alignItems: 'center', gap: 8 },
    enclaveTitle: { flex: 1, fontSize: 15, fontWeight: '700' },
    enclaveBody: { fontSize: 13.5, lineHeight: 19 },
    enclaveLink: { fontSize: 14, fontWeight: '600', color: p.action, marginTop: 2 },
    note: { fontSize: 13, color: p.warnText, textAlign: 'center' },
    orText: { fontSize: 13, color: p.textMuted, textAlign: 'center' },
    input: {
        width: '100%', borderWidth: 1, borderColor: p.border, borderRadius: 10,
        backgroundColor: p.card,
        paddingHorizontal: 14, paddingVertical: 14, fontSize: 16, color: p.textPrimary,
    },
    primary: {
        flexDirection: 'row', backgroundColor: p.action, borderRadius: 10, paddingVertical: 14,
        paddingHorizontal: 24, alignItems: 'center', justifyContent: 'center', alignSelf: 'stretch',
    },
    primaryText: { color: '#FFFFFF', fontSize: 16, fontWeight: '600' },
    disabled: { opacity: 0.5 },
    secondary: { paddingVertical: 10, alignItems: 'center' },
    secondaryText: { color: p.action, fontSize: 15 },
    camera: { flex: 1, width: '100%' },
    selfieOverlay: { position: 'absolute', bottom: 0, left: 0, right: 0, padding: 24, gap: 12, backgroundColor: 'rgba(0,0,0,0.55)' },
    selfieFaceGuide: {
        position: 'absolute', alignSelf: 'center', top: '12%',
        width: 250, height: 330, borderRadius: 999,
        borderWidth: 3, borderColor: 'rgba(255,255,255,0.85)', borderStyle: 'dashed',
    },
    selfieText: { color: '#FFFFFF', fontSize: 15, textAlign: 'center' },
    // Round the lines themselves, wherever they are in view.
    linesBox: { position: 'absolute', borderWidth: 3, borderRadius: 10, borderColor: '#FFFFFF' },
    linesBoxRead: { borderColor: '#34C759', backgroundColor: 'rgba(52,199,89,0.16)' },
    // Where to put them, with a sample of what they look like.
    linesSlot: {
        position: 'absolute', alignSelf: 'center', width: '62%', paddingVertical: 8, paddingHorizontal: 12,
        borderWidth: 2, borderStyle: 'dashed', borderRadius: 10, borderColor: 'rgba(255,255,255,0.8)',
        backgroundColor: 'rgba(0,0,0,0.25)',
    },
    linesSample: {
        fontFamily: Platform.select({ ios: 'Menlo', android: 'monospace' }),
        fontSize: 11, lineHeight: 16, color: 'rgba(255,255,255,0.85)',
    },
    // One at the top and one at the bottom, clear of Back and Close.
    capturePill: {
        position: 'absolute', alignSelf: 'center', maxWidth: '72%', flexDirection: 'row', alignItems: 'center', gap: 8,
        backgroundColor: 'rgba(0,0,0,0.62)', borderRadius: 999, paddingVertical: 8, paddingHorizontal: 16,
    },
    capturePillText: { flexShrink: 1, color: '#FFFFFF', fontSize: 15, fontWeight: '600', textAlign: 'center' },
    capturePillRead: { color: '#34C759' },
    docOption: {
        flexDirection: 'row', alignItems: 'center', gap: 14, alignSelf: 'stretch',
        backgroundColor: p.card, borderRadius: 12, borderWidth: 1, borderColor: p.border,
        padding: 16,
    },
    docOptionBody: { flex: 1 },
    docOptionTitle: { fontSize: 16, fontWeight: '600', color: p.textPrimary },
    docOptionSub: { fontSize: 13, color: p.textSecondary, marginTop: 2 },
    summaryCard: {
        alignSelf: 'stretch', backgroundColor: p.card, borderRadius: 12,
        borderWidth: 1, borderColor: p.border, paddingHorizontal: 16, paddingVertical: 4,
    },
    summaryRow: {
        flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', gap: 12,
        paddingVertical: 12, borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: p.border,
    },
    summaryValuePlain: { flexShrink: 1, fontSize: 15, fontWeight: '600', textAlign: 'right', color: p.textPrimary },
    summaryLabel: { fontSize: 14, color: p.textSecondary },
    summaryValue: { fontSize: 15, fontWeight: '600', color: p.textPrimary, letterSpacing: 1 },
});
