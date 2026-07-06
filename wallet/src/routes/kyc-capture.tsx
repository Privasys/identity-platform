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
import { manipulateAsync, SaveFormat } from 'expo-image-manipulator';
import { Stack, useRouter } from 'expo-router';
import { useEffect, useRef, useState } from 'react';
import { ActivityIndicator, Alert, KeyboardAvoidingView, Platform, Pressable, ScrollView, StyleSheet, View as NativeView, useWindowDimensions } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { AttestationView } from '@/components/AttestationView';
import { DataRequestConsent } from '@/components/DataRequestConsent';
import { ImportSelectionSheet } from '@/components/ImportSelectionSheet';
import { Text, View } from '@/components/Themed';
import { getProfileValue, setProfileValue } from '@/services/attributes';
import {
    applyGovAttributes, attestVerifier, getVerifierInfo, govAttributeCandidates, readDocumentMrz,
    verifyIdentity, type KycRecord, type VerifierAttestation,
} from '@/services/kyc';
import { useProfileStore, type ProfileAttribute } from '@/stores/profile';
import * as Emrtd from '../../modules/native-emrtd/src/index';

type Step = 'doctype' | 'consent' | 'attest' | 'capture' | 'read' | 'selfie' | 'verifying' | 'select' | 'done';
type DocType = 'passport' | 'id-card';
type CaptureState = 'positioning' | 'checking' | 'captured';

// Data-page (TD3 photo page) aspect ≈ 125×88 mm ≈ 1.42:1.
const DOC_PAGE_RATIO = 1.42;

// The raw inputs the verifier reads during capture, shown on the consent screen.
// These are transient processing inputs — consumed in the enclave and never
// stored — NOT disclosable profile attributes, so they are defined here (local to
// the capture flow) rather than in the shared canonical-attributes referential,
// which models stored/disclosed attributes (with scope + assurance). The verifier
// turns these into the gov-assured *output* attributes (birthdate, nationality,
// age_over_18, …) that the user picks in the post-verify "select" step; those
// outputs ARE in the referential. `doc` is the document noun (passport / ID card).
const KYC_INPUT_ITEMS: { key: string; icon: keyof typeof Ionicons.glyphMap; label: (doc: string) => string }[] = [
    { key: 'doc_page', icon: 'camera-outline', label: (doc) => `Your ${doc}'s photo page` },
    { key: 'nfc_chip', icon: 'hardware-chip-outline', label: (doc) => `Your ${doc} chip, read over NFC` },
    { key: 'live_selfie', icon: 'person-outline', label: () => 'A live selfie' },
];

/**
 * Crop a captured still to the on-screen guide frame (plus a generous margin) so
 * only the document page — not the surroundings — leaves the device. The preview
 * is shown "cover" (fills the viewport), so map the guide rect (screen points)
 * back to image pixels through that same cover transform. Returns base64, or null
 * to fall back to the full frame when the orientation/mapping can't be trusted —
 * a wrong crop must never break the enclave read.
 */
async function cropDocToFrame(
    shot: { uri?: string; width?: number; height?: number },
    view: { winW: number; winH: number; frameLeft: number; frameTop: number; frameW: number; frameH: number },
): Promise<string | null> {
    const { uri, width: iw, height: ih } = shot;
    if (!uri || !iw || !ih) return null;
    const { winW, winH, frameLeft, frameTop, frameW, frameH } = view;
    // Only crop when the image orientation matches the (landscape) viewport;
    // otherwise the screen→image mapping is wrong, so fall back to the full frame.
    if ((winW >= winH) !== (iw >= ih)) return null;

    const f = Math.max(winW / iw, winH / ih);   // image px → screen pts (cover)
    const offX = (iw * f - winW) / 2;
    const offY = (ih * f - winH) / 2;
    const m = frameW * 0.12;                     // generous margin around the guide

    const sx = Math.max(0, frameLeft - m);
    const sy = Math.max(0, frameTop - m);
    const sw = Math.min(winW, frameLeft + frameW + m) - sx;
    const sh = Math.min(winH, frameTop + frameH + m) - sy;

    let ox = (sx + offX) / f;
    let oy = (sy + offY) / f;
    let cw = sw / f;
    let ch = sh / f;
    ox = Math.max(0, Math.min(ox, iw));
    oy = Math.max(0, Math.min(oy, ih));
    cw = Math.max(1, Math.min(cw, iw - ox));
    ch = Math.max(1, Math.min(ch, ih - oy));

    const out = await manipulateAsync(
        uri,
        [{ crop: { originX: ox, originY: oy, width: cw, height: ch } }],
        { compress: 0.9, base64: true, format: SaveFormat.JPEG },
    );
    return out.base64 ?? null;
}

export default function KycCaptureScreen() {
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const [step, setStep] = useState<Step>('doctype');
    const [docType, setDocType] = useState<DocType>('passport');
    const [support, setSupport] = useState<Emrtd.EmrtdSupport | null>(null);
    const [docNumber, setDocNumber] = useState('');
    const [dob, setDob] = useState('');
    const [expiry, setExpiry] = useState('');
    const [docRead, setDocRead] = useState<Emrtd.EmrtdReadResult | null>(null);
    // The captured data-page frame — sent to the enclave for the heavy OCR +
    // visual↔chip cross-reference (GPG45 box 3). The wallet stays thin (no OCR
    // lib); it just forwards the image.
    const [docImage, setDocImage] = useState('');
    const [busy, setBusy] = useState(false);
    const [permission, requestPermission] = useCameraPermissions();
    const cameraRef = useRef<CameraView>(null);
    const [cameraReady, setCameraReady] = useState(false);
    const [cameraKey, setCameraKey] = useState(0);
    // Toggled off→on to kick expo-camera's continuous autofocus (see the
    // effect below); starts 'on' so behaviour is unchanged if the kick never
    // runs.
    const [autofocus, setAutofocus] = useState<'on' | 'off'>('on');
    const [captureState, setCaptureState] = useState<CaptureState>('positioning');
    const captureInFlight = useRef(false);
    const captureFinished = useRef(false);
    // The authoritative MRZ (BAC key) comes back from the enclave once we reach
    // the read step; gate the chip scan on it.
    const [mrzReadDone, setMrzReadDone] = useState(false);
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

    // Size the guide from the live landscape viewport and leave a dark margin so
    // every edge of the document remains visible.
    const { width: winW, height: winH } = useWindowDimensions();
    const usableH = winH - insets.top - insets.bottom;
    const frameW = Math.min(winW * 0.94, usableH * 0.9 * DOC_PAGE_RATIO);
    const frameH = frameW / DOC_PAGE_RATIO;
    const frameLeft = (winW - frameW) / 2;
    const frameTop = (winH - frameH) / 2;

    useEffect(() => {
        Emrtd.isSupported().then(setSupport).catch(() => setSupport({ supported: false }));
    }, []);

    // Force a fresh camera session once the landscape layout has settled. Mounting
    // CameraView the instant `step` becomes 'capture' coincides with the portrait
    // →landscape flip (Stack.Screen), so the preview can come up blank/white when
    // the session starts mid-rotation. Remounting via a changing `key` after the
    // viewport dimensions change is the same stale-stream reset the QR scanner
    // uses (routes/scan.tsx). Resetting cameraReady restarts the inspect loop.
    useEffect(() => {
        if (step !== 'capture') return;
        setCameraReady(false);
        setCameraKey((k) => k + 1);
    }, [step, winW, winH]);

    // Kick continuous autofocus. On iOS, expo-camera's `autofocus="on"`
    // intermittently fails to engage on the *first* camera session, so the
    // opening data-page still comes up soft and the only recovery the user has
    // is to close and reopen (a fresh session where AF happens to work).
    // Toggling the prop off→on forces the native layer to re-apply the focus
    // mode: once as soon as the camera is ready, then on a short cadence while
    // the user is still positioning, so a stuck focus self-heals in place. The
    // in-flight guard avoids flipping to fixed focus during a still capture.
    useEffect(() => {
        if (step !== 'capture' || !cameraReady) return;
        let cancelled = false;
        const kick = () => {
            if (cancelled || captureFinished.current || captureInFlight.current) return;
            setAutofocus('off');
            setTimeout(() => { if (!cancelled) setAutofocus('on'); }, 150);
        };
        kick();
        const iv = setInterval(kick, 2000);
        return () => { cancelled = true; clearInterval(iv); };
    }, [step, cameraReady]);

    // Resolve the verifier's name + origin for the consent card (no attestation
    // yet — that is the dedicated enclave page after consent).
    useEffect(() => {
        if (step !== 'consent' || verifierInfo) return;
        let cancelled = false;
        getVerifierInfo()
            .then((info) => { if (!cancelled) setVerifierInfo(info); })
            .catch(() => { if (!cancelled) setVerifierInfo({ origin: '', displayName: 'Privasys identity verifier' }); });
        return () => { cancelled = true; };
    }, [step, verifierInfo]);

    // Enclave verification page: attest the verifier and show the holder the same
    // "Verify Enclave" view they see at sign-in, before any document data is
    // captured. The digest pin + attestation are re-enforced again at send time.
    useEffect(() => {
        if (step !== 'attest') return;
        let cancelled = false;
        setVerifierAtt(null);
        setAttError(null);
        attestVerifier()
            .then((res) => { if (!cancelled) setVerifierAtt(res); })
            .catch((e) => {
                if (cancelled) return;
                console.warn('[KYC] enclave attestation failed:', e?.message);
                setAttError(e?.message ?? 'Could not verify the enclave.');
            });
        return () => { cancelled = true; };
    }, [step, attRetry]);

    const close = () => {
        if (router.canGoBack()) router.back();
        else router.replace('/(tabs)');
    };

    const docLabel = docType === 'passport' ? 'passport' : 'ID card';

    // ── Step 2: read the document chip over NFC (or dev stub) ────────────────
    const handleScan = async () => {
        setBusy(true);
        // Log the access-field shapes (not values) so a rejected key vs a chip
        // failure is diagnosable from the in-app logs.
        console.log(
            `[KYC] reading ${docType} chip — doc=${docNumber.trim().length}c dob=${dob.trim().length}c exp=${expiry.trim().length}c`,
        );
        try {
            const read = await Emrtd.readDocument({
                documentNumber: docNumber.trim(),
                dateOfBirth: dob.trim(),
                dateOfExpiry: expiry.trim(),
            });
            setDocRead(read);
            setStep('selfie');
        } catch (e: any) {
            console.warn('[KYC] chip read failed:', e?.message);
            // A rejected key (vs a chip/comms drop) is almost always a single
            // mistyped/misread character in the document number, so point the user
            // straight at the usual OCR-B look-alikes and let them fix it.
            const rejectedKey = typeof e?.message === 'string' && e.message.includes('InvalidMRZKey');
            if (rejectedKey) {
                Alert.alert(
                    "The code didn't match the chip",
                    'This usually means a look-alike character was misread (I vs 1, O vs 0, S vs 5, B vs 8, Z vs 2). Tap Retake photo, hold the page flat and steady, then try again.',
                );
            } else {
                Alert.alert(
                    'Could not read the chip',
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
            Alert.alert('Camera needed', 'Allow camera access to photograph your document.');
            return;
        }
        setDocNumber(''); setDob(''); setExpiry(''); setDocImage('');
        setMrzReadDone(false);
        captureFinished.current = false;
        setCameraReady(false);
        setCaptureState('positioning');
        setStep('capture');
    };

    // One clear photo of the data page does double duty: we OCR it for the chip
    // access key (BAC/PACE) and forward the same image to the enclave for the
    // visual↔chip cross-reference (GPG45 box 3).
    // CameraView does not expose raw preview frames. Sample a still roughly once
    // per second and run on-device OCR over it. scanMrz only succeeds when the
    // ICAO document-number, DOB and expiry check digits all validate, making it
    // a useful signal that the passport is sharp, readable and correctly placed.
    useEffect(() => {
        if (step !== 'capture' || !cameraReady) return;
        let cancelled = false;
        let timer: ReturnType<typeof setTimeout> | undefined;

        const inspectFrame = async () => {
            if (cancelled || captureFinished.current || captureInFlight.current) return;
            captureInFlight.current = true;
            setCaptureState('checking');
            try {
                // Fast, low-resolution probe purely to detect a sharp, well-placed
                // MRZ in frame — keeps the green positioning feedback snappy.
                const probe = await cameraRef.current?.takePictureAsync({
                    base64: true,
                    quality: 0.3,
                    shutterSound: false,
                });
                if (!probe?.base64 || cancelled) return;
                const mrz = await Emrtd.scanMrz(probe.base64); // throws until placed & sharp
                if (cancelled) return;

                captureFinished.current = true;
                setCaptureState('captured');
                // Provisional BAC/PACE key from the on-device read. This on-device
                // scan is unreliable on some documents, so it is only a positioning
                // trigger; the authoritative MRZ comes back from the enclave's
                // OmniMRZ read of docImage (see services/kyc.ts) — next step.
                setDocNumber(mrz.documentNumber);
                setDob(mrz.dateOfBirth);
                setExpiry(mrz.dateOfExpiry);

                // Grab one clean, full-quality frame for the enclave OCR (OmniMRZ)
                // + box-3 cross-reference. Crop it to the on-screen guide before it
                // leaves the device, so only the document page (not the
                // surroundings) is sent — falls back to the full frame if the crop
                // can't be computed, so a mapping quirk never breaks the read.
                const shot = await cameraRef.current?.takePictureAsync({
                    base64: true,
                    quality: 0.9,
                    shutterSound: false,
                });
                const cropped = shot
                    ? await cropDocToFrame(shot, { winW, winH, frameLeft, frameTop, frameW, frameH }).catch(() => null)
                    : null;
                setDocImage(cropped ?? shot?.base64 ?? probe.base64);

                // Keep the green confirmation visible long enough to register.
                await new Promise((resolve) => setTimeout(resolve, 500));
                if (!cancelled) setStep('read');
            } catch {
                if (!cancelled) setCaptureState('positioning');
            } finally {
                captureInFlight.current = false;
                if (!cancelled && !captureFinished.current) {
                    timer = setTimeout(inspectFrame, 350);
                }
            }
        };

        timer = setTimeout(inspectFrame, 400);
        return () => {
            cancelled = true;
            if (timer) clearTimeout(timer);
        };
    }, [cameraReady, step]);

    // ── Between Step 1 and Step 2: derive the BAC key from the captured image ─
    // The on-device OCR is unreliable on the OCR-B MRZ, so we send the data-page
    // photo to the attested enclave (OmniMRZ) and use its check-digit-validated
    // read as the chip access key. Runs once on entering the read step; a failed
    // read sends the user back to retake the photo.
    useEffect(() => {
        if (step !== 'read' || !docImage || mrzReadDone) return;
        let cancelled = false;
        (async () => {
            setBusy(true);
            try {
                const mrz = await readDocumentMrz(docImage);
                if (cancelled) return;
                setDocNumber(mrz.documentNumber);
                setDob(mrz.dateOfBirth);
                setExpiry(mrz.dateOfExpiry);
                setMrzReadDone(true);
            } catch (e: any) {
                if (cancelled) return;
                console.warn('[KYC] enclave MRZ read failed:', e?.message);
                Alert.alert(
                    "Couldn't read the photo page",
                    'Make sure the whole page is in frame, flat and well lit, then retake the photo.',
                    [{ text: 'Retake photo', onPress: () => { openCapture(); } }],
                );
            } finally {
                if (!cancelled) setBusy(false);
            }
        })();
        return () => { cancelled = true; };
    }, [step, docImage, mrzReadDone]);

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
        const current = curGiven || curFamily ? `\n\nKeep your current name (${[curGiven, curFamily].filter(Boolean).join(' ')})?` : '';
        Alert.alert(
            'Use your verified name?',
            `Your ID shows:\n  First name: ${idGiven ?? '—'}\n  Last name: ${idFamily ?? '—'}${current}`,
            [
                { text: 'Keep current', style: 'cancel' },
                {
                    text: 'Use ID name',
                    onPress: () => {
                        const rec = [{
                            verifier: 'privasys-kyc', verifierDisplayName: 'Privasys identity verifier',
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
            // Present the verified attributes for the holder to choose what to
            // import (same pattern as the IdP import flow), including the ID photo.
            const cands = govAttributeCandidates(result.record, docRead.portraitBase64);
            setVerifiedRecord(result.record);
            setCandidates(cands);
            setSelected(new Set(cands.map((c) => c.key)));
            setStep('select');
        } catch (e: any) {
            Alert.alert('Verification failed', e.message);
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
            Alert.alert('Camera error', e.message);
        }
    };

    return (
        <KeyboardAvoidingView
            style={styles.container}
            behavior={Platform.OS === 'ios' ? 'padding' : undefined}
        >
            <Stack.Screen options={{ orientation: step === 'capture' ? 'landscape' : 'portrait' }} />
            <Pressable style={[styles.close, { top: insets.top + 12 }]} onPress={close} hitSlop={12}>
                <Ionicons name="close" size={26} color="#8E8E93" />
            </Pressable>

            {step === 'doctype' && (
                <ScrollView
                    style={styles.flex}
                    contentContainerStyle={styles.padContent}
                    showsVerticalScrollIndicator={false}
                >
                    <Ionicons name="id-card-outline" size={40} color="#007AFF" />
                    <Text style={styles.title}>What are you verifying?</Text>
                    <Text style={styles.body}>
                        Pick the document with an NFC chip. We read it in a secure enclave, on device.
                    </Text>

                    <Pressable
                        style={styles.docOption}
                        onPress={() => { setDocType('passport'); setStep('consent'); }}
                    >
                        <Ionicons name="airplane-outline" size={22} color="#007AFF" />
                        <View style={styles.docOptionBody}>
                            <Text style={styles.docOptionTitle}>Passport</Text>
                            <Text style={styles.docOptionSub}>Any country&apos;s biometric passport</Text>
                        </View>
                        <Ionicons name="chevron-forward" size={18} color="#C7C7CC" />
                    </Pressable>

                    <Pressable
                        style={styles.docOption}
                        onPress={() => { setDocType('id-card'); setStep('consent'); }}
                    >
                        <Ionicons name="card-outline" size={22} color="#007AFF" />
                        <View style={styles.docOptionBody}>
                            <Text style={styles.docOptionTitle}>National ID card</Text>
                            <Text style={styles.docOptionSub}>Biometric (eMRTD) ID cards</Text>
                        </View>
                        <Ionicons name="chevron-forward" size={18} color="#C7C7CC" />
                    </Pressable>

                    <Text style={styles.note}>
                        Driving licences don&apos;t carry an NFC identity chip and can&apos;t be verified this way.
                    </Text>
                    {support && !support.supported && (
                        <Text style={[styles.note, { color: '#F59E0B' }]}>
                            NFC is unavailable on this device{support.reason ? ` (${support.reason})` : ''}, so the chip can&apos;t be read.
                        </Text>
                    )}
                </ScrollView>
            )}

            {step === 'consent' && (
                <DataRequestConsent
                    appName={verifierInfo?.displayName ?? 'Privasys identity verifier'}
                    origin={verifierInfo?.origin ?? ''}
                    appIcon="id-card-outline"
                    sectionTitle="WHAT THE VERIFIER READS"
                    sectionDescription={`To verify your ${docLabel}, the Privasys identity verifier processes the following in a secure enclave and keeps nothing once done. Your data otherwise stays on this device.`}
                    items={KYC_INPUT_ITEMS.map((i) => ({ key: i.key, icon: i.icon, label: i.label(docLabel) }))}
                    note="You'll verify the enclave next; your chip is read over NFC only after you agree."
                    denyLabel="Cancel"
                    approveLabel="Agree and continue"
                    onDeny={close}
                    onApprove={() => setStep('attest')}
                    contentTopInset={insets.top + 36}
                    actionsBottomInset={insets.bottom + 16}
                />
            )}

            {step === 'attest' && (
                attError ? (
                    <View style={styles.pad}>
                        <Ionicons name="alert-circle" size={40} color="#DC2626" />
                        <Text style={styles.title}>Couldn&apos;t verify the enclave</Text>
                        <Text style={styles.body}>{attError}</Text>
                        <Pressable style={styles.primary} onPress={() => setAttRetry((n) => n + 1)}>
                            <Text style={styles.primaryText}>Try again</Text>
                        </Pressable>
                        <Pressable style={styles.secondary} onPress={close}>
                            <Text style={styles.secondaryText}>Cancel</Text>
                        </Pressable>
                    </View>
                ) : !verifierAtt ? (
                    <View style={styles.pad}>
                        <ActivityIndicator size="large" color="#007AFF" />
                        <Text style={styles.body}>Verifying the enclave…</Text>
                    </View>
                ) : (
                    <AttestationView
                        attestation={verifierAtt.attestation}
                        rpId={verifierAtt.origin}
                        displayName={verifierAtt.displayName}
                        isChanged={false}
                        verificationLevel="fresh-as-verified"
                        onApprove={openCapture}
                        onReject={close}
                    />
                )
            )}

            {step === 'capture' && (
                <NativeView style={[styles.flex, { backgroundColor: '#000' }]}>
                    <CameraView
                        key={cameraKey}
                        ref={cameraRef}
                        style={styles.camera}
                        facing="back"
                        autofocus={autofocus}
                        active={step === 'capture'}
                        onCameraReady={() => {
                            console.log('[KYC] capture camera ready');
                            setCameraReady(true);
                        }}
                        onMountError={(e) => console.warn('[KYC] capture camera mount error:', e?.message)}
                    />
                    <NativeView style={[styles.captureMask, { top: 0, left: 0, right: 0, height: frameTop }]} pointerEvents="none" />
                    <NativeView
                        style={[styles.captureMask, { top: frameTop + frameH, left: 0, right: 0, bottom: 0 }]}
                        pointerEvents="none"
                    />
                    <NativeView
                        style={[styles.captureMask, { top: frameTop, left: 0, width: frameLeft, height: frameH }]}
                        pointerEvents="none"
                    />
                    <NativeView
                        style={[styles.captureMask, {
                            top: frameTop,
                            right: 0,
                            width: frameLeft,
                            height: frameH,
                        }]}
                        pointerEvents="none"
                    />
                    <NativeView
                        pointerEvents="none"
                        style={[
                            styles.frameGuide,
                            {
                                left: frameLeft,
                                top: frameTop,
                                width: frameW,
                                height: frameH,
                                borderColor: captureState === 'captured' ? '#34C759' : '#D1D5DB',
                            },
                        ]}
                    >
                        <PassportPageGuide active={captureState === 'captured'} />
                    </NativeView>
                    {captureState !== 'captured' && (
                        <NativeView style={[styles.captureHint, { top: insets.top + 14 }]} pointerEvents="none">
                            <Text style={styles.captureHintText}>
                                Position the camera over your {docLabel}&apos;s photo page
                            </Text>
                            <Text style={styles.captureHintSub}>
                                It captures on its own once the page is sharp and in frame
                            </Text>
                        </NativeView>
                    )}
                    <NativeView style={[styles.capturePrompt, { bottom: insets.bottom + 14 }]} pointerEvents="none">
                        {captureState === 'captured' ? (
                            <>
                                <Ionicons name="checkmark-circle" size={25} color="#34C759" />
                                <Text style={styles.capturePromptReady}>Passport captured</Text>
                            </>
                        ) : (
                            <>
                                <ActivityIndicator size="small" color="#FFFFFF" />
                                <Text style={styles.capturePromptText}>
                                    Fit the photo page inside the frame and hold still
                                </Text>
                            </>
                        )}
                    </NativeView>
                </NativeView>
            )}

            {step === 'read' && (
                <View style={styles.pad}>
                    {!mrzReadDone ? (
                        <>
                            <ActivityIndicator size="large" color="#007AFF" />
                            <Text style={styles.body}>Reading the photo page securely…</Text>
                            <Pressable style={styles.secondary} onPress={openCapture}>
                                <Text style={styles.secondaryText}>Cancel</Text>
                            </Pressable>
                        </>
                    ) : (
                        <>
                            <Ionicons name="phone-portrait-outline" size={40} color="#007AFF" />
                            <Text style={styles.title}>Step 2 · Scan the chip</Text>
                            <Text style={styles.body}>
                                Hold your {docLabel} flat against the top of your phone and keep it still. The chip
                                unlocks using the details read from your photo.
                            </Text>

                            <View style={styles.summaryCard}>
                                <SummaryRow label="Document" value={docNumber.trim()} />
                                <SummaryRow label="Date of birth" value={dob.trim()} />
                                <SummaryRow label="Expiry" value={expiry.trim()} />
                            </View>

                            <Pressable
                                style={[styles.primary, busy && styles.disabled]}
                                onPress={handleScan}
                                disabled={busy}
                            >
                                {busy ? (
                                    <ActivityIndicator color="#FFFFFF" />
                                ) : (
                                    <Text style={styles.primaryText}>Scan document chip</Text>
                                )}
                            </Pressable>
                            <Pressable style={styles.secondary} onPress={openCapture} disabled={busy}>
                                <Text style={styles.secondaryText}>Retake photo</Text>
                            </Pressable>
                        </>
                    )}
                </View>
            )}

            {step === 'selfie' && (
                <View style={styles.flex}>
                    <CameraView ref={cameraRef} style={styles.camera} facing="front" />
                    <View style={styles.selfieOverlay}>
                        <Text style={styles.selfieText}>
                            Take a quick selfie so the enclave can match it to your document photo.
                        </Text>
                        <Pressable style={styles.primary} onPress={handleSelfie}>
                            <Text style={styles.primaryText}>Capture & verify</Text>
                        </Pressable>
                    </View>
                </View>
            )}

            {step === 'verifying' && (
                <View style={styles.pad}>
                    <ActivityIndicator size="large" color="#007AFF" />
                    <Text style={styles.body}>Verifying your identity in the enclave…</Text>
                </View>
            )}

            {step === 'select' && (
                <ScrollView
                    style={styles.flex}
                    contentContainerStyle={styles.padContent}
                    showsVerticalScrollIndicator={false}
                >
                    <Ionicons name="shield-checkmark" size={40} color="#34C759" />
                    <Text style={styles.title}>Identity verified</Text>
                    <Text style={styles.body}>
                        Choose which government-verified details to add to your wallet.
                    </Text>
                    <ImportSelectionSheet
                        providerName="your ID"
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
                    <Ionicons name="checkmark-circle" size={48} color="#34C759" />
                    <Text style={styles.title}>All set</Text>
                    <Text style={styles.body}>
                        Your selected government-verified attributes have been added to your wallet.
                    </Text>
                    <Pressable style={styles.primary} onPress={close}>
                        <Text style={styles.primaryText}>Done</Text>
                    </Pressable>
                </View>
            )}
        </KeyboardAvoidingView>
    );
}

function PassportPageGuide({ active }: { active: boolean }) {
    const color = active ? '#34C759' : '#C7C7C7';
    const textLineWidths = ['88%', '95%', '82%', '92%', '76%', '96%', '85%'] as const;

    return (
        <>
            <NativeView style={[styles.innerSafeGuide, { borderColor: color }]} />
            <NativeView style={[styles.passportPhotoGuide, { borderColor: color }]}>
                <NativeView style={[styles.passportFaceGuide, { borderColor: color }]} />
            </NativeView>
            <NativeView style={styles.passportTextGuides}>
                {textLineWidths.map((width, index) => (
                    <NativeView
                        key={index}
                        style={[styles.passportTextLine, { backgroundColor: color, width }]}
                    />
                ))}
            </NativeView>
            <NativeView style={[styles.passportMrzGuide, { borderColor: color }]}>
                <Text style={[styles.passportMrzText, { color }]}>
                    {'<<<<<<<<<<<<<<<<<<<<<<<<<<<<'}
                </Text>
                <Text style={[styles.passportMrzText, { color }]}>
                    {'<<<<<<<<<<<<<<<<<<<<<<<<<<<<'}
                </Text>
            </NativeView>
            <NativeView style={[styles.guideCorner, styles.guideCornerTopLeft, { borderColor: active ? '#34C759' : '#F3F4F6' }]} />
            <NativeView style={[styles.guideCorner, styles.guideCornerTopRight, { borderColor: active ? '#34C759' : '#F3F4F6' }]} />
            <NativeView style={[styles.guideCorner, styles.guideCornerBottomRight, { borderColor: active ? '#34C759' : '#F3F4F6' }]} />
            <NativeView style={[styles.guideCorner, styles.guideCornerBottomLeft, { borderColor: active ? '#34C759' : '#F3F4F6' }]} />
        </>
    );
}

function SummaryRow({ label, value }: { label: string; value: string }) {
    return (
        <View style={styles.summaryRow}>
            <Text style={styles.summaryLabel}>{label}</Text>
            <Text style={styles.summaryValue}>{value || '—'}</Text>
        </View>
    );
}

const styles = StyleSheet.create({
    container: { flex: 1, backgroundColor: '#F8FAFB' },
    flex: { flex: 1 },
    pad: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 28, gap: 14 },
    padContent: { flexGrow: 1, alignItems: 'center', justifyContent: 'center', padding: 28, gap: 14, paddingTop: 72 },
    close: { position: 'absolute', right: 16, zIndex: 10, width: 40, height: 40, alignItems: 'center', justifyContent: 'center' },
    title: { fontSize: 22, fontWeight: '700', textAlign: 'center', color: '#0F172A' },
    body: { fontSize: 15, lineHeight: 22, textAlign: 'center', color: '#475569' },
    note: { fontSize: 13, color: '#F59E0B', textAlign: 'center' },
    orText: { fontSize: 13, color: '#94A3B8', textAlign: 'center' },
    input: {
        width: '100%', borderWidth: 1, borderColor: '#E2E8F0', borderRadius: 10,
        backgroundColor: '#FFFFFF',
        paddingHorizontal: 14, paddingVertical: 14, fontSize: 16, color: '#0F172A',
    },
    primary: {
        flexDirection: 'row', backgroundColor: '#007AFF', borderRadius: 10, paddingVertical: 14,
        paddingHorizontal: 24, alignItems: 'center', justifyContent: 'center', alignSelf: 'stretch',
    },
    primaryText: { color: '#FFFFFF', fontSize: 16, fontWeight: '600' },
    disabled: { opacity: 0.5 },
    secondary: { paddingVertical: 10, alignItems: 'center' },
    secondaryText: { color: '#007AFF', fontSize: 15 },
    camera: { flex: 1, width: '100%' },
    selfieOverlay: { position: 'absolute', bottom: 0, left: 0, right: 0, padding: 24, gap: 12, backgroundColor: 'rgba(0,0,0,0.55)' },
    selfieText: { color: '#FFFFFF', fontSize: 15, textAlign: 'center' },
    captureMask: { position: 'absolute', backgroundColor: 'rgba(0,0,0,0.3)' },
    frameGuide: {
        position: 'absolute', borderWidth: 3, borderRadius: 14,
        backgroundColor: 'transparent',
    },
    innerSafeGuide: {
        position: 'absolute', left: '2.7%', right: '2.7%', top: '3.8%', bottom: '3.8%',
        borderWidth: 1, borderStyle: 'dashed', borderRadius: 10, opacity: 0.72,
    },
    passportPhotoGuide: {
        position: 'absolute', left: '6.8%', top: '16%', width: '25%', height: '46%',
        borderWidth: 1.5, borderRadius: 7, alignItems: 'center', justifyContent: 'center',
    },
    passportFaceGuide: {
        width: '46%', height: '49%', borderWidth: 1.5, borderRadius: 999, opacity: 0.8,
    },
    passportTextGuides: {
        position: 'absolute', left: '37%', right: '7%', top: '17%', height: '45%',
        justifyContent: 'space-between',
    },
    passportTextLine: { height: 2, borderRadius: 2, opacity: 0.82 },
    passportMrzGuide: {
        position: 'absolute', left: '6.8%', right: '6.8%', bottom: '10.5%', height: '15.5%',
        borderWidth: 1.5, borderRadius: 6, justifyContent: 'center', paddingHorizontal: '3%',
    },
    passportMrzText: {
        fontFamily: Platform.select({ ios: 'Menlo', android: 'monospace' }),
        fontSize: 12, lineHeight: 15, letterSpacing: 0.3, opacity: 0.9,
    },
    guideCorner: { position: 'absolute', width: 34, height: 34 },
    guideCornerTopLeft: { left: -3, top: -3, borderLeftWidth: 5, borderTopWidth: 5, borderTopLeftRadius: 14 },
    guideCornerTopRight: { right: -3, top: -3, borderRightWidth: 5, borderTopWidth: 5, borderTopRightRadius: 14 },
    guideCornerBottomRight: { right: -3, bottom: -3, borderRightWidth: 5, borderBottomWidth: 5, borderBottomRightRadius: 14 },
    guideCornerBottomLeft: { left: -3, bottom: -3, borderLeftWidth: 5, borderBottomWidth: 5, borderBottomLeftRadius: 14 },
    capturePrompt: {
        position: 'absolute', left: 64, right: 64, flexDirection: 'row',
        alignItems: 'center', justifyContent: 'center', gap: 9,
    },
    capturePromptText: { color: '#FFFFFF', fontSize: 15, fontWeight: '600', textAlign: 'center' },
    capturePromptReady: { color: '#34C759', fontSize: 16, fontWeight: '700', textAlign: 'center' },
    captureHint: { position: 'absolute', left: 32, right: 32, alignItems: 'center', gap: 4 },
    captureHintText: { color: '#FFFFFF', fontSize: 16, fontWeight: '700', textAlign: 'center' },
    captureHintSub: { color: 'rgba(255,255,255,0.82)', fontSize: 13, textAlign: 'center' },
    docOption: {
        flexDirection: 'row', alignItems: 'center', gap: 14, alignSelf: 'stretch',
        backgroundColor: '#FFFFFF', borderRadius: 12, borderWidth: 1, borderColor: '#E2E8F0',
        padding: 16,
    },
    docOptionBody: { flex: 1 },
    docOptionTitle: { fontSize: 16, fontWeight: '600', color: '#0F172A' },
    docOptionSub: { fontSize: 13, color: '#64748B', marginTop: 2 },
    summaryCard: {
        alignSelf: 'stretch', backgroundColor: '#FFFFFF', borderRadius: 12,
        borderWidth: 1, borderColor: '#E2E8F0', paddingHorizontal: 16, paddingVertical: 4,
    },
    summaryRow: {
        flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
        paddingVertical: 12, borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: '#F1F5F9',
    },
    summaryLabel: { fontSize: 14, color: '#64748B' },
    summaryValue: { fontSize: 15, fontWeight: '600', color: '#0F172A', letterSpacing: 1 },
});
