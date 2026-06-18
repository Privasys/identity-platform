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
import { useRouter } from 'expo-router';
import { useEffect, useRef, useState } from 'react';
import { ActivityIndicator, Alert, KeyboardAvoidingView, Platform, Pressable, ScrollView, StyleSheet, TextInput } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text, View } from '@/components/Themed';
import { verifyIdentity } from '@/services/kyc';
import * as Emrtd from '../../modules/native-emrtd/src/index';

type Step = 'doctype' | 'mrz' | 'mrz-camera' | 'read' | 'selfie' | 'verifying' | 'done';
type DocType = 'passport' | 'id-card';

// Dev-only stub document fields, used when the device can't read a chip yet so
// the verify_identity → auto-fill round-trip is exercisable. Never used in prod.
const DEV_STUB_FIELDS: Record<string, string> = {
    given_name: 'Ada',
    family_name: 'Lovelace',
    birthdate: '1990-05-17',
    nationality: 'GBR',
};

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
    const [busy, setBusy] = useState(false);
    const [permission, requestPermission] = useCameraPermissions();
    const cameraRef = useRef<CameraView>(null);
    const scanningRef = useRef(false);

    useEffect(() => {
        Emrtd.isSupported().then(setSupport).catch(() => setSupport({ supported: false }));
    }, []);

    // Continuously OCR the MRZ while the camera is open: scan a frame, and only
    // accept it when the `mrz` parser confirms the check digits (so a misread
    // never yields a wrong BAC key). Stops as soon as a valid MRZ is found.
    useEffect(() => {
        if (step !== 'mrz-camera') {
            scanningRef.current = false;
            return;
        }
        scanningRef.current = true;
        let cancelled = false;
        // Require the same MRZ from two separate frames before accepting it. A
        // single OCR misread (e.g. the OCR-B 'I' read as '1') rarely repeats
        // identically, so consensus filters out transient errors that would
        // otherwise pass the check digits as a self-consistent but wrong key.
        let previous: string | null = null;
        const loop = async () => {
            while (scanningRef.current && !cancelled) {
                try {
                    const photo = await cameraRef.current?.takePictureAsync({
                        base64: true,
                        quality: 0.5,
                        skipProcessing: true,
                        shutterSound: false,
                    });
                    if (photo?.base64) {
                        const mrz = await Emrtd.scanMrz(photo.base64);
                        if (cancelled) return;
                        const fingerprint = `${mrz.documentNumber}|${mrz.dateOfBirth}|${mrz.dateOfExpiry}`;
                        if (fingerprint === previous) {
                            scanningRef.current = false;
                            setDocNumber(mrz.documentNumber);
                            setDob(mrz.dateOfBirth);
                            setExpiry(mrz.dateOfExpiry);
                            setStep('mrz');
                            return;
                        }
                        previous = fingerprint;
                    }
                } catch {
                    // No valid MRZ in this frame (or camera not ready) — keep trying.
                }
                await new Promise((r) => setTimeout(r, 350));
            }
        };
        const t = setTimeout(loop, 800); // let the camera mount first
        return () => {
            cancelled = true;
            scanningRef.current = false;
            clearTimeout(t);
        };
    }, [step]);

    const close = () => {
        if (router.canGoBack()) router.back();
        else router.replace('/(tabs)');
    };

    const docLabel = docType === 'passport' ? 'passport' : 'ID card';
    const mrzReady = docNumber.trim().length > 0 && dob.trim().length === 6 && expiry.trim().length === 6;

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
                    'Check the document number for look-alike characters: I vs 1, O vs 0, S vs 5, B vs 8, Z vs 2. Tap Edit details to correct it, then try again.',
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

    const handleUseDevStub = () => {
        setDocRead({ fields: DEV_STUB_FIELDS });
        setStep('selfie');
    };

    // ── MRZ OCR: photograph the photo page, auto-fill the access fields ─────
    const openMrzCamera = async () => {
        if (permission && !permission.granted) {
            const res = await requestPermission();
            if (!res.granted) {
                Alert.alert('Camera needed', 'Allow camera access to scan your document.');
                return;
            }
        }
        setStep('mrz-camera');
    };


    // ── Step 2: capture a live selfie (for the enclave face match) ──────────
    const captureAndVerify = async (liveImageBase64?: string) => {
        if (!docRead) return;
        setStep('verifying');
        setBusy(true);
        try {
            const result = await verifyIdentity(docRead, { liveImageBase64 });
            console.log('[KYC] verified — filled:', result.filled.join(', '));
            setStep('done');
        } catch (e: any) {
            Alert.alert('Verification failed', e.message);
            setStep('selfie');
        } finally {
            setBusy(false);
        }
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
                        onPress={() => { setDocType('passport'); setStep('mrz'); }}
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
                        onPress={() => { setDocType('id-card'); setStep('mrz'); }}
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
                </ScrollView>
            )}

            {step === 'mrz' && (
                <ScrollView
                    style={styles.flex}
                    contentContainerStyle={styles.padContent}
                    keyboardShouldPersistTaps="handled"
                    showsVerticalScrollIndicator={false}
                >
                    <Ionicons name="scan-outline" size={40} color="#007AFF" />
                    <Text style={styles.title}>Step 1 · Read the code</Text>
                    <Text style={styles.body}>
                        Scan the machine-readable zone (the rows of {'<<<'} on your {docLabel}) to fill
                        these automatically, or enter them by hand. This unlocks the chip in the next step.
                    </Text>

                    {support?.supported && (
                        <Pressable style={styles.primary} onPress={openMrzCamera}>
                            <Ionicons name="camera-outline" size={18} color="#FFFFFF" />
                            <Text style={styles.primaryText}>Scan {docLabel} to auto-fill</Text>
                        </Pressable>
                    )}
                    <Text style={styles.orText}>or enter the details by hand</Text>

                    <TextInput
                        style={styles.input}
                        value={docNumber}
                        onChangeText={setDocNumber}
                        placeholder="Document number"
                        placeholderTextColor="#94A3B8"
                        autoCapitalize="characters"
                    />
                    <TextInput
                        style={styles.input}
                        value={dob}
                        onChangeText={setDob}
                        placeholder="Date of birth (YYMMDD)"
                        placeholderTextColor="#94A3B8"
                        keyboardType="number-pad"
                        maxLength={6}
                    />
                    <TextInput
                        style={styles.input}
                        value={expiry}
                        onChangeText={setExpiry}
                        placeholder="Expiry date (YYMMDD)"
                        placeholderTextColor="#94A3B8"
                        keyboardType="number-pad"
                        maxLength={6}
                    />

                    {support && !support.supported && (
                        <Text style={styles.note}>
                            NFC scanning is unavailable on this device{support.reason ? ` (${support.reason})` : ''}.
                        </Text>
                    )}

                    <Pressable
                        style={[styles.primary, (!mrzReady || !support?.supported) && styles.disabled]}
                        onPress={() => setStep('read')}
                        disabled={!mrzReady || !support?.supported}
                    >
                        <Text style={styles.primaryText}>Continue</Text>
                    </Pressable>

                    {__DEV__ && (
                        <Pressable style={styles.secondary} onPress={handleUseDevStub}>
                            <Text style={styles.secondaryText}>Use test identity (dev)</Text>
                        </Pressable>
                    )}
                </ScrollView>
            )}

            {step === 'read' && (
                <View style={styles.pad}>
                    <Ionicons name="phone-portrait-outline" size={40} color="#007AFF" />
                    <Text style={styles.title}>Step 2 · Scan the chip</Text>
                    <Text style={styles.body}>
                        Hold your {docLabel} flat against the top of your phone and keep it still. The chip
                        unlocks with the code from step 1.
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
                    <Pressable style={styles.secondary} onPress={() => setStep('mrz')} disabled={busy}>
                        <Text style={styles.secondaryText}>Edit details</Text>
                    </Pressable>
                </View>
            )}

            {step === 'mrz-camera' && (
                <View style={styles.flex}>
                    <CameraView ref={cameraRef} style={styles.camera} facing="back" autofocus="on" />
                    <View style={styles.selfieOverlay}>
                        <View style={styles.scanningRow}>
                            <ActivityIndicator color="#FFFFFF" />
                            <Text style={styles.selfieText}>
                                Hold the bottom two lines of {'<<<'} steady in view…
                            </Text>
                        </View>
                        <Pressable style={styles.secondary} onPress={() => setStep('mrz')}>
                            <Text style={[styles.secondaryText, { color: '#FFFFFF' }]}>Enter manually instead</Text>
                        </Pressable>
                    </View>
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

            {step === 'done' && (
                <View style={styles.pad}>
                    <Ionicons name="checkmark-circle" size={48} color="#34C759" />
                    <Text style={styles.title}>Identity verified</Text>
                    <Text style={styles.body}>
                        Your government-verified attributes have been added to your wallet.
                    </Text>
                    <Pressable style={styles.primary} onPress={close}>
                        <Text style={styles.primaryText}>Done</Text>
                    </Pressable>
                </View>
            )}
        </KeyboardAvoidingView>
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
    scanningRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 10 },
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
