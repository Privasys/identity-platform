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

type Step = 'mrz' | 'mrz-camera' | 'selfie' | 'verifying' | 'done';

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
    const [step, setStep] = useState<Step>('mrz');
    const [support, setSupport] = useState<Emrtd.EmrtdSupport | null>(null);
    const [docNumber, setDocNumber] = useState('');
    const [dob, setDob] = useState('');
    const [expiry, setExpiry] = useState('');
    const [fields, setFields] = useState<Record<string, string> | null>(null);
    const [busy, setBusy] = useState(false);
    const [ocrBusy, setOcrBusy] = useState(false);
    const [permission, requestPermission] = useCameraPermissions();
    const cameraRef = useRef<CameraView>(null);

    useEffect(() => {
        Emrtd.isSupported().then(setSupport).catch(() => setSupport({ supported: false }));
    }, []);

    const close = () => {
        if (router.canGoBack()) router.back();
        else router.replace('/(tabs)');
    };

    // ── Step 1: read the document (NFC chip, or dev stub) ───────────────────
    const handleScan = async () => {
        setBusy(true);
        try {
            const read = await Emrtd.readDocument({
                documentNumber: docNumber.trim(),
                dateOfBirth: dob.trim(),
                dateOfExpiry: expiry.trim(),
            });
            setFields(read.fields);
            setStep('selfie');
        } catch (e: any) {
            Alert.alert('Could not read the document', e.message);
        } finally {
            setBusy(false);
        }
    };

    const handleUseDevStub = () => {
        setFields(DEV_STUB_FIELDS);
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

    const handleScanMrz = async () => {
        setOcrBusy(true);
        try {
            const photo = await cameraRef.current?.takePictureAsync({ base64: true, quality: 0.5 });
            if (!photo?.base64) throw new Error('No photo captured');
            const mrz = await Emrtd.scanMrz(photo.base64);
            setDocNumber(mrz.documentNumber);
            setDob(mrz.dateOfBirth);
            setExpiry(mrz.dateOfExpiry);
            setStep('mrz');
        } catch (e: any) {
            Alert.alert('Could not read the MRZ', `${e.message}\n\nYou can also enter the details by hand.`);
        } finally {
            setOcrBusy(false);
        }
    };

    // ── Step 2: capture a live selfie (for the enclave face match) ──────────
    const captureAndVerify = async (liveImageBase64?: string) => {
        if (!fields) return;
        setStep('verifying');
        setBusy(true);
        try {
            const result = await verifyIdentity(fields, { liveImageBase64 });
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

            {step === 'mrz' && (
                <ScrollView
                    style={styles.flex}
                    contentContainerStyle={styles.padContent}
                    keyboardShouldPersistTaps="handled"
                    showsVerticalScrollIndicator={false}
                >
                    <Ionicons name="id-card-outline" size={40} color="#007AFF" />
                    <Text style={styles.title}>Verify your ID</Text>
                    <Text style={styles.body}>
                        Scan the machine-readable zone (the two lines of {'<<<'} at the bottom of the
                        photo page) to fill these automatically, or enter them by hand. The chip
                        stays locked until your phone proves these values, then you hold the document
                        to the top of your phone to read it. Verified in a secure enclave, on device.
                    </Text>

                    {support?.supported && (
                        <Pressable style={styles.primary} onPress={openMrzCamera}>
                            <Ionicons name="camera-outline" size={18} color="#FFFFFF" />
                            <Text style={styles.primaryText}>Scan passport to auto-fill</Text>
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
                        style={[styles.primary, (busy || !support?.supported) && styles.disabled]}
                        onPress={handleScan}
                        disabled={busy || !support?.supported}
                    >
                        {busy ? (
                            <ActivityIndicator color="#FFFFFF" />
                        ) : (
                            <Text style={styles.primaryText}>Scan document chip</Text>
                        )}
                    </Pressable>

                    {__DEV__ && (
                        <Pressable style={styles.secondary} onPress={handleUseDevStub}>
                            <Text style={styles.secondaryText}>Use test identity (dev)</Text>
                        </Pressable>
                    )}
                </ScrollView>
            )}

            {step === 'mrz-camera' && (
                <View style={styles.flex}>
                    <CameraView ref={cameraRef} style={styles.camera} facing="back" autofocus="on" />
                    <View style={styles.selfieOverlay}>
                        <Text style={styles.selfieText}>
                            Frame the two lines of {'<<<'} at the bottom of the passport photo page.
                        </Text>
                        <Pressable style={styles.primary} onPress={handleScanMrz} disabled={ocrBusy}>
                            {ocrBusy ? (
                                <ActivityIndicator color="#FFFFFF" />
                            ) : (
                                <Text style={styles.primaryText}>Capture MRZ</Text>
                            )}
                        </Pressable>
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
});
