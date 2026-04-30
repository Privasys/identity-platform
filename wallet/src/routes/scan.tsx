import { useFocusEffect } from '@react-navigation/native';
import Ionicons from '@expo/vector-icons/Ionicons';
import { CameraView, CameraType, useCameraPermissions, BarcodeScanningResult } from 'expo-camera';
import { useRouter } from 'expo-router';
import { useState, useEffect, useCallback, useRef } from 'react';
import { Pressable, StyleSheet } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text, View } from '@/components/Themed';

export default function TabScanScreen() {
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const [facing] = useState<CameraType>('back');
    const [serviceUrl, setServiceUrl] = useState<string>();
    const [permission, requestPermission] = useCameraPermissions();
    const [rerenderTrigger, setRerenderTrigger] = useState(0);
    const navigating = useRef(false);
    const [cameraKey, setCameraKey] = useState(0);

    useFocusEffect(
        useCallback(() => {
            setServiceUrl(undefined);
            navigating.current = false;
            setCameraKey(k => k + 1);
        }, [])
    );

    useEffect(() => {
        (async () => {
            if (!permission) {
                const { status } = await requestPermission();
                if (status !== 'granted') {
                    console.warn('Camera permission not granted');
                }
            } else if (!permission.granted && permission.canAskAgain) {
                const { status } = await requestPermission();
                if (status !== 'granted') {
                    console.warn('Camera permission not granted');
                }
            }
        })();
    }, [permission, requestPermission]);

    useEffect(() => {
        if (!serviceUrl) return;
        router.push({ pathname: '/connect', params: { serviceUrl, source: 'qr' } });
    }, [serviceUrl]);

    if (!permission) {
        // Camera permissions are still loading.
        return <View />;
    }

    if (!permission.granted) {
        // Camera permissions are not granted yet.
        return (
            <View style={styles.container}>
                <Text style={styles.infoText}>We need your permission to show the camera.</Text>
                {permission.canAskAgain ? (
                    <>
                        <Text style={styles.infoText}>
                            Click the button below to grant permission to Privasys Wallet.
                        </Text>
                        <Text
                            style={styles.cameraAskButton}
                            onPress={async () => {
                                const { status } = await requestPermission();
                                if (status !== 'granted') {
                                    console.warn('Camera permission not granted');
                                }
                                setRerenderTrigger(rerenderTrigger + 1);
                            }}
                        >
                            Allow camera
                        </Text>
                    </>
                ) : (
                    <Text style={styles.infoText}>
                        You will need to go to your device settings to grant camera permission for
                        Privasys Wallet.
                    </Text>
                )}
            </View>
        );
    }

    const handleBarcode = (result: BarcodeScanningResult) => {
        if (navigating.current) return;
        if (result.type === 'qr') {
            // Helper: decode a base64url string to UTF-8
            const decodeB64Url = (s: string): string | null => {
                try {
                    let padded = s.replace(/-/g, '+').replace(/_/g, '/');
                    while (padded.length % 4 !== 0) padded += '=';
                    return atob(padded);
                } catch {
                    return null;
                }
            };

            // Helper: try to route a parsed JSON payload
            const routePayload = (json: string): boolean => {
                try {
                    const parsed = JSON.parse(json);

                    // Batch payload: { origin, sessionId, brokerUrl, apps: [...] }
                    if (parsed.apps && Array.isArray(parsed.apps)) {
                        navigating.current = true;
                        router.push({
                            pathname: '/batch-connect',
                            params: { payload: json }
                        });
                        return true;
                    }

                    // Single-app payload: { origin, sessionId, rpId, brokerUrl }
                    if (parsed.origin && parsed.sessionId && parsed.rpId) {
                        navigating.current = true;
                        router.push({
                            pathname: '/connect',
                            params: { payload: json }
                        });
                        return true;
                    }
                } catch {
                    // Not valid JSON
                }
                return false;
            };

            // 1. Try raw JSON payload (backward-compatible)
            if (routePayload(result.data)) return;

            // 2. Try universal link URL.
            //    Short form: https://privasys.id/scp?v=1&s=<sid>&h=<pin>&r=<host>
            //                — descriptor is fetched from the relay.
            //    Long form:  https://privasys.id/scp?p=<base64url(JSON)>
            //                — full descriptor in the URL (legacy).
            try {
                const url = new URL(result.data);
                if (url.pathname.startsWith('/scp')) {
                    const v = url.searchParams.get('v');
                    const s = url.searchParams.get('s');
                    const h = url.searchParams.get('h');
                    if (v && s && h) {
                        // Hand off to the /scp route, which handles fetch +
                        // hash verification and then redirects to /connect.
                        navigating.current = true;
                        const params: Record<string, string> = { v, s, h };
                        const r = url.searchParams.get('r');
                        if (r) params.r = r;
                        router.push({ pathname: '/scp', params });
                        return;
                    }
                    const b64 = url.searchParams.get('p');
                    if (b64) {
                        const json = decodeB64Url(b64);
                        if (json && routePayload(json)) return;
                    }
                }

                // Legacy URL format: /_/ prefix
                if (url.pathname.startsWith('/_/')) {
                    setServiceUrl(url.toString());
                    return;
                }
            } catch {
                // Not a valid URL
            }
        }
    };

    return (
        <View style={styles.container}>
            <CameraView
                key={cameraKey}
                style={styles.camera}
                facing={facing}
                autofocus="on"
                onBarcodeScanned={handleBarcode}
                barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
            />
            <Pressable
                style={[styles.closeButton, { top: insets.top + 12 }]}
                onPress={() => {
                    if (router.canGoBack()) router.back();
                    else router.replace('/(tabs)');
                }}
                accessibilityLabel="Close scanner"
                hitSlop={12}
            >
                <Ionicons name="close" size={26} color="#FFFFFF" />
            </Pressable>
        </View>
    );
}

const styles = StyleSheet.create({
    container: { flex: 1, alignItems: 'center', justifyContent: 'center' },
    closeButton: {
        position: 'absolute',
        left: 16,
        width: 40,
        height: 40,
        borderRadius: 20,
        backgroundColor: 'rgba(0,0,0,0.55)',
        alignItems: 'center',
        justifyContent: 'center'
    },
    infoText: {
        fontSize: 17,
        lineHeight: 24,
        paddingHorizontal: 100,
        paddingBottom: 30,
        textAlign: 'center'
    },
    cameraAskButton: {
        backgroundColor: '#007AFF',
        borderRadius: 8,
        color: 'white',
        fontSize: 17,
        lineHeight: 24,
        paddingHorizontal: 20,
        paddingVertical: 10,
        textAlign: 'center'
    },
    message: { textAlign: 'center', paddingBottom: 10 },
    camera: { flex: 1, flexGrow: 1, width: '100%' },
    buttonContainer: { flex: 1, flexDirection: 'row', backgroundColor: 'transparent', margin: 64 },
    button: { flex: 1, alignSelf: 'flex-end', alignItems: 'center' },
    text: { fontSize: 24, fontWeight: 'bold', color: 'white' }
});
