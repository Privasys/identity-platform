import { useFocusEffect } from '@react-navigation/native';
import { CameraView, CameraType, useCameraPermissions, BarcodeScanningResult } from 'expo-camera';
import { useRouter } from 'expo-router';
import { useState, useEffect, useCallback, useRef } from 'react';
import { StyleSheet } from 'react-native';

import { Text, View } from '@/components/Themed';

export default function TabScanScreen() {
    const router = useRouter();
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
        router.push({ pathname: '/connect', params: { serviceUrl } });
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
            try {
                // Try parsing as JSON payload (new format)
                const parsed = JSON.parse(result.data);

                // Batch payload: { origin, sessionId, brokerUrl, apps: [...] }
                if (parsed.apps && Array.isArray(parsed.apps)) {
                    navigating.current = true;
                    router.push({
                        pathname: '/batch-connect',
                        params: { payload: result.data }
                    });
                    return;
                }

                // Single-app payload: { origin, sessionId, rpId, brokerUrl }
                if (parsed.origin && parsed.sessionId && parsed.rpId) {
                    navigating.current = true;
                    router.push({
                        pathname: '/connect',
                        params: { payload: result.data }
                    });
                    return;
                }
            } catch {
                // Not JSON — try as URL (legacy format)
            }

            try {
                const url = new URL(result.data);
                if (url.pathname.startsWith('/_/')) {
                    setServiceUrl(url.toString());
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
        </View>
    );
}

const styles = StyleSheet.create({
    container: { flex: 1, alignItems: 'center', justifyContent: 'center' },
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
