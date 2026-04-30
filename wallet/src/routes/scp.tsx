import { useLocalSearchParams, useRouter, Redirect } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { ActivityIndicator, View, Text } from 'react-native';

import { fetchDescriptor, DEFAULT_RELAY_HOST } from '@/services/descriptor';

/**
 * Universal link handler for QR deep links.
 *
 * Two QR formats are accepted:
 *
 *   1. Short form (current):
 *        https://privasys.id/scp?v=1&s=<sessionId>&h=<sha256-prefix>&r=<relayHost>
 *      The descriptor itself lives at the relay (PUT by the SDK). The
 *      wallet GETs it and verifies the body against the SHA-256 prefix
 *      pinned in the QR before trusting any field.
 *
 *   2. Legacy long form (kept for back-compat):
 *        https://privasys.id/scp?p=<base64url(JSON)>
 *      Entire descriptor packed into the URL. To be removed.
 */
export default function ScpRedirect() {
    const { p, v, s, h, r } = useLocalSearchParams<{
        p?: string;
        v?: string;
        s?: string;
        h?: string;
        r?: string;
    }>();
    const router = useRouter();

    // Short-form: fetch descriptor from relay, verify, then route
    const isShort = !!(v && s && h);
    const [shortError, setShortError] = useState<string | null>(null);
    const [shortRouting, setShortRouting] = useState(false);

    useEffect(() => {
        if (!isShort || shortRouting) return;
        const relayHost = r ?? DEFAULT_RELAY_HOST;
        let cancelled = false;
        (async () => {
            try {
                const desc = await fetchDescriptor(relayHost, s!, h!);
                if (cancelled) return;
                setShortRouting(true);
                const json = JSON.stringify(desc);
                if (desc.apps && Array.isArray(desc.apps)) {
                    router.replace({ pathname: '/batch-connect', params: { payload: json } });
                } else if (desc.origin && desc.sessionId && desc.rpId) {
                    router.replace({ pathname: '/connect', params: { payload: json, source: 'qr' } });
                } else {
                    setShortError('Descriptor is missing required fields');
                }
            } catch (e: any) {
                if (cancelled) return;
                setShortError(e?.message ?? 'Failed to load sign-in descriptor');
            }
        })();
        return () => {
            cancelled = true;
        };
    }, [isShort, r, s, h, shortRouting]);

    // Legacy long-form: decode synchronously and redirect
    const legacyTarget = useMemo(() => {
        if (isShort || !p) return null;
        try {
            let padded = p.replace(/-/g, '+').replace(/_/g, '/');
            while (padded.length % 4 !== 0) padded += '=';
            const json = atob(padded);
            const parsed = JSON.parse(json);

            if (parsed.apps && Array.isArray(parsed.apps)) {
                return { pathname: '/batch-connect' as const, params: { payload: json } };
            }
            if (parsed.origin && parsed.sessionId && parsed.rpId) {
                return { pathname: '/connect' as const, params: { payload: json, source: 'qr' as const } };
            }
        } catch {
            // Invalid payload
        }
        return null;
    }, [p, isShort]);

    if (legacyTarget) {
        return <Redirect href={{ pathname: legacyTarget.pathname, params: legacyTarget.params }} />;
    }

    if (isShort) {
        if (shortError) {
            return (
                <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24 }}>
                    <Text style={{ fontSize: 16, color: '#c00', textAlign: 'center', marginBottom: 12 }}>
                        Sign-in failed
                    </Text>
                    <Text style={{ fontSize: 14, color: '#444', textAlign: 'center' }}>{shortError}</Text>
                </View>
            );
        }
        return (
            <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center' }}>
                <ActivityIndicator size="large" color="#007AFF" />
                <Text style={{ marginTop: 16, color: '#666' }}>Loading sign-in request…</Text>
            </View>
        );
    }

    // Nothing usable in the URL
    return <Redirect href="/(tabs)" />;
}
