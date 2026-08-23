import { useLocalSearchParams, useRouter, Redirect } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { ActivityIndicator, View, Text, Pressable } from 'react-native';

import { fetchDescriptor, DEFAULT_RELAY_HOST } from '@/services/descriptor';

import { usePalette } from '@/components/Themed';
import { useTranslation } from 'react-i18next';

/**
 * Turn a raw descriptor-fetch error into a plain-language message. The most
 * common case by far is an expired QR: sign-in codes live for only a few
 * minutes on the relay, so a code scanned late (or re-scanned) 404s.
 */
/**
 * Map a raw error to the copy KEYS for a friendly explanation. Keys rather
 * than strings because this runs outside the component and has no `t`.
 */
function friendlyError(raw: string): { titleKey: string; bodyKey: string; canRescan: boolean } {
    const m = raw.toLowerCase();
    if (m.includes('not found') || m.includes('404')) {
        return {
            titleKey: 'scp.expiredTitle',
            bodyKey: 'scp.expiredBody',
            canRescan: true,
        };
    }
    if (m.includes('hash mismatch')) {
        return {
            titleKey: 'scp.untrustedTitle',
            bodyKey: 'scp.untrustedBody',
            canRescan: true,
        };
    }
    if (m.includes('not supported') || m.includes('version')) {
        return {
            titleKey: 'scp.updateTitle',
            bodyKey: 'scp.updateBody',
            canRescan: false,
        };
    }
    return {
        titleKey: 'scp.failedTitle',
        bodyKey: 'scp.failedBody',
        canRescan: true,
    };
}

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
    const { t } = useTranslation();
    const { p, v, s, h, r } = useLocalSearchParams<{
        p?: string;
        v?: string;
        s?: string;
        h?: string;
        r?: string;
    }>();
    const router = useRouter();
    const palette = usePalette();

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
                    setShortError(t('scp.missingFields'));
                }
            } catch (e: any) {
                if (cancelled) return;
                setShortError(e?.message ?? t('scp.loadFailed'));
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
            const { titleKey, bodyKey, canRescan } = friendlyError(shortError);
            return (
                <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24 }}>
                    <Text style={{ fontSize: 18, fontWeight: '600', color: palette.danger, textAlign: 'center', marginBottom: 12 }}>
                        {t(titleKey)}
                    </Text>
                    <Text style={{ fontSize: 15, color: palette.textSecondary, textAlign: 'center', lineHeight: 21, marginBottom: 28 }}>
                        {t(bodyKey)}
                    </Text>
                    {canRescan && (
                        <Pressable
                            onPress={() => router.replace('/scan')}
                            style={{
                                backgroundColor: palette.action,
                                paddingVertical: 14,
                                paddingHorizontal: 32,
                                borderRadius: 12,
                                alignSelf: 'stretch',
                                alignItems: 'center',
                                marginBottom: 12,
                            }}
                        >
                            <Text style={{ color: '#FFFFFF', fontSize: 16, fontWeight: '600' }}>Scan again</Text>
                        </Pressable>
                    )}
                    <Pressable
                        onPress={() => router.replace('/(tabs)')}
                        style={{
                            paddingVertical: 14,
                            paddingHorizontal: 32,
                            borderRadius: 12,
                            alignSelf: 'stretch',
                            alignItems: 'center',
                        }}
                    >
                        <Text style={{ color: palette.textSecondary, fontSize: 16, fontWeight: '500' }}>
                            {t('scp.backToWallet')}
                        </Text>
                    </Pressable>
                </View>
            );
        }
        return (
            <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center' }}>
                <ActivityIndicator size="large" color={palette.action} />
                <Text style={{ marginTop: 16, color: palette.textSecondary }}>{t('scp.loading')}</Text>
            </View>
        );
    }

    // Nothing usable in the URL
    return <Redirect href="/(tabs)" />;
}
