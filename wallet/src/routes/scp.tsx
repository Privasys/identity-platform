import { useLocalSearchParams, useRouter, Redirect } from 'expo-router';
import { useMemo } from 'react';

/**
 * Universal link handler for QR deep links.
 *
 * When a regular phone camera scans a Privasys QR code, the URL
 * `https://privasys.id/scp?p=<base64url>` opens the wallet via
 * iOS associated domains or Android intent filters.
 *
 * This route decodes the `p` parameter and redirects to /connect
 * (single-app) or /batch-connect (multi-app).
 */
export default function ScpRedirect() {
    const { p } = useLocalSearchParams<{ p?: string }>();
    const router = useRouter();

    const target = useMemo(() => {
        if (!p) return null;
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
    }, [p]);

    if (target) {
        return <Redirect href={{ pathname: target.pathname, params: target.params }} />;
    }

    // No valid payload — go home
    return <Redirect href="/(tabs)" />;
}
