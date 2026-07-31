// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

import {
    useState,
    useEffect,
    useCallback,
    useRef,
    createElement,
    type ReactNode,
} from 'react';
import { PrivasysAuth } from './client';
import type { AuthConfig, AuthEvents, AuthResult, AuthState } from './types';
import { AttributePicker, attributeBadge, type AttributePickerConfig } from './attributes-ui';
import type { CanonicalAttribute } from './attributes';

// ---------------------------------------------------------------------------
// Hook: usePrivasysAuth
// ---------------------------------------------------------------------------

export interface UsePrivasysAuthReturn {
    /** Current auth state. */
    state: AuthState;
    /** The QR payload string — render this with any QR library. */
    qrPayload: string | null;
    /** The session ID for this auth attempt. */
    sessionId: string | null;
    /** Start a QR-based auth flow. */
    startQR: () => void;
    /** For returning users: trigger a push notification. */
    startPush: (pushToken: string) => void;
    /** Cancel the active flow. */
    cancel: () => void;
    /** The auth result once authentication completes. */
    result: AuthResult | null;
    /** Error, if any. */
    error: Error | null;
}

/**
 * React hook for Privasys Wallet authentication.
 *
 * ```tsx
 * const { state, qrPayload, startQR, result } = usePrivasysAuth({
 *   rpId: 'myapp.apps.privasys.org',
 *   brokerUrl: 'wss://relay.privasys.org',
 * });
 * ```
 */
export function usePrivasysAuth(
    config: AuthConfig,
    events?: AuthEvents,
): UsePrivasysAuthReturn {
    const [state, setState] = useState<AuthState>('idle');
    const [qrPayload, setQrPayload] = useState<string | null>(null);
    const [sessionId, setSessionId] = useState<string | null>(null);
    const [result, setResult] = useState<AuthResult | null>(null);
    const [error, setError] = useState<Error | null>(null);
    const authRef = useRef<PrivasysAuth | null>(null);

    // Stable client reference
    useEffect(() => {
        const auth = new PrivasysAuth(config, {
            ...events,
            onStateChange: (s) => {
                setState(s);
                events?.onStateChange?.(s);
            },
            onAuthenticated: (r) => {
                setResult(r);
                events?.onAuthenticated?.(r);
            },
            onError: (e) => {
                setError(e);
                events?.onError?.(e);
            },
        });
        authRef.current = auth;
        return () => auth.destroy();
        // Only recreate if rpId or brokerUrl changes
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [config.rpId, config.brokerUrl]);

    const startQR = useCallback(() => {
        const auth = authRef.current;
        if (!auth) return;
        setResult(null);
        setError(null);
        const { sessionId: sid, payload } = auth.createQR();
        setSessionId(sid);
        setQrPayload(payload);
        auth.waitForResult(sid).catch((err: Error) => setError(err));
    }, []);

    const startPush = useCallback((pushToken: string) => {
        const auth = authRef.current;
        if (!auth) return;
        setResult(null);
        setError(null);
        auth.notifyAndWait(pushToken).then(
            (r) => setResult(r),
            (err: Error) => setError(err),
        );
    }, []);

    const cancel = useCallback(() => {
        const auth = authRef.current;
        if (!auth || !sessionId) return;
        auth.cancel(sessionId);
        setQrPayload(null);
        setSessionId(null);
    }, [sessionId]);

    return { state, qrPayload, sessionId, startQR, startPush, cancel, result, error };
}

// ---------------------------------------------------------------------------
// Component: PrivasysLoginButton
// ---------------------------------------------------------------------------

export interface PrivasysLoginButtonProps {
    config: AuthConfig;
    /** Called on successful auth. */
    onSuccess?: (result: AuthResult) => void;
    /** Called on error. */
    onError?: (error: Error) => void;
    /** Custom render function for the QR content area. */
    renderQR?: (payload: string) => ReactNode;
    /** Label for the button. */
    label?: string;
    /** Optional className for the wrapper. */
    className?: string;
}

/**
 * Pre-built login component that shows a "Sign in with Privasys" button
 * and a QR code when clicked. The QR rendering is delegated to `renderQR`
 * since QR libraries vary — this avoids forcing a specific dependency.
 */
export function PrivasysLoginButton(props: PrivasysLoginButtonProps): ReactNode {
    const {
        config,
        onSuccess,
        onError,
        renderQR,
        label = 'Sign in with Privasys',
        className,
    } = props;

    const { state, qrPayload, startQR, result, error } = usePrivasysAuth(config, {
        onAuthenticated: onSuccess,
        onError,
    });

    // Notify parent on result/error changes
    useEffect(() => {
        if (result) onSuccess?.(result);
    }, [result, onSuccess]);

    useEffect(() => {
        if (error) onError?.(error);
    }, [error, onError]);

    const showQR = state !== 'idle' && state !== 'complete' && state !== 'error' && qrPayload;

    return createElement('div', { className },
        state === 'idle' &&
            createElement('button', {
                type: 'button',
                onClick: startQR,
                'data-privasys': 'login-btn',
            }, label),

        showQR && renderQR
            ? renderQR(qrPayload)
            : showQR && createElement('pre', {
                'data-privasys': 'qr-payload',
                style: {
                    fontFamily: 'monospace',
                    fontSize: '10px',
                    wordBreak: 'break-all' as const,
                    whiteSpace: 'pre-wrap' as const,
                },
            }, qrPayload),

        state === 'wallet-connected' &&
            createElement('p', { 'data-privasys': 'status' }, 'Wallet connected — approve on your phone'),

        state === 'authenticating' &&
            createElement('p', { 'data-privasys': 'status' }, 'Verifying...'),

        state === 'complete' &&
            createElement('p', { 'data-privasys': 'status' }, 'Signed in!'),

        state === 'error' &&
            createElement('p', {
                'data-privasys': 'status',
                style: { color: 'red' },
            }, error?.message ?? 'Authentication failed'),

        state === 'timeout' &&
            createElement('p', {
                'data-privasys': 'status',
                style: { color: 'orange' },
            }, 'Timed out — try again'),
    );
}

// ---------------------------------------------------------------------------
// Attribute UI
// ---------------------------------------------------------------------------

/**
 * The attribute picker as a React component.
 *
 * The picker itself is plain DOM in a closed shadow root (see attributes-ui.ts),
 * so this is a mount point rather than a reimplementation: two renderings of the
 * same trust markers would eventually disagree, and the one a user is looking at
 * would be whichever framework their vendor happened to pick.
 */
export function PrivasysAttributePicker(
    props: Omit<AttributePickerConfig, 'container'> & { className?: string },
): ReactNode {
    const mount = useRef<HTMLDivElement | null>(null);
    const picker = useRef<AttributePicker | null>(null);
    const { className, onChange, selected, attributes, only, showKeys } = props;

    // onChange is re-created by most callers on every render; holding it in a ref
    // keeps the picker from being torn down and rebuilt underneath the user's
    // click, which loses focus and scroll position.
    const onChangeRef = useRef(onChange);
    onChangeRef.current = onChange;

    useEffect(() => {
        if (!mount.current) return;
        picker.current = new AttributePicker({
            container: mount.current,
            selected,
            attributes,
            only,
            showKeys,
            onChange: (keys) => onChangeRef.current?.(keys),
        });
        return () => {
            picker.current?.destroy();
            picker.current = null;
        };
        // `selected` is the INITIAL selection; use the ref's setSelection to
        // drive it from outside, or the picker would reset mid-interaction.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [attributes, only, showKeys]);

    return createElement('div', { ref: mount, className });
}

/** One attribute's assurance badge as a React component. */
export function PrivasysAttributeBadge(
    props: { attribute: CanonicalAttribute | string; showPaid?: boolean; className?: string },
): ReactNode {
    const mount = useRef<HTMLSpanElement | null>(null);
    const { attribute, showPaid, className } = props;

    useEffect(() => {
        const host = mount.current;
        if (!host) return;
        const el = attributeBadge(attribute, { showPaid });
        host.appendChild(el);
        return () => el.remove();
    }, [attribute, showPaid]);

    return createElement('span', { ref: mount, className });
}
