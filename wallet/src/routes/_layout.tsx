import { DarkTheme, DefaultTheme, ThemeProvider } from '@react-navigation/native';
import Constants from 'expo-constants';
import { useFonts } from 'expo-font';
import { useKeepAwake } from 'expo-keep-awake';
import { Stack, usePathname, useRouter } from 'expo-router';
import * as SplashScreen from 'expo-splash-screen';
import { useEffect, useState, useCallback, type ReactNode } from 'react';
import 'react-native-get-random-values';
import 'react-native-reanimated';

import { AppLock } from '@/components/AppLock';
import { Notice } from '@/components/Notice';
import { UpdateGate } from '@/components/UpdateGate';
import { useColorScheme } from '@/components/useColorScheme';
import { useAppLocale } from '@/hooks/useAppLocale';
import { useDeviceUuid } from '@/hooks/useDeviceUuid';
import { useExpoPushToken } from '@/hooks/useExpoPushToken';
import { useUpdateGate } from '@/hooks/useUpdateGate';
import { initI18n } from '@/i18n';
import { useAuthStore } from '@/stores/auth';
import { useConsentStore } from '@/stores/consent';
import { useDependencyApprovalsStore } from '@/stores/dependency-approvals';
import { useProfileStore } from '@/stores/profile';
import { pullRelay, requestSync, sendIfPasskeysChanged, watchProfileForDevices } from '@/services/device-sync';
import { syncRegistry } from '@/services/devices';
import { migrateToThisDeviceOnly } from '@/utils/storage';

/** What the wallet kept before its secrets stayed on this phone (utils/storage.ts). */
const DEVICE_ONLY_KEYS = [
    'privasys.sovereign-root',
    'privasys.sovereign.recovered-seed',
    'v1-profile',
    'v1-auth-store',
    'v1-notify-seal-key',
    'v1-setup-keep-index',
    'privasys.kyc.records',
    'privasys.identities.protected',
    'privasys.identities.legacy',
];
import { deletionStartup } from '@/services/account-deletion-events';
import { installPasskeyRoot } from '@/services/website-passkeys';
import { restoreFromAutoBackupIfEmpty, watchProfileForBackup } from '@/services/profile-backup';
import { useServiceSessionsStore } from '@/stores/service-sessions';
import { useSessionsStore } from '@/stores/sessions';
import { useSettingsStore } from '@/stores/settings';
import { useTrustedAppsStore } from '@/stores/trusted-apps';
import { isTabPath } from '@/services/app-lock';
import { holderVerificationAvailable } from '@/services/biometrics';
import { checkDeviceSecurity } from '@/services/security';
import { assertDemoAllowed, demo, isDemo } from '@/services/demo/gate';
import { getDeviceLocale } from '@/services/device-locale';
import { installLogCapture } from '@/utils/logs';
import { useWindowDimensions } from 'react-native';
import { columnGutter, useLargeScreen } from '@/hooks/useLargeScreen';
import { TASK_ROUTES, WideFrame, useSidebarLayout } from '@/components/WideFrame';
import { usePalette } from '@/components/Themed';

// Capture console output into an in-memory ring buffer as early as
// possible so the Settings → Logs screen and the Connect → Report Error
// flow can surface the lines that led up to a problem.
installLogCapture();

// Bring i18next up before any screen renders. This is synchronous and starts
// on the compiled-in en-GB bundle, so it cannot fail and cannot delay the
// first frame; the user's own language is swapped in later by useAppLocale.
initI18n();

// A demo build (EXPO_PUBLIC_DEMO=1, the `demo` profile) refuses to start on a
// production stage, then fills the stores with its invented holder before the
// first render, in place of the hydrate below. In any other build both lines
// are no-ops and the demo code is not in the bundle (services/demo/gate.ts).
assertDemoAllowed(Constants.expoConfig?.extra?.STAGE);
if (isDemo()) demo().seedDemo(Date.now(), getDeviceLocale());

export {
    // Catch any errors thrown by the Layout component.
    ErrorBoundary
} from 'expo-router';

export const unstable_settings = {
    // Ensure that reloading on `/modal` keeps a back button present.
    initialRouteName: '(tabs)'
};

// Prevent the splash screen from auto-hiding before asset loading is complete.
SplashScreen.preventAutoHideAsync();

// Device attestation is NOT warmed up here. The wallet mints its own tokens
// through modules/app-attest (iOS App Attest, Android Play Integrity CLASSIC
// requests), which need no provider preparation. The block that used to sit
// here called @expo/app-integrity's prepareIntegrityTokenProviderAsync — an API
// belonging to the STANDARD Play Integrity request, which nothing in the wallet
// issues. With EXPO_PUBLIC_GOOGLE_PROJECT_ID unset it logged
// "App integrity not available on this device" on every Android launch, which
// read like a real attestation failure while having no bearing on any (2026-08-26).

export default function RootLayout() {
    useExpoPushToken();
    useDeviceUuid();
    useAppLocale();
    const [loaded, error] = useFonts({
        Inter: require('@/assets/fonts/InterVariable.ttf'),
    });

    const hasProfile = useProfileStore((s) => s.profile != null);
    // Is this build still supported? Null until an answer arrives, so a slow or
    // absent network never delays the app.
    const { notice: updateNotice, dismiss: dismissUpdate } = useUpdateGate();
    const [storesReady, setStoresReady] = useState(isDemo());
    // The logo has opened onto the wallet (components/AppLock).
    const [opened, setOpened] = useState(false);

    // Hydrate persisted stores on app launch, once the secrets written before
    // they stayed on this phone have been moved (utils/storage.ts).
    useEffect(() => {
        // The demo was seeded at load, and has no storage to read and no
        // other phones to sync with.
        if (isDemo()) return;
        migrateToThisDeviceOnly(DEVICE_ONLY_KEYS).then(() => Promise.all([
            useAuthStore.getState().hydrate(),
            useProfileStore.getState().hydrate(),
            useConsentStore.getState().hydrate(),
            useTrustedAppsStore.getState().hydrate(),
            useSettingsStore.getState().hydrate(),
            useSessionsStore.getState().hydrate(),
            useServiceSessionsStore.getState().hydrate(),
            useDependencyApprovalsStore.getState().hydrate()
        ]).then(() => {
            setStoresReady(true);
            // The profile's encrypted copy follows its changes, and a phone
            // restored from its own backup picks the copy up once recovered.
            watchProfileForBackup();
            void restoreFromAutoBackupIfEmpty();
            // The holder's other phones: their changes, and this one's to them.
            watchProfileForDevices();
            void syncRegistry()
                .then(() => pullRelay())
                .then(() => requestSync())
                .catch((e: any) => console.warn('[device-sync] start-up sync failed:', e?.message ?? e));
            // A deletion: marks still to send, the banner, and whether this
            // wallet's account (or this device) is gone.
            void deletionStartup();
            // The passkey provider's root, from the seed, and the backed-up
            // website passkeys this device made since it last told the others.
            void installPasskeyRoot(useProfileStore.getState().profile?.pairwiseSeed)
                .then(() => sendIfPasskeysChanged())
                .catch((e: any) => console.warn('[website-passkeys] start-up:', e?.message ?? e));
        }));
    }, []);

    // Run security checks in the background
    useEffect(() => {
        checkDeviceSecurity().then((status) => {
            if (status.warnings.length > 0) {
                console.warn('Security warnings:', status.warnings);
            }
        });
    }, []);

    // Expo Router uses Error Boundaries to catch errors in the navigation tree.
    useEffect(() => {
        if (error) throw error;
    }, [error]);

    const onOpened = useCallback(() => {
        setOpened(true);
    }, []);

    if (!loaded || !storesReady) {
        return null;
    }

    return (
        <>
            <RootLayoutNav hasProfile={hasProfile} ready={opened} />
            <Notice />
            {/* Above the navigator, below the logo. A required notice has no
                dismiss handler, and that absence IS what makes it a wall: there
                is no flag the screen could be talked out of. */}
            {updateNotice && (
                <UpdateGate
                    notice={updateNotice}
                    onDismiss={updateNotice.level === 'required' ? undefined : dismissUpdate}
                />
            )}
            {/* The logo, above everything: it opens onto the wallet at start and
                closes over it as the lock (components/AppLock). */}
            <AppLock onShown={() => SplashScreen.hideAsync()} onOpened={onOpened} />
        </>
    );
}

function KeepAwake() {
    useKeepAwake();
    return null;
}

function RootLayoutNav({ hasProfile, ready }: { hasProfile: boolean; ready: boolean }) {
    const colorScheme = useColorScheme();
    const router = useRouter();
    const pathname = usePathname();
    const appLockAsked = useSettingsStore((s) => s.appLockAsked);
    const large = useLargeScreen();
    // The sidebar layout: a wide window, once the wallet is set up.
    const wide = useSidebarLayout();
    const { width } = useWindowDimensions();
    const palette = usePalette();
    // The navigator's background is what shows beside the centred column on a
    // large screen: the wallet's own, not the library's grey.
    const baseTheme = colorScheme === 'dark' ? DarkTheme : DefaultTheme;
    const navTheme = { ...baseTheme, colors: { ...baseTheme.colors, background: palette.screenBg } };

    // No identity yet (fresh install, or after Settings → Clear All Data) →
    // send the user to the Profile tab, whose empty state runs the first-run
    // setup (biometric + device key + identity). Replaces the old redirect to
    // the standalone gradient onboarding screen, which has been removed.
    useEffect(() => {
        if (!hasProfile) {
            router.replace('/(tabs)');
        }
    }, [hasProfile]);

    // The app lock is asked about once, on a tab and never over a task: after
    // setup, or on the first start of a version that has it. A phone with no
    // Face ID and no passcode has nothing to lock with, so it is not asked.
    useEffect(() => {
        if (isDemo() || !ready || !hasProfile || appLockAsked || !isTabPath(pathname)) return;
        let cancelled = false;
        void holderVerificationAvailable().then((can) => {
            if (!cancelled && can) router.push('/app-lock');
        });
        return () => {
            cancelled = true;
        };
    }, [ready, hasProfile, appLockAsked, pathname]);

    return (
        <>
            {__DEV__ && <KeepAwake />}
            <ThemeProvider value={navTheme}>
                {/* On a phone, portrait and full width. On a large screen (a
                    tablet, an unfolded phone) any orientation, and the content
                    in a centred column of readable width. */}
                <Stack
                    // On a wide window every screen is drawn in the wallet's
                    // frame: the sidebar, a list beside its item, a task in a
                    // centred sheet (components/WideFrame). On a phone the
                    // frame draws nothing.
                    screenLayout={({ route, children }: { route: { name: string }; children: ReactNode }) => (
                        <WideFrame routeName={route.name}>{children}</WideFrame>
                    )}
                    screenOptions={({ route }: { route: { name: string } }) => {
                        const task = wide && TASK_ROUTES.has(route.name);
                        return {
                            headerShown: false,
                            orientation: large ? 'all' : 'portrait',
                            // Between a phone and a wide window (an iPad mini
                            // upright, say) the content is a centred column. It
                            // is made with side padding, not a narrower view, so
                            // the screen's view stays full width: Android clips
                            // what is drawn outside it, and each header paints
                            // its colour into the padding (components/HeaderBleed).
                            contentStyle:
                                large && !wide
                                    ? { paddingHorizontal: columnGutter(width), backgroundColor: palette.screenBg }
                                    : undefined,
                            // Beside the sidebar a screen replaces the last in
                            // place, and a task fades in over the window.
                            ...(wide ? { animation: task ? ('fade' as const) : ('none' as const) } : {}),
                            ...(task
                                ? { presentation: 'transparentModal' as const, contentStyle: { backgroundColor: 'transparent' } }
                                : {}),
                        };
                    }}
                >
                    {/* The tabs make their own column (routes/(tabs)/_layout):
                        the tab navigator clips its scenes, so a column made
                        here would also clip each tab's header band. */}
                    <Stack.Screen
                        name="(tabs)"
                        options={{ contentStyle: large && !wide ? { backgroundColor: palette.screenBg } : undefined }}
                    />
                </Stack>
            </ThemeProvider>
        </>
    );
}
