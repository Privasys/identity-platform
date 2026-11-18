# Maestro screenshot flows

One flow per screen group, each taking one named screenshot, against the demo build (`src/services/demo`). Run together, they also click through every main screen.

| Flow | Screenshot | What it shows |
| --- | --- | --- |
| `01-home.yaml` | `01-home` | Profile: the holder, their ID photo and data |
| `02-access.yaml` | `02-access` | Access with an approval, a form and an invitation waiting |
| `03-app-form.yaml` | `03-app-form` | A form from Northwind Bank, its sender verified |
| `04-attestation.yaml` | `04-attestation` | The attestation of that app |
| `05-approval.yaml` | `05-approval` | An approval from Civic Register, counting down |
| `06-drive-my-files.yaml` | `06-drive-my-files` | Drive, My files |
| `07-drive-shared.yaml` | `07-drive-shared` | Drive, Shared with me |
| `08-drive-file.yaml` | `08-drive-file` | A shared Markdown file in the viewer |
| `09-personal-data.yaml` | `09-personal-data` | Personal data, passport attributes verified |
| `10-id-check.yaml` | `10-id-check` | The ID check overview |
| `11-settings.yaml` | `11-settings` | Settings |
| `12-devices.yaml` | `12-devices` | The holder's two phones |
| `13-consent-history.yaml` | `13-consent-history` | Sharing history |

The sign-in approval is not captured: it starts from a QR code or a push, which the demo cannot raise.

## Build the demo app

The `demo` profile builds a simulator app on iOS and an APK on Android. EAS asks for a clean commit (`requireCommit`), and the RA-TLS libraries must be in place as CI puts them (`modules/native-ratls/ios/lib/`, `modules/native-ratls/android/src/main/jniLibs/`, see `.github/workflows/build-wallet.yaml`). The iOS simulator needs a simulator slice of `libratls_mobile.a`.

```sh
eas build --profile demo --platform ios --local
eas build --profile demo --platform android --local
```

Install the results:

```sh
tar -xzf build-*.tar.gz && xcrun simctl install booted "Privasys Wallet Demo.app"
adb install build-*.apk
```

## Run the flows

```sh
maestro test maestro/
```

Screenshots are written to the current directory, named as in the table. For a tidy status bar on iOS first run `xcrun simctl status_bar booted override --time 9:41 --batteryState charged --batteryLevel 100`, and on Android enable demo mode (`adb shell settings put global sysui_demo_allowed 1`).

Each flow starts from a fresh launch (`subflows/launch.yaml`), so any one can run alone: `maestro test maestro/05-approval.yaml`.
