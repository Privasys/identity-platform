# Expo + GitHub + TestFlight Setup Guide

Step-by-step instructions to get Privasys Wallet building in CI and deploying to TestFlight.

---

## 1. Create the EAS Project

```bash
cd wallet
bunx eas init
```

This links the repo to your Expo account and creates (or updates) `app.json` / `app.config.ts` with the `extra.eas.projectId`. If you've already run this, skip it.

Verify:
```bash
bunx eas project:info
```

## 2. Configure Expo Secrets

### a) Get your Expo access token

1. Go to [expo.dev/accounts/[your-account]/settings/access-tokens](https://expo.dev/accounts/settings/access-tokens)
2. Create a **Robot** token with scope `eas:build` (or a personal token for now).
3. Copy the token.

### b) Add it as a GitHub secret

1. Go to **github.com/Privasys/identity-platform → Settings → Secrets and variables → Actions**
2. Add secret: `EXPO_TOKEN` = (the token you just copied)

## 3. Apple Developer Setup

### a) Apple Developer account

You need an active [Apple Developer Program](https://developer.apple.com/programs/) membership ($99/year). Ensure the account has the **App Manager** or **Admin** role.

### b) Register the Bundle ID

1. Go to [developer.apple.com/account/resources/identifiers](https://developer.apple.com/account/resources/identifiers/list)
2. Register a new **App ID** (type: App):
   - **Bundle ID:** `org.privasys.wallet`
   - **Description:** Privasys Wallet
3. Enable capabilities:
   - ✅ Associated Domains
   - ✅ Push Notifications

### c) Create the App in App Store Connect

1. Go to [appstoreconnect.apple.com](https://appstoreconnect.apple.com)
2. **My Apps → +** → New App
   - **Platform:** iOS
   - **Name:** Privasys Wallet
   - **Bundle ID:** `org.privasys.wallet` (select from dropdown)
   - **SKU:** `org.privasys.wallet`
   - **Primary Language:** English (U.S.)

### d) Apple credentials for EAS

EAS Build handles provisioning profiles and signing certificates automatically. On first build, run:

```bash
bunx eas credentials
```

Select **iOS**, then follow the prompts to:
- Log in with your Apple ID
- Let EAS generate/manage the **Distribution Certificate**
- Let EAS generate/manage the **Provisioning Profile**

> **Tip:** If you're on a machine that can't run Xcode (like your MacBook on 12.7.6), EAS still handles credentials — it generates them server-side via the Apple Developer API. No local Xcode needed.

## 4. Build for TestFlight

### Option A: EAS Cloud Build (recommended)

```bash
cd wallet
bunx eas build --platform ios --profile preview
```

This will:
1. Upload the project to EAS Build servers
2. Compile the native app (including Rust RA-TLS modules)
3. Sign it with your Apple credentials
4. Produce an `.ipa` file

Check build status at [expo.dev](https://expo.dev) or:
```bash
bunx eas build:list
```

### Option B: GitHub Actions

Push to `main` or use the manual workflow dispatch:

1. Go to **github.com/Privasys/identity-platform → Actions → Build Wallet**
2. Click **Run workflow**
3. Select platform: `ios`, profile: `preview`, use EAS Cloud: `true`

### Note on Rust native modules

The RA-TLS Rust library needs to be cross-compiled for iOS/Android. The GitHub Actions workflow handles this automatically by checking out the public `Privasys/ra-tls-clients` repo and running the build scripts. No extra secret is required — the default `GITHUB_TOKEN` is sufficient for public-repo checkouts.

## 5. Submit to TestFlight

After the build completes:

```bash
bunx eas submit --platform ios --profile preview
```

Or auto-submit by adding to `eas.json`:
```json
{
  "submit": {
    "preview": {
      "ios": {
        "appleId": "your-apple-id@example.com",
        "ascAppId": "YOUR_APP_STORE_CONNECT_APP_ID",
        "appleTeamId": "YOUR_TEAM_ID"
      }
    }
  }
}
```

Then future builds auto-submit:
```bash
bunx eas build --platform ios --profile preview --auto-submit
```

## 6. TestFlight Internal Testing

1. In App Store Connect → your app → **TestFlight** tab
2. The build will appear after Apple processes it (usually 5–30 minutes)
3. **Internal Testing** → Add yourself as a tester (uses your Apple ID)
4. Install **TestFlight** on your iPhone from the App Store
5. Open TestFlight → Accept the invite → Install the app

## 7. GitHub Secrets Summary

| Secret | Description |
|--------|-------------|
| `EXPO_TOKEN` | Expo access token for EAS CLI |

## 8. Verification Checklist

- [ ] `bunx eas project:info` shows the correct project
- [ ] `EXPO_TOKEN` secret is set in GitHub repo settings
- [ ] Bundle ID `org.privasys.wallet` registered in Apple Developer portal
- [ ] App created in App Store Connect
- [ ] `bunx eas credentials` ran successfully (certificates + profiles generated)
- [ ] First build completed: `bunx eas build --platform ios --profile preview`
- [ ] Build appeared in TestFlight
- [ ] App installed on iPhone via TestFlight
