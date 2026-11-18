# Demo mode

A build of the wallet that opens straight into a populated wallet with invented data, for store screenshots. It needs no network, no NFC, no camera and no RA-TLS, so it runs on the iOS simulator and the Android emulator.

## Turning it on

Only the `demo` EAS profile turns it on: `EXPO_PUBLIC_DEMO=1`, `STAGE=demo`. That stage has its own name (Privasys Wallet Demo), scheme (`privasys-wallet-demo`) and bundle id (`org.privasys.wallet.demo`), shares no keychain group, has no passkey or notification extension, and claims no privasys.id links, so it can neither replace nor read a real install.

Two guards stop a demo reaching a holder:

- `app.config.ts` refuses `EXPO_PUBLIC_DEMO=1` on the production stage;
- `assertDemoAllowed` (`gate.ts`), called first thing in `src/routes/_layout.tsx`, throws at launch if a build carries the flag on the production stage.

## What is here

| File | What it holds |
| --- | --- |
| `gate.ts` | `isDemo()`, `demo()` (the only way in to the rest) and the production guard. |
| `fixtures.ts` | The holder, phones, apps and their attestations, sign-ins, sharing history, a grant, the waiting form, approval and message, and the Drive tree. |
| `seed.ts` | `seedDemo()`: fills the stores with `setState`, writing nothing to storage. |
| `api.ts` | The stand-ins the switch points call, one per real service function. |
| `files.ts`, `assets/` | The bytes of the sample PDF and photo; `notes.ts` holds the Markdown files. |
| `portrait.ts` | The holder's illustrated ID photo, as a data URI. |

Every measurement is a hash of a label (`fakeHex`), so it looks real and matches nothing real. The form and approval are built from the exact strings an app would send and parsed by the wallet's own parsers, so their digests are consistent.

## Switch points

Each is one line at the top of the real function: `if (isDemo()) return demo().x(...)`.

| Where | Function | Demo answer |
| --- | --- | --- |
| `src/routes/_layout.tsx` | start-up hydrate and device sync | skipped; `seedDemo()` runs before the first render |
| `services/attestation.ts` | `inspectAttestation`, `attestEnclave` | a verified TDX attestation for the app at that host |
| `services/app-form-answer.ts` | `confirmFormSource` | the form's sender, confirmed |
| `services/approval-answer.ts` | `confirmApprovalSource` | the approval's sender, confirmed |
| `services/drive.ts` | `attestDrive` | Drive's attestation, already trusted |
| `services/drive.ts` | `ensureDrive` | `null`: no session; every Drive call a screen makes has its own switch point |
| `services/drive.ts` | `listShareRequests` | no requests |
| `services/drive-files.ts` | `myTenant`, `listFolder`, `listSharedWithMe`, `readFile` | the demo Drive and its sample files |
| `services/devices.ts` | `listDevices`, `syncRegistry` | two phones |
| `services/platform-token.ts` | `getPlatformToken`, `getCachedPlatformToken` | no token: every background call to the IdP or the control plane stays quiet, and nothing ever starts a sign-in |
| `stores/app-messages.ts` | `refresh` | nothing to fetch; the seeded items stay |

Answering a form or an approval is not switched: it would need a signature, and the demo signs nothing. It fails the way it does without a network.

## Keeping it out of other builds

`EXPO_PUBLIC_DEMO` is inlined at build time. In a release bundle Metro folds the comparison in `gate.ts` to false and drops `require('./api')` before collecting dependencies, so none of this folder (fixtures, samples, portrait) is bundled; checked with `expo export` on 2026-11-17. `metro.config.js` keys Metro's transform cache on the flag, because without that a normal export run after a demo one reused the demo's transforms.

Keep the comparison written out literally inside `gate.ts`: a flag computed once and imported elsewhere is not folded.

## What the demo cannot show

- The sign-in approval: it starts from a QR code or a push. The same attestation screen is reachable from a form's verified host.
- The ID check past its first screen: every later step needs the camera or an NFC chip.
