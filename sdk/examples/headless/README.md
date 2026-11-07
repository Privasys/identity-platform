# A headless sign-in gate

`index.html` draws the Privasys sign-in gate itself, in the style of the
[GOV.UK Design System](https://design-system.service.gov.uk/): its own buttons,
focus state, error summary and wording. The same approach fits any design system.

## How it works

The page creates an `AuthFrame` with a `headless` option. The frame on
`privasys.id` stays invisible and keeps every credential and every flow:

1. **Options.** `onOptions(options, controls)` reports what this client offers:
   the client's own registrations (`options.own`, such as an organisation's staff
   sign-in), the platform's providers (`options.providers`), and whether the
   Privasys Wallet is offered (`options.wallet`, with `options.push` when the
   device can be notified). The page draws them.
2. **Start.** A click calls `controls.start(choice)`. The frame only starts a
   choice it offered.
3. **Progress.** `onState(state)` reports where the sign-in is. These are the
   states the page narrates: `authenticating`, `push-waiting`, `qr-scanning`
   (with `qrSvg`), `success` and `error` (with `error`). While a push waits,
   `start({ method: 'wallet', qr: true })` switches to the QR code.
4. **Result.** `connect()` resolves with the access token, as it does with the
   visible gate.

A social sign-in needs a popup, and a popup needs the click, which only the page
has. So the page opens it at the address the frame names, which is always the
identity provider's own sign-in route. The client does this for you.

Passkeys are not offered headless: a passkey ceremony needs the click inside the
frame. Use the visible gate where passkeys matter.

## Running it

1. Set `clientId` and `appName` in `CONFIG` to your client and app.
2. Serve the page from an origin your client registered: a redirect URI's
   origin, or one added with
   `PUT /api/v1/oauth-clients/{client_id}/origins`. The sign-in's result goes to
   the page that runs it, so the identity provider checks that origin.
3. Open it in a browser and sign in.

## Notes on the style

- The GOV.UK typeface, GDS Transport, is licensed to services on gov.uk only,
  so the example uses Arial. Use your own font stack.
- Every label is set as text. The page never parses markup from the frame; it
  shows the QR code as an image.
- The first button is the page's one primary action, as the design system asks.
