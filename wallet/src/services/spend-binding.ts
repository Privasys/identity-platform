/**
 * The holder's binding of a spend consent to a ledger handle.
 *
 * The wallet mints the handle the platform will debit by, random and
 * meaningful to nobody, and signs handle‖0‖app‖0‖cap with the passkey of
 * the identity that consents: its own credential at privasys.id, the key
 * that signed the sign-in. The IdP looks that key up itself from the wallet
 * session, checks the signature, and forwards it with its own co-signature
 * to the platform as the evidence that the holder, not the IdP alone, bound
 * their credits to this handle. Each identity has its own passkey, so the
 * key links nothing, and the wallet sends no key of its own.
 */
import * as Crypto from 'expo-crypto';
import { derToRawEcdsa } from './encauth';
import { signWithDeviceKey } from './did';

export interface SpendBinding {
    ledgerHandle: string;
    walletSig: string;
}

function b64u(bytes: Uint8Array): string {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64uToBytes(s: string): Uint8Array {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

/** The bytes the holder signs: handle ‖ 0x00 ‖ app id ‖ 0x00 ‖ cap (decimal). */
export function spendBindingMessage(ledgerHandle: string, appId: string, cap: number): Uint8Array {
    return new TextEncoder().encode(`${ledgerHandle}\u0000${appId}\u0000${Math.max(0, Math.floor(cap))}`);
}

/**
 * Mint a handle for `appId` under `cap` and sign the binding with
 * `passkeyAlias`, the identity's privasys.id passkey that opened the wallet
 * session the consent is recorded with.
 */
export async function bindSpendConsent(passkeyAlias: string, appId: string, cap: number): Promise<SpendBinding> {
    const ledgerHandle = b64u(Crypto.getRandomBytes(16));
    const msg = spendBindingMessage(ledgerHandle, appId, cap);
    const der = await signWithDeviceKey(b64u(msg), passkeyAlias);
    const raw = derToRawEcdsa(b64uToBytes(der));
    if (raw.length !== 64) throw new Error('wallet_sig must be 64 bytes');
    return { ledgerHandle, walletSig: b64u(raw) };
}
