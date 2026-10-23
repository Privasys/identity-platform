/**
 * The relying party a paid disclosure is presented under.
 *
 * The identity verifier refuses a disclosure whose voucher was issued to a
 * different relying party than the one the request names. privasys.id
 * stamps each voucher with the client that pays (its registered rp id, else
 * its client id, e.g. `privasys-platform`), while a sign-in brokered by
 * privasys.id carries `privasys.id` as its rpId. So the proof is presented
 * under the voucher's own rp_id: the one the verifier will check, and the
 * service the disclosure is for. The voucher's signature is the verifier's
 * to check; reading its claim here only keeps the two sides in step.
 * Without a voucher (an unpaid disclosure) the sign-in's rpId stands.
 */
export function voucherRpId(token: string | undefined): string | undefined {
    if (!token) return undefined;
    const part = token.split('.')[1];
    if (!part) return undefined;
    try {
        const b64 = part.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (part.length % 4)) % 4);
        const claims = JSON.parse(atob(b64)) as { rp_id?: unknown };
        return typeof claims.rp_id === 'string' && claims.rp_id.trim() ? claims.rp_id.trim() : undefined;
    } catch {
        return undefined;
    }
}

export function disclosureRpId(rpId: string, voucher: string | undefined): string {
    return voucherRpId(voucher) ?? rpId;
}
