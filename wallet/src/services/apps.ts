/**
 * The holder's standing relationship with an app, at the IdP.
 *
 * Removing an app ends everything the IdP keeps for the pair: the
 * relationship row that lets the app reach this holder, the sessions of the
 * client that stands for the app (its browsers end as signed-out), the spend
 * consent (its ledger handle is reported dead to the platform) and the asks
 * the app had waiting. The app's subject for the holder then names nobody.
 */
const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** Remove `appId` (the attested app id, undashed hex) for the signed-in holder. */
export async function removeAppAtIdp(walletSessionToken: string, appId: string): Promise<void> {
    const res = await fetch(`${IDP_BASE}/wallet/apps/${encodeURIComponent(appId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer wallet:${walletSessionToken}` },
    });
    if (!res.ok && res.status !== 404) {
        throw new Error(`the app could not be removed at the identity provider (${res.status})`);
    }
}
