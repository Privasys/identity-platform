/**
 * Pure decisions behind the sign-in gate's idle menu, kept out of the DOM
 * code so they can be tested.
 */

export type GateMethod = 'wallet' | 'passkey' | 'social';

/**
 * The name the gate shows for the app. A slug (`diom-dar`, `my_app`,
 * `globaml`) reads better as words with capitals; a name the adopter already
 * wrote for people ("Isle of Man Data Asset Register") is shown as written,
 * since capitalising every word would turn its "of" into "Of".
 */
export function displayAppName(raw: string): string {
    const name = (raw ?? '').trim();
    if (!name) return name;
    const slug = /[-_]/.test(name) || name === name.toLowerCase();
    if (!slug) return name;
    return name.replace(/[-_]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * The order of the alternatives under the wallet: the adopter's `methods`
 * list is an order as well as a filter, so `['social', 'passkey']` puts the
 * federated identity first. Without a list, the passkey comes first, as the
 * gate always did.
 */
export function alternativeOrder(methods: readonly GateMethod[] | undefined): readonly ('passkey' | 'social')[] {
    const defaults: readonly ('passkey' | 'social')[] = ['passkey', 'social'];
    if (!methods) return defaults;
    const listed = methods.filter((m): m is 'passkey' | 'social' => m === 'passkey' || m === 'social');
    return listed.filter((m, i) => listed.indexOf(m) === i);
}
