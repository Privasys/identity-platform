// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The holder's standing grants, arranged the two ways a person looks for them.
 *
 * By provider: "what have I connected at Google?" One entry per provider;
 * inside it the holder's accounts there (a level of its own only when there is
 * more than one); under each account the products connected (Gmail, Calendar);
 * under each product the apps using it.
 *
 * By app: "what can this assistant reach?" One entry per app, and under it
 * everything it may use, whoever holds it.
 *
 * Both are views over the same records. Nothing here names a provider or a
 * product: those words are what each service declared at the mint. A grant
 * from a service that declares nothing falls back to that service's own name,
 * with the resource it described as the account, so older grants still land
 * somewhere sensible.
 */

import type { CapabilityRecord } from '@/stores/capabilities';
import type { LinkedProvider } from '@/stores/profile';
import { accessRows, groupOf, isLive, type AccessRow } from '@/utils/access-rows';

export interface ProductNode {
    /** Stable within its account: the service and kind. */
    key: string;
    /** "Gmail", or the service's name when it declared no product. */
    product: string;
    category?: string;
    /** The apps using it, as rows, newest first. */
    rows: AccessRow[];
}

export interface AccountNode {
    /** The address, or the resource label for a service that names none. */
    account: string;
    products: ProductNode[];
}

export interface ProviderNode {
    /** Stable: the declared provider id, or the service's app id. */
    key: string;
    /** The declared provider id ("google"), when there is one. */
    providerId?: string;
    name: string;
    accounts: AccountNode[];
    /**
     * The sign-in the holder used to import details from this provider into
     * the wallet, when there is one. Not a grant: nothing holds a credential
     * for it but this phone.
     */
    signIn?: LinkedProvider;
}

export interface AppNode {
    appId: string;
    appName?: string;
    rows: AccessRow[];
}

/** Whether a record is a connection to an account somewhere else. */
export function isConnection(r: CapabilityRecord): boolean {
    return !!r.providerId || groupOf(r) === 'account';
}

function providerKeyOf(r: CapabilityRecord): string {
    return r.providerId ? `p:${r.providerId}` : `s:${r.resourceAppId}`;
}

function sortByName<T>(items: T[], name: (t: T) => string): T[] {
    return items.slice().sort((a, b) => name(a).localeCompare(name(b)));
}

/**
 * Connected accounts, by provider. Only connections: a grant over the holder's
 * own Privasys data is not an account somewhere else, and appears by app.
 */
export function providerTree(records: CapabilityRecord[]): ProviderNode[] {
    const providers = new Map<string, ProviderNode>();
    for (const row of accessRows(records)) {
        const r = row.record;
        if (!isConnection(r)) continue;
        const pkey = providerKeyOf(r);
        let provider = providers.get(pkey);
        if (!provider) {
            provider = {
                key: pkey,
                providerId: r.providerId,
                name: r.providerName || r.providerId || r.resourceAppName || r.resourceAppId,
                accounts: [],
            };
            providers.set(pkey, provider);
        }
        const accountName = r.account || r.resourceLabel;
        let account = provider.accounts.find((a) => a.account === accountName);
        if (!account) {
            account = { account: accountName, products: [] };
            provider.accounts.push(account);
        }
        const productKey = `${r.resourceAppId}|${r.kind}`;
        let product = account.products.find((p) => p.key === productKey);
        if (!product) {
            product = {
                key: productKey,
                product: r.product || r.resourceAppName || r.kind,
                category: r.category,
                rows: [],
            };
            account.products.push(product);
        }
        product.rows.push(row);
    }
    const out = sortByName([...providers.values()], (p) => p.name);
    for (const p of out) {
        p.accounts = sortByName(p.accounts, (a) => a.account);
        for (const a of p.accounts) a.products = sortByName(a.products, (x) => x.product);
    }
    return out;
}

/**
 * The providers, with each import sign-in joined to its provider's entry, and
 * an entry of its own for a provider the holder signed in with and connected
 * nothing at.
 */
export function withSignIns(tree: ProviderNode[], linked: LinkedProvider[]): ProviderNode[] {
    const out = tree.map((p) => ({ ...p }));
    for (const l of linked) {
        const id = l.provider.toLowerCase();
        const existing = out.find((p) => p.providerId === id);
        if (existing) {
            existing.signIn = l;
            continue;
        }
        out.push({ key: `p:${id}`, providerId: id, name: l.displayName || l.provider, accounts: [], signIn: l });
    }
    return sortByName(out, (p) => p.name);
}

/** Everything each app may use, by app. */
export function appTree(records: CapabilityRecord[]): AppNode[] {
    const apps = new Map<string, AppNode>();
    for (const row of accessRows(records)) {
        const r = row.record;
        let app = apps.get(r.appId);
        if (!app) {
            app = { appId: r.appId, appName: r.appName, rows: [] };
            apps.set(r.appId, app);
        }
        if (!app.appName && r.appName) app.appName = r.appName;
        app.rows.push(row);
    }
    return sortByName([...apps.values()], (a) => a.appName || a.appId);
}

/** What one row is, in a person's words: "Gmail", or the resource described. */
export function whatOf(r: CapabilityRecord): string {
    return r.product || r.resourceLabel;
}

/** Every record under a provider, an account in it, or a product. */
export function recordsIn(node: ProviderNode | AccountNode | ProductNode): CapabilityRecord[] {
    if ('rows' in node) return node.rows.map((r) => r.record);
    if ('products' in node) return node.products.flatMap((p) => p.rows.map((r) => r.record));
    return node.accounts.flatMap((a) => recordsIn(a));
}

/** How many of these still stand. */
export function liveIn(records: CapabilityRecord[], nowSeconds: number): number {
    return records.filter((r) => isLive(r, nowSeconds)).length;
}

/** The products under a provider or an account, named once each, in order. */
export function productNames(node: ProviderNode | AccountNode): string[] {
    const accounts = 'accounts' in node ? node.accounts : [node];
    const names: string[] = [];
    for (const a of accounts) for (const p of a.products) if (!names.includes(p.product)) names.push(p.product);
    return names;
}
