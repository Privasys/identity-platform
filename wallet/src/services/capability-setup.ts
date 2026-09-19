// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Setup requirements: what a resource service needs from the holder before a
 * capability can exist, rendered on the approval screen as a form.
 *
 * A secret is typed in the wallet and nowhere else. The wallet is the one party
 * in the chain whose verification of the far end the holder can see, and the
 * value then travels a single attested hop to the service that seals it: the
 * app that asked, the runtime that pushed and the conversation the holder was
 * having never hold it.
 *
 * Nothing here is product code. The service declares a JSON schema and the
 * wallet draws what it can draw honestly, so a new credential for a new
 * provider never means shipping a new wallet.
 *
 * The line between this and the closed vocabularies in `capabilities.ts` is
 * deliberate. WHAT is being granted is still wallet-owned prose selected by
 * kind, because an app that can author that sentence can describe itself
 * however it likes. These are field labels under it, read after the wallet's
 * own sentence about the grant.
 */

/** A schema the wallet will not draw. Rewrapped by the caller. */
export class SetupSchemaError extends Error {}

/** The field kinds the wallet can render. Anything else is refused. */
export type SetupFieldKind = 'text' | 'email' | 'secret' | 'choice' | 'switch' | 'oauth';

/**
 * A field answered by signing in at a provider rather than by typing.
 *
 * The service runs the provider's OAuth flow itself (its own client, its own
 * secret, its own redirect) and only asks the wallet to open its start URL in
 * an authentication session and bring back the one-time grant code the
 * service hands out at the end (services/setup-oauth.ts). The wallet learns
 * nothing about the provider beyond a name to put on the button, and no token
 * ever passes through it in the clear: what the service wants kept comes back
 * on the mint as `keep`, opaque.
 */
export interface SetupOAuth {
    /** The provider's name for the button ("Google"). The service's words. */
    provider: string;
    /**
     * Where the wallet sends the browser. Checked at press time to be on the
     * resource service's own attested host, over https: a URL out of a schema
     * is exactly what the wallet must not dial blindly.
     */
    startUrl: string;
}

export interface SetupField {
    /** Property name; the key the answer is sent back under. */
    name: string;
    kind: SetupFieldKind;
    /** Label. The service's own words, shown as a label and never as the ask. */
    title: string;
    /** Hint under the field. */
    description?: string;
    required: boolean;
    /**
     * Prefilled value. Never set on a secret: the wallet shows no value in a
     * masked field that the holder did not type into it.
     */
    initial?: string | boolean;
    /** The closed set of values, for `choice`. */
    options?: string[];
    /** How to obtain the answer, for `oauth`. */
    oauth?: SetupOAuth;
}

export interface SetupPrerequisite {
    /**
     * Hostname of the app that owns the prerequisite ask, attested like any
     * other. A bare hostname, because the wallet builds the URL around it.
     */
    app_host: string;
    nonce: string;
}

export interface SetupRequirement {
    /** One sentence from the service saying why it is asking. */
    message: string;
    fields: SetupField[];
    /**
     * Capability asks the service needs granted before this one can be minted.
     * Always empty on a second step, which may not introduce new ones.
     */
    prerequisites: SetupPrerequisite[];
}

/** Answers held in component state. Never persisted, never logged. */
export type SetupAnswers = Record<string, string | boolean>;

// Bounds. A service declares these, and a screen the holder must read before
// approving is not somewhere an unbounded string or an unbounded list belongs.
const MAX_FIELDS = 12;
const MAX_PREREQUISITES = 4;
const MAX_OPTIONS = 20;
const MAX_TEXT = 200;
const MAX_MESSAGE = 240;

function text(v: unknown, limit: number): string {
    return typeof v === 'string' ? v.trim().slice(0, limit) : '';
}

/** A bare hostname. No scheme, no path, no port: the wallet builds the URL. */
function isHostname(v: string): boolean {
    return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(v);
}

function parseField(
    name: string,
    raw: unknown,
    secrets: Set<string>,
    required: Set<string>,
): SetupField {
    const p = raw as Record<string, unknown> | null;
    if (!p || typeof p !== 'object') {
        throw new SetupSchemaError(`the service described "${name}" in a way the wallet cannot draw`);
    }

    const title = text(p['title'], MAX_TEXT) || name;
    const description = text(p['description'], MAX_TEXT) || undefined;
    const isRequired = required.has(name);
    const type = typeof p['type'] === 'string' ? p['type'] : 'string';
    const format = typeof p['format'] === 'string' ? p['format'] : '';

    // An enum is a picker whatever its declared type: the holder is choosing
    // from a list either way.
    if (Array.isArray(p['enum'])) {
        const raw_options = p['enum'];
        const options = raw_options.filter((o): o is string => typeof o === 'string');
        if (options.length === 0 || options.length !== raw_options.length) {
            throw new SetupSchemaError(`the choices for "${name}" are not ones the wallet can show`);
        }
        if (options.length > MAX_OPTIONS) {
            throw new SetupSchemaError(`"${name}" offers too many choices to show`);
        }
        const preset = typeof p['default'] === 'string' && options.includes(p['default'])
            ? p['default']
            : undefined;
        return {
            name,
            kind: 'choice',
            title,
            description,
            required: isRequired,
            options,
            initial: preset,
        };
    }

    if (type === 'boolean') {
        return {
            name,
            kind: 'switch',
            title,
            description,
            required: isRequired,
            initial: typeof p['default'] === 'boolean' ? p['default'] : false,
        };
    }

    if (type === 'string' && p['x-privasys-oauth'] !== undefined) {
        const o = p['x-privasys-oauth'] as Record<string, unknown> | null;
        const provider = o && typeof o === 'object' ? text(o['provider'], 60) : '';
        const startUrl = o && typeof o === 'object' ? text(o['start_url'], 2000) : '';
        if (!provider || !startUrl || !/^https:\/\/[^/?#]+\/[^\s]*$/i.test(startUrl)) {
            throw new SetupSchemaError(`the service described the sign-in for "${name}" in a way the wallet cannot follow`);
        }
        // A grant code is a secret in every way that matters: single use,
        // never shown, never prefilled, never kept (the service's `keep` is
        // what survives).
        return { name, kind: 'oauth', title, description, required: isRequired, oauth: { provider, startUrl } };
    }

    if (type === 'string') {
        // `format: password` and membership of `secrets` mean the same thing,
        // and either alone is enough: a service that declares one and forgets
        // the other must not end up with an unmasked field.
        const secret = secrets.has(name) || format === 'password';
        const kind: SetupFieldKind = secret ? 'secret' : format === 'email' ? 'email' : 'text';
        const preset = !secret && typeof p['default'] === 'string'
            ? p['default'].slice(0, MAX_TEXT)
            : undefined;
        return { name, kind, title, description, required: isRequired, initial: preset };
    }

    // Numbers, arrays, nested objects. There is no honest single control for
    // them, and guessing one sends the service something it did not ask for.
    throw new SetupSchemaError(`the service asked for something the wallet cannot draw: ${name}`);
}

/**
 * Turn a declared schema into the fields the wallet will draw, or refuse.
 *
 * Refuses rather than repairs, like every other parse on this path: a form the
 * wallet only half understands produces a grant the holder did not intend.
 */
export function parseSetupFields(raw: unknown, secretNames: unknown): SetupField[] {
    const schema = raw as Record<string, unknown> | null;
    if (!schema || typeof schema !== 'object') {
        throw new SetupSchemaError(
            'the service described what it needs in a way the wallet cannot read',
        );
    }
    const props = schema['properties'] as Record<string, unknown> | undefined;
    if (!props || typeof props !== 'object') {
        throw new SetupSchemaError('the service asked for nothing the wallet can show');
    }

    const names = Object.keys(props);
    if (names.length === 0) {
        throw new SetupSchemaError('the service asked for nothing the wallet can show');
    }
    if (names.length > MAX_FIELDS) {
        throw new SetupSchemaError('the service asked for too much at once');
    }

    const secrets = new Set(
        Array.isArray(secretNames)
            ? secretNames.filter((s): s is string => typeof s === 'string')
            : [],
    );
    const declared = Array.isArray(schema['required'])
        ? schema['required'].filter((s): s is string => typeof s === 'string')
        : [];

    for (const name of declared) {
        // A required field the schema never described cannot be filled in, so
        // every answer the wallet could send would be refused.
        if (!names.includes(name)) {
            throw new SetupSchemaError(`the service requires "${name}" but did not describe it`);
        }
    }
    for (const name of secrets) {
        // Same reasoning, and worse: a secret the wallet cannot find is one it
        // might have drawn unmasked under another name.
        if (!names.includes(name)) {
            throw new SetupSchemaError(
                `the service named "${name}" as secret but did not describe it`,
            );
        }
    }

    const required = new Set(declared);
    return names.map((name) => parseField(name, props[name], secrets, required));
}

/** The `setup` object on a fetched request, or undefined when there is none. */
export function parseSetupRequirement(raw: unknown): SetupRequirement | undefined {
    if (raw === undefined || raw === null) return undefined;
    const o = raw as Record<string, unknown>;
    if (typeof o !== 'object') {
        throw new SetupSchemaError('the request describes its setup in a way the wallet cannot read');
    }

    const listed = Array.isArray(o['prerequisites']) ? o['prerequisites'] : [];
    if (listed.length > MAX_PREREQUISITES) {
        throw new SetupSchemaError('the service asks for too many approvals before this one');
    }
    const prerequisites = listed.map((entry) => {
        const e = entry as Record<string, unknown> | null;
        const host = e && typeof e === 'object' ? text(e['app_host'], 253) : '';
        const nonce = e && typeof e === 'object' ? text(e['nonce'], 128) : '';
        if (!host || !nonce || !isHostname(host)) {
            throw new SetupSchemaError('the service named an approval the wallet cannot reach');
        }
        return { app_host: host, nonce };
    });

    return {
        message: text(o['message'], MAX_MESSAGE),
        fields: parseSetupFields(o['requestedSchema'], o['secrets']),
        prerequisites,
    };
}

/**
 * The 428 body: the service has one more question. It may not introduce
 * prerequisites, because the holder is already mid-approval and a new screen
 * stack under them is not something they asked for.
 */
export function parseElicitation(raw: unknown): SetupRequirement {
    const body = raw as Record<string, unknown> | null;
    const e = body && typeof body === 'object' ? (body['elicit'] as Record<string, unknown>) : null;
    if (!e || typeof e !== 'object') {
        throw new SetupSchemaError('the service asked for more but did not say what');
    }
    return {
        message: text(e['message'], MAX_MESSAGE),
        fields: parseSetupFields(e['requestedSchema'], e['secrets']),
        prerequisites: [],
    };
}

/**
 * Starting values for a step. Carries forward anything the holder already typed
 * under the same name, so a second question never asks for the first answer
 * again, and prefills an email field with the holder's own address when the
 * caller passes one.
 */
export function initialAnswers(
    fields: SetupField[],
    opts: { previous?: SetupAnswers; email?: string } = {},
): SetupAnswers {
    const out: SetupAnswers = {};
    for (const f of fields) {
        const wanted = f.kind === 'switch' ? 'boolean' : 'string';
        const carried = opts.previous?.[f.name];
        if (f.kind === 'oauth') {
            // A grant code is single use: a second step signs in again.
            out[f.name] = '';
        } else if (carried !== undefined && typeof carried === wanted) {
            out[f.name] = carried;
        } else if (f.initial !== undefined) {
            out[f.name] = f.initial;
        } else if (f.kind === 'email' && opts.email) {
            out[f.name] = opts.email;
        } else {
            out[f.name] = f.kind === 'switch' ? false : '';
        }
    }
    return out;
}

/** Required fields still empty. A switch is answered by existing. */
export function missingRequired(fields: SetupField[], answers: SetupAnswers): string[] {
    return fields
        .filter((f) => f.required && f.kind !== 'switch')
        .filter((f) => String(answers[f.name] ?? '').length === 0)
        .map((f) => f.name);
}

/**
 * The `setup` object sent with the mint request.
 *
 * Secrets are sent exactly as typed. Everything else is trimmed, because a
 * trailing space in an address or a hostname is a typo and a trailing space in
 * a password is a character.
 */
export function setupPayload(fields: SetupField[], answers: SetupAnswers): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const f of fields) {
        const v = answers[f.name];
        if (f.kind === 'switch') {
            out[f.name] = v === true;
            continue;
        }
        const s = typeof v === 'string' ? (f.kind === 'secret' ? v : v.trim()) : '';
        // An empty optional field is an answer the service never asked for.
        if (!s && !f.required) continue;
        out[f.name] = s;
    }
    return out;
}
