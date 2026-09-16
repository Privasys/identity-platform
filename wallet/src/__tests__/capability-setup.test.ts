// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What the wallet will and will not draw when a service says it needs
 * something from the holder before it can grant a capability.
 *
 * The form is generic on purpose: a service declares a schema and the wallet
 * renders it, so connecting a new provider is not a wallet release. The price
 * of that is that the wallet must be strict about what it accepts, because a
 * control it guesses at sends the service an answer nobody gave.
 */

import {
    initialAnswers,
    missingRequired,
    parseElicitation,
    parseSetupFields,
    parseSetupRequirement,
    SetupSchemaError,
    setupPayload,
} from '@/services/capability-setup';

const mailbox = () => ({
    message: 'Connect your mailbox.',
    requestedSchema: {
        type: 'object',
        properties: {
            user: { type: 'string', title: 'Email address', format: 'email' },
            password: {
                type: 'string',
                title: 'App password',
                format: 'password',
                description: 'For Gmail: Google account, Security, App passwords.',
            },
        },
        required: ['user', 'password'],
    },
    secrets: ['password'],
    prerequisites: [{ app_host: 'mail-connector.apps.privasys.org', nonce: 'a'.repeat(64) }],
});

describe('parseSetupRequirement', () => {
    it('reads a declared mailbox connection', () => {
        const s = parseSetupRequirement(mailbox())!;
        expect(s.message).toBe('Connect your mailbox.');
        expect(s.fields.map((f) => [f.name, f.kind, f.required])).toEqual([
            ['user', 'email', true],
            ['password', 'secret', true],
        ]);
        expect(s.prerequisites).toEqual([
            { app_host: 'mail-connector.apps.privasys.org', nonce: 'a'.repeat(64) },
        ]);
    });

    it('is absent when the service declares none', () => {
        expect(parseSetupRequirement(undefined)).toBeUndefined();
        expect(parseSetupRequirement(null)).toBeUndefined();
    });

    // The wallet builds the URL around this value and attests what answers, so
    // anything that is not a bare hostname is a place it will not go.
    it.each(['https://evil.example', 'host/path', '', 'localhost', '1.2.3.4:8443'])(
        'refuses a prerequisite host of %p',
        (host) => {
            const s = mailbox();
            s.prerequisites = [{ app_host: host, nonce: 'n' }];
            expect(() => parseSetupRequirement(s)).toThrow(SetupSchemaError);
        },
    );

    it('refuses a prerequisite with no nonce', () => {
        const s = mailbox();
        s.prerequisites = [{ app_host: 'mail-connector.apps.privasys.org', nonce: '' }];
        expect(() => parseSetupRequirement(s)).toThrow(SetupSchemaError);
    });
});

describe('parseSetupFields', () => {
    const props = (properties: Record<string, unknown>, required: string[] = []) => ({
        type: 'object',
        properties,
        required,
    });

    it('maps each declared type to one control', () => {
        const fields = parseSetupFields(
            props({
                host: { type: 'string', title: 'Server' },
                who: { type: 'string', format: 'email' },
                security: { type: 'string', enum: ['SSL', 'STARTTLS'], default: 'SSL' },
                keep: { type: 'boolean', title: 'Keep a copy', default: true },
            }),
            [],
        );
        expect(fields.map((f) => f.kind)).toEqual(['text', 'email', 'choice', 'switch']);
        expect(fields[2].options).toEqual(['SSL', 'STARTTLS']);
        expect(fields[2].initial).toBe('SSL');
        expect(fields[3].initial).toBe(true);
    });

    // Either signal alone is enough. A service that lists a secret but forgets
    // `format: password`, or the reverse, must not get an unmasked field.
    it('masks a field named in secrets, and one declared as a password', () => {
        const byList = parseSetupFields(props({ token: { type: 'string' } }), ['token']);
        expect(byList[0].kind).toBe('secret');
        const byFormat = parseSetupFields(props({ token: { type: 'string', format: 'password' } }), []);
        expect(byFormat[0].kind).toBe('secret');
    });

    // A default in a masked field would show the holder a value they did not
    // type and would then be sent as if they had.
    it('never prefills a secret', () => {
        const f = parseSetupFields(props({ token: { type: 'string', default: 'hunter2' } }), ['token']);
        expect(f[0].initial).toBeUndefined();
    });

    it('falls back to the property name when no title is declared', () => {
        expect(parseSetupFields(props({ host: { type: 'string' } }), [])[0].title).toBe('host');
    });

    // There is no honest single control for these, and a guessed one sends the
    // service something nobody entered.
    it.each([
        { port: { type: 'integer' } },
        { tags: { type: 'array' } },
        { server: { type: 'object' } },
        { host: 'not a description at all' },
    ])('refuses a property the wallet cannot draw: %p', (properties) => {
        expect(() => parseSetupFields(props(properties as Record<string, unknown>), [])).toThrow(
            SetupSchemaError,
        );
    });

    it('refuses an empty schema', () => {
        expect(() => parseSetupFields(props({}), [])).toThrow(SetupSchemaError);
        expect(() => parseSetupFields({ type: 'object' }, [])).toThrow(SetupSchemaError);
        expect(() => parseSetupFields(null, [])).toThrow(SetupSchemaError);
    });

    // A required field that was never described cannot be filled in, so every
    // answer the wallet could send would be refused.
    it('refuses a required property that was not described', () => {
        expect(() =>
            parseSetupFields(props({ user: { type: 'string' } }, ['password']), []),
        ).toThrow(/did not describe/);
    });

    // Worse than the above: a secret the wallet cannot find is one it may have
    // drawn unmasked under another name.
    it('refuses a secret that was not described', () => {
        expect(() => parseSetupFields(props({ user: { type: 'string' } }), ['password'])).toThrow(
            /did not describe/,
        );
    });

    it('refuses choices that are not all values it can show', () => {
        expect(() =>
            parseSetupFields(props({ mode: { type: 'string', enum: ['SSL', 3] } }), []),
        ).toThrow(SetupSchemaError);
    });

    it('refuses more fields than a holder should read before approving', () => {
        const many: Record<string, unknown> = {};
        for (let i = 0; i < 13; i++) many['f' + i] = { type: 'string' };
        expect(() => parseSetupFields(props(many), [])).toThrow(/too much/);
    });
});

describe('parseElicitation', () => {
    it('reads the second question the service asks', () => {
        const step = parseElicitation({
            elicit: {
                message: 'We could not find your mail server.',
                requestedSchema: {
                    type: 'object',
                    properties: { imap_host: { type: 'string', title: 'IMAP server' } },
                    required: ['imap_host'],
                },
            },
        });
        expect(step.message).toBe('We could not find your mail server.');
        expect(step.fields).toHaveLength(1);
    });

    // The holder is already mid-approval. A service that could push a new
    // screen stack under them at that point would be moving them somewhere
    // they did not choose to go.
    it('never carries prerequisites', () => {
        const step = parseElicitation({
            elicit: {
                requestedSchema: { type: 'object', properties: { x: { type: 'string' } } },
                prerequisites: [{ app_host: 'a.example.org', nonce: 'n' }],
            },
        });
        expect(step.prerequisites).toEqual([]);
    });

    it('refuses a 428 that says nothing', () => {
        expect(() => parseElicitation({})).toThrow(SetupSchemaError);
        expect(() => parseElicitation({ elicit: {} })).toThrow(SetupSchemaError);
    });
});

describe('answers', () => {
    const fields = parseSetupFields(
        {
            type: 'object',
            properties: {
                user: { type: 'string', format: 'email' },
                password: { type: 'string', format: 'password' },
                note: { type: 'string' },
                keep: { type: 'boolean' },
            },
            required: ['user', 'password'],
        },
        [],
    );

    it('prefills an email field with the holder address the caller supplies', () => {
        expect(initialAnswers(fields, { email: 'me@example.org' }).user).toBe('me@example.org');
    });

    it('leaves it empty when the caller supplies none', () => {
        expect(initialAnswers(fields, {}).user).toBe('');
    });

    // The service's second question must not ask again for what was already
    // typed on the first.
    it('carries earlier answers forward', () => {
        const carried = initialAnswers(fields, {
            previous: { user: 'typed@example.org', keep: true },
        });
        expect(carried.user).toBe('typed@example.org');
        expect(carried.keep).toBe(true);
    });

    it('names the required fields still empty', () => {
        const answers = initialAnswers(fields, { email: 'me@example.org' });
        expect(missingRequired(fields, answers)).toEqual(['password']);
        answers.password = 'x';
        expect(missingRequired(fields, answers)).toEqual([]);
    });
});

describe('setupPayload', () => {
    const fields = parseSetupFields(
        {
            type: 'object',
            properties: {
                user: { type: 'string', format: 'email' },
                password: { type: 'string', format: 'password' },
                note: { type: 'string' },
                keep: { type: 'boolean' },
            },
            required: ['user', 'password'],
        },
        [],
    );

    // A trailing space in an address is a typo; a trailing space in a password
    // is a character, and trimming it would fail a login for no visible reason.
    it('trims everything except a secret', () => {
        const out = setupPayload(fields, {
            user: '  me@example.org ',
            password: ' pw ',
            note: '',
            keep: false,
        });
        expect(out).toEqual({ user: 'me@example.org', password: ' pw ', keep: false });
    });

    it('omits an optional field the holder left empty', () => {
        const out = setupPayload(fields, { user: 'a@b.org', password: 'p', note: '', keep: false });
        expect('note' in out).toBe(false);
    });
});
