// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The trusted-app record after a sign-in with a passkey the wallet already
 * held: an approved, verified change is recorded; an unverified one is not.
 */

import { trustAfterSignIn } from '../services/trust-after-sign-in';

const record = {
    rpId: 'app.example',
    origin: 'app.example',
    appName: 'App',
    teeType: 'tdx',
    mrtd: 'mrtd-old',
    rtmr1: 'r1-old',
    rtmr2: 'r2-old',
    codeHash: 'code-old',
    configRoot: 'config-old',
    lastVerified: 100,
    credentialId: 'cred',
};

const attested = {
    mrtd: 'mrtd-old',
    rtmr1: 'r1-new',
    rtmr2: 'r2-new',
    workload_code_hash: 'code-new',
    workload_config_merkle_root: 'config-old',
    tee_type: 'tdx',
};

describe('after a sign-in with an existing passkey', () => {
    it('a change the attestation service verified and the holder approved is recorded', () => {
        const next = trustAfterSignIn(record, { attested, verified: true, sameHost: true, appName: 'App 2', nowSeconds: 200 });
        expect(next).toMatchObject({
            mrtd: 'mrtd-old',
            rtmr1: 'r1-new',
            rtmr2: 'r2-new',
            codeHash: 'code-new',
            configRoot: 'config-old',
            teeType: 'tdx',
            appName: 'App 2',
            lastVerified: 200,
        });
        // What the record held besides is kept.
        expect(next.credentialId).toBe('cred');
        expect(next.rpId).toBe('app.example');
    });

    it('continued although verification was unreachable or invalid: the stored measurements do not move', () => {
        const next = trustAfterSignIn(record, { attested, verified: false, sameHost: true, nowSeconds: 200 });
        expect(next).toMatchObject({
            mrtd: 'mrtd-old',
            rtmr1: 'r1-old',
            rtmr2: 'r2-old',
            codeHash: 'code-old',
            configRoot: 'config-old',
            appName: 'App',
            lastVerified: 200,
        });
    });

    it("what was attested for another host is never written into this host's record", () => {
        const next = trustAfterSignIn(record, { attested, verified: true, sameHost: false, nowSeconds: 200 });
        expect(next.rtmr1).toBe('r1-old');
        expect(next.codeHash).toBe('code-old');
    });

    it('with nothing attested only the time and the name change', () => {
        const next = trustAfterSignIn(record, { attested: null, verified: true, sameHost: true, nowSeconds: 200 });
        expect(next).toEqual({ ...record, lastVerified: 200 });
    });
});
