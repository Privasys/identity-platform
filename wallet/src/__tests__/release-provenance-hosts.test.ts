// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { apiBasesForHost } from '../services/release-provenance';

const DEV = 'https://api.developer.test.privasys.org';
const PROD = 'https://api.developer.privasys.org';

describe('apiBasesForHost', () => {
    it('asks the dev control plane first for a test app host', () => {
        expect(apiBasesForHost('drive-demo.apps.test.privasys.org')[0]).toBe(DEV);
    });

    it('asks the prod control plane first for a prod app host', () => {
        expect(apiBasesForHost('privasys-drive.apps.privasys.org')[0]).toBe(PROD);
    });

    it('never names the retired dev API host', () => {
        expect(apiBasesForHost().join(' ')).not.toContain('api-test.');
    });
});
