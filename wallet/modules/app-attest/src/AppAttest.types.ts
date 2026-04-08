// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

export interface AppAttestState {
    supported: boolean;
    keyId: string | null;
    attested: boolean;
}
