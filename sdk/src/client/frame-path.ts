// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * Where the identity provider serves this SDK's frame: one path per major
 * version (/auth/v1/, /auth/v2/, ...). The page and its frame speak one
 * protocol, so a page pins the major it was built for, and fixes reach it in
 * place.
 */
export const FRAME_PATH = '/auth/v1/';
