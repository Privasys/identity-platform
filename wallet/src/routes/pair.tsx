// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * privasys-wallet://pair, the link a new device's QR code carries, when the
 * phone's Camera opens it rather than the wallet's own scanner. Checked the
 * same way the scanner checks it, then handed to the send screen; anything
 * else goes home.
 */

import { Redirect, useLocalSearchParams } from 'expo-router';

import { pairingLink, parsePairingLink } from '@/services/devices';

export default function PairLink() {
    const params = useLocalSearchParams<{ s?: string; k?: string }>();
    const pair = parsePairingLink(pairingLink(String(params.s ?? ''), String(params.k ?? '')));
    if (!pair) return <Redirect href="/(tabs)" />;
    return <Redirect href={{ pathname: '/device-send', params: { s: pair.slot, k: pair.key } }} />;
}
