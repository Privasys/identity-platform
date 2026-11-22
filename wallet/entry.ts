// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// The background tasks first: a push that wakes the wallet without drawing it
// runs only a task defined in this first pass. Then the app itself.
import './src/background-tasks';
import 'expo-router/entry';
