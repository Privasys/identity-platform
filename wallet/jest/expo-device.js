// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// expo-device ships as ES modules, which Jest cannot load. The wallet reads
// the model name and whether it runs on a real device.
module.exports = {
    modelName: 'Test Phone',
    deviceName: null,
    isDevice: false,
    osName: 'test',
};
