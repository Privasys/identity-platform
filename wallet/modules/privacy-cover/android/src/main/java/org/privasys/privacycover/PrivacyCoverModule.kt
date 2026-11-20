// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.privacycover

import android.os.Build
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

/**
 * Android's half of the app-switcher cover. From Android 13 the system can be
 * told not to keep a screenshot of the wallet for Recents, which then shows a
 * plain card. Screenshots by the holder still work: FLAG_SECURE would block
 * them too, so it is not used. Before Android 13 the wallet's own cover
 * (components/AppLock) is all there is.
 */
class PrivacyCoverModule : Module() {
    override fun definition() = ModuleDefinition {
        Name("PrivacyCover")

        Function("setEnabled") { on: Boolean ->
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val activity = appContext.currentActivity ?: return@Function
                activity.runOnUiThread { activity.setRecentsScreenshotEnabled(!on) }
            }
        }

        // iOS lifts its cover on the wallet's word; Android has none to lift.
        Function("release") {}
    }
}
