// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// Says of a build script that it runs on every build.
//
// expo-dev-client adds a script to the app target that takes its local network
// keys out of a release build's Info.plist. It declares no outputs, so Xcode
// warns on every build ("Script has ambiguous dependencies causing it to run
// on every build"). Running every time is what the script is for: this marks
// it so (Xcode's "Based on dependency analysis", unticked), and the warning
// goes. The script itself is untouched.
//
// Done once the project is written, whichever plugin added the script first.

const { withFinalizedMod, IOSConfig } = require('expo/config-plugins');
const fs = require('fs');

const PHASES = ['[Expo Dev Launcher] Strip Local Network Keys for Release'];

module.exports = function withScriptPhaseAlwaysRuns(config) {
    return withFinalizedMod(config, [
        'ios',
        (mod) => {
            const project = IOSConfig.XcodeUtils.getPbxproj(mod.modRequest.projectRoot);
            const phases = project.hash.project.objects.PBXShellScriptBuildPhase || {};
            let changed = false;
            for (const phase of Object.values(phases)) {
                if (typeof phase !== 'object') continue;
                const name = String(phase.name || '').replace(/^"|"$/g, '');
                if (PHASES.includes(name) && phase.alwaysOutOfDate !== 1) {
                    phase.alwaysOutOfDate = 1;
                    changed = true;
                }
            }
            if (changed) fs.writeFileSync(project.filepath, project.writeSync());
            return mod;
        },
    ]);
};
