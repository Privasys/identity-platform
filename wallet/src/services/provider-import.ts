// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Bringing a linked provider's attributes into the profile: one path for the
 * Import screen and for linking a provider in the middle of a sign-in.
 *
 * Each attribute is merged (stores/profile mergeAttribute): a value the
 * profile lacks is added, a second email beside the first; the same value is
 * strengthened, its new verifications (the Attribute Verifier's proof among
 * them) merged in; a different value for a single-valued attribute is a
 * conflict. The Import screen asks the holder about each conflict; a sign-in
 * keeps what the holder has, since nobody is there to be asked.
 */

import { ATTRIBUTE_MAP } from '@/services/attributes';
import { useProfileStore, type LinkedProvider, type ProfileAttribute } from '@/stores/profile';

/** A value the provider has that differs from the holder's. */
export interface AttributeConflict {
    existing: ProfileAttribute;
    incoming: ProfileAttribute;
    multiValued: boolean;
}

export interface ImportOutcome {
    added: number;
    strengthened: number;
    /** Left for the holder to decide; empty when conflicts are kept. */
    conflicts: AttributeConflict[];
    /** Conflicts settled by keeping the holder's value. */
    kept: number;
}

/**
 * The avatar and language are also kept on the profile itself: the first
 * value becomes them, and a value the holder chose to take over replaces them.
 */
function adoptProfileField(attr: ProfileAttribute): void {
    if (!attr.value) return;
    const store = useProfileStore.getState();
    if (attr.key === 'picture') store.updateProfile({ avatarUri: attr.value });
    if (attr.key === 'locale') store.updateProfile({ locale: attr.value });
}

/**
 * Link the provider and merge its attributes. `selected` limits the import to
 * those keys (the Import screen's checkboxes); all of them otherwise.
 */
export function applyProviderImport(
    linked: LinkedProvider,
    attributes: ProfileAttribute[],
    { selected, conflicts: onConflict }: { selected?: ReadonlySet<string>; conflicts: 'ask' | 'keep' },
): ImportOutcome {
    const store = useProfileStore.getState();
    store.linkProvider(linked);
    const outcome: ImportOutcome = { added: 0, strengthened: 0, conflicts: [], kept: 0 };
    for (const attr of attributes) {
        if (selected && !selected.has(attr.key)) continue;
        const multiValued = ATTRIBUTE_MAP[attr.key]?.multiValued ?? false;
        const res = useProfileStore.getState().mergeAttribute(attr, multiValued);
        if (res.status === 'conflict') {
            if (onConflict === 'ask') outcome.conflicts.push({ existing: res.existing, incoming: res.incoming, multiValued });
            else outcome.kept++;
        } else if (res.status === 'strengthened') {
            outcome.strengthened++;
        } else {
            outcome.added++;
            if (res.status === 'added') adoptProfileField(attr);
        }
    }
    return outcome;
}

/** Settle one conflict the way the holder chose. */
export function resolveImportConflict(conflict: AttributeConflict, choice: 'keep' | 'replace' | 'both'): void {
    useProfileStore.getState().resolveConflict(conflict.existing, conflict.incoming, choice);
    if (choice === 'replace') adoptProfileField(conflict.incoming);
}
