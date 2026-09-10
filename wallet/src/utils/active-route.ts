// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Which push-target screens are currently on screen.
 *
 * Inbound notifications route by pushing a path. That is right when the holder
 * is somewhere else, and wrong when they are already looking at the screen the
 * push targets: it stacks a second copy of the same view.
 *
 * The cost is not cosmetic. Approving several vault operations in a row pushed
 * one screen per notification, so after working through the queue the holder
 * had a pile of identical screens, each showing "nothing left to approve", and
 * had to press back once per approval to get home (2026-09-10).
 *
 * It only matters for LIST screens, which show everything pending and are
 * therefore idempotent: if the screen is already up, the store update that
 * precedes the push has already put the new item in the list, and pushing adds
 * nothing. A per-request screen is different and should still stack, because
 * each instance shows a different request.
 *
 * Deliberately a module-level set rather than router state: the dispatcher is a
 * plain function called from a notification handler, with no component context
 * to read a pathname from.
 */

import { useCallback } from 'react';
import { useFocusEffect } from '@react-navigation/native';

const active = new Set<string>();

/** True while a screen registered under this name is focused. */
export function isRouteActive(name: string): boolean {
    return active.has(name);
}

/** The registry itself, so it can be exercised without a React render. */
export function markRouteActive(name: string): void {
    active.add(name);
}

export function markRouteInactive(name: string): void {
    active.delete(name);
}

/**
 * Register this screen as active while it is focused. Focus rather than mount,
 * so a screen buried under another one does not suppress a push that should
 * bring its own view forward.
 */
export function useActiveRoute(name: string): void {
    useFocusEffect(
        useCallback(() => {
            markRouteActive(name);
            return () => markRouteInactive(name);
        }, [name]),
    );
}

/** Test seam: forget every registration. */
export function resetActiveRoutes(): void {
    active.clear();
}
