// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

import { useEffect, useRef, createElement, type ReactNode } from 'react';
import { AttributePicker, type AttributePickerConfig } from './attributes-ui';

/**
 * The attribute picker as a React component.
 *
 * The picker itself is plain DOM in a closed shadow root (see attributes-ui.ts),
 * so this is a mount point rather than a reimplementation: two renderings of the
 * same trust markers would eventually disagree, and the one a user is looking at
 * would be whichever framework their vendor happened to pick.
 */
export function PrivasysAttributePicker(
    props: Omit<AttributePickerConfig, 'container'> & { className?: string },
): ReactNode {
    const mount = useRef<HTMLDivElement | null>(null);
    const picker = useRef<AttributePicker | null>(null);
    const { className, onChange, selected, attributes, only, showKeys, layout, prices, copy, totalTemplate } =
        props;
    // Wording is set once per mount; comparing it by value keeps a caller that
    // builds the object inline from tearing the picker down on every render.
    const copyKey = JSON.stringify(copy ?? null);

    // onChange is re-created by most callers on every render; holding it in a ref
    // keeps the picker from being torn down and rebuilt underneath the user's
    // click, which loses focus and scroll position.
    const onChangeRef = useRef(onChange);
    onChangeRef.current = onChange;

    useEffect(() => {
        if (!mount.current) return;
        picker.current = new AttributePicker({
            container: mount.current,
            selected,
            attributes,
            only,
            showKeys,
            layout,
            prices,
            copy,
            totalTemplate,
            onChange: (keys) => onChangeRef.current?.(keys),
        });
        return () => {
            picker.current?.destroy();
            picker.current = null;
        };
        // `selected` is the INITIAL selection; use the ref's setSelection to
        // drive it from outside, or the picker would reset mid-interaction.
        // Prices are left out for the same reason: they arrive after the first
        // render and are applied below without rebuilding the picker.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [attributes, only, showKeys, layout, copyKey, totalTemplate]);

    // Prices usually land a moment after the picker, from the catalogue. Apply
    // them in place, so a choice made while they loaded is not thrown away.
    useEffect(() => {
        picker.current?.setPrices(prices ?? null);
    }, [prices]);

    return createElement('div', { ref: mount, className });
}
