// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Custom animated splash overlay.
 *
 * Two large rotated rectangles (green top-left, blue bottom-right) form the
 * icon's 135° diagonal split. The white gap shakes perpendicular to the
 * diagonal, then both shapes slide apart vertically to reveal the app.
 */

import { useEffect } from 'react';
import { Dimensions, StyleSheet } from 'react-native';
import Animated, {
    useSharedValue,
    useAnimatedStyle,
    withSequence,
    withTiming,
    withDelay,
    runOnJS,
    Easing
} from 'react-native-reanimated';

const { width: SCREEN_W, height: SCREEN_H } = Dimensions.get('window');

const SLIDE_DISTANCE = SCREEN_H * 0.7;

// cos(45°) = sin(45°) — perpendicular direction to the diagonal
const PERP = Math.SQRT1_2;

interface Props {
    onComplete: () => void;
}

export function SplashAnimation({ onComplete }: Props) {
    const shakePerp = useSharedValue(0);
    const greenSlideY = useSharedValue(0);
    const blueSlideY = useSharedValue(0);
    const opacity = useSharedValue(1);

    useEffect(() => {
        // Shake the white gap perpendicular to the 135° diagonal
        shakePerp.value = withSequence(
            withTiming(8, { duration: 60 }),
            withTiming(-8, { duration: 60 }),
            withTiming(7, { duration: 55 }),
            withTiming(-7, { duration: 55 }),
            withTiming(4, { duration: 50 }),
            withTiming(-4, { duration: 50 }),
            withTiming(0, { duration: 40 })
        );

        // After shake (~370ms), slide apart vertically
        const slideDelay = 400;

        greenSlideY.value = withDelay(
            slideDelay,
            withTiming(-SLIDE_DISTANCE, {
                duration: 500,
                easing: Easing.in(Easing.cubic)
            })
        );

        blueSlideY.value = withDelay(
            slideDelay,
            withTiming(SLIDE_DISTANCE, {
                duration: 500,
                easing: Easing.in(Easing.cubic)
            })
        );

        opacity.value = withDelay(
            slideDelay + 400,
            withTiming(0, { duration: 150 }, (finished) => {
                if (finished) {
                    runOnJS(onComplete)();
                }
            })
        );
    }, []);

    const greenStyle = useAnimatedStyle(() => ({
        transform: [
            { translateX: shakePerp.value * PERP },
            { translateY: shakePerp.value * PERP + greenSlideY.value },
            { rotate: '-45deg' }
        ],
        opacity: opacity.value
    }));

    const blueStyle = useAnimatedStyle(() => ({
        transform: [
            { translateX: shakePerp.value * PERP },
            { translateY: shakePerp.value * PERP + blueSlideY.value },
            { rotate: '-45deg' }
        ],
        opacity: opacity.value
    }));

    return (
        <Animated.View style={styles.overlay} pointerEvents="none">
            <Animated.View style={[styles.greenShape, greenStyle]} />
            <Animated.View style={[styles.blueShape, blueStyle]} />
        </Animated.View>
    );
}

const SHAPE_SIZE = Math.max(SCREEN_W, SCREEN_H) * 1.5;
const GAP = 20;

const styles = StyleSheet.create({
    overlay: {
        ...StyleSheet.absoluteFillObject,
        backgroundColor: '#FFFFFF',
        zIndex: 999
    },
    greenShape: {
        position: 'absolute',
        width: SHAPE_SIZE,
        height: SHAPE_SIZE,
        backgroundColor: '#34C17B',
        top: -SHAPE_SIZE / 2 - GAP / 2,
        left: -SHAPE_SIZE / 2 + SCREEN_W / 2 - SCREEN_H * 0.05
    },
    blueShape: {
        position: 'absolute',
        width: SHAPE_SIZE,
        height: SHAPE_SIZE,
        backgroundColor: '#00AAEE',
        top: SCREEN_H / 2 + GAP / 2 - SHAPE_SIZE / 2 + SCREEN_H * 0.05,
        left: SCREEN_W / 2 - SHAPE_SIZE / 2 + SCREEN_H * 0.05
    }
});
