import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inlineFrameHeight, INLINE_MIN_HEIGHT } from '../src/frame-size';

test('a reported content height becomes a whole pixel height, never below the floor', () => {
    assert.equal(inlineFrameHeight(612.4), 613);
    assert.equal(inlineFrameHeight(100), INLINE_MIN_HEIGHT);
    assert.equal(inlineFrameHeight(INLINE_MIN_HEIGHT), INLINE_MIN_HEIGHT);
    assert.equal(inlineFrameHeight(700, 560), 700);
    assert.equal(inlineFrameHeight(400, 560), 560);
});

test('a value that is not a positive finite number is ignored', () => {
    for (const bad of [undefined, null, 'tall', -1, 0, NaN, Infinity, {}]) {
        assert.equal(inlineFrameHeight(bad), null, String(bad));
    }
});
