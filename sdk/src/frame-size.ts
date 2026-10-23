/**
 * The inline auth frame tells its host how tall its content is.
 *
 * An iframe cannot size itself to a cross-origin document, and a percentage
 * height only works against a definite parent. So the hosted page measures
 * its own UI on every render and posts `privasys:frame:size`; the embedding
 * client sets the iframe (or the overlay container) to that height. The
 * adopter's container can then be auto-sized, and no page needs to know
 * how tall a QR screen, a passkey prompt or a success tile is.
 */

/** Message type posted by the hosted frame to its parent. */
export const FRAME_SIZE_MESSAGE = 'privasys:frame:size';

/**
 * The smallest height an inline frame is given, so the box never collapses
 * between two renders (the shadow root is emptied before it is refilled).
 */
export const INLINE_MIN_HEIGHT = 320;

/**
 * The height to give an inline frame for a reported content height: a whole
 * number of pixels, never below the floor, and nothing for a value that is
 * not a finite positive number (an old or foreign frame).
 */
export function inlineFrameHeight(reported: unknown, floor: number = INLINE_MIN_HEIGHT): number | null {
    if (typeof reported !== 'number' || !Number.isFinite(reported) || reported <= 0) return null;
    return Math.max(floor, Math.ceil(reported));
}
