/**
 * A calendar date from a document chip (`YYYY-MM-DD`) as a local-time Date.
 *
 * `new Date('1985-08-28')` is midnight UTC, which a phone west of Greenwich
 * shows as the 27th. A date of birth is a day, not an instant, so it is built
 * from its parts in local time. Returns null for anything that is not a real
 * calendar date.
 */
export function calendarDate(iso?: string): Date | null {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso ?? '');
    if (!m) return null;
    const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
    const date = new Date(y, mo - 1, d);
    return date.getFullYear() === y && date.getMonth() === mo - 1 && date.getDate() === d ? date : null;
}
