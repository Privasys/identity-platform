// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Date and value formatting for i18next, without `Intl`.
 *
 * Hermes delegates `Intl.DateTimeFormat` to the platform, so it mostly works,
 * but it formats in the DEVICE locale and quietly ignores locales the OS has
 * no data for. The wallet lets the app language differ from the device
 * language (Settings -> Language), so "device locale" is the wrong answer:
 * a French-speaking user on an English phone must see French month names.
 *
 * So patterns and month names travel in the locale pack, next to the copy
 * they belong with, and these formatters interpret them. That also keeps
 * date rendering identical across engines and testable in plain Node.
 *
 * Registered on the i18next instance as `date`, `time`, `datetime` and
 * `technical`, usable from any string:
 *
 *     "issued": "Issued {{when, date}}"
 *     "expires": "Expires {{when, datetime}}"
 *     "digest": "Measurement {{value, technical}}"
 */

/**
 * Pattern tokens, longest first so `MMMM` wins over `MM` over `M`.
 *
 * The quoted-literal alternative comes first and is not optional. Several
 * languages write a word inside the long date (Latvian "2026. gada 3. marts",
 * Lithuanian "2026 m. kovo 3 d."), and every letter of those words is also a
 * token: unquoted, "gada" renders as "ga3a". ICU rules apply, so wrap literal
 * text in single quotes and write a real apostrophe as `''`.
 */
const TOKEN = /'(?:[^']|'')*'|yyyy|yy|MMMM|MMM|MM|M|dddd|ddd|dd|d|HH|H|mm|ss/g;

/** The `format` block every locale pack carries. */
export interface LocaleFormats {
    /** Numeric date, e.g. "dd/MM/yyyy" (en-GB) or "d.M.yyyy" (cs). */
    date: string;
    /** Date with a spelled-out month, e.g. "d MMMM yyyy". */
    dateLong: string;
    /** Clock time, e.g. "HH:mm". */
    time: string;
    /** Date and time combined, e.g. "{{date}}, {{time}}". */
    dateTime: string;
    /** 12 full month names, January first. */
    months: string[];
    /** 12 abbreviated month names, January first. */
    monthsShort: string[];
    /** 7 full weekday names, SUNDAY first (matches Date.getDay()). */
    days: string[];
    /** 7 abbreviated weekday names, Sunday first. */
    daysShort: string[];
}

/**
 * en-GB formats, compiled into the binary. This is the fallback used before
 * a pack has downloaded and whenever one fails to verify, so it must never
 * depend on pack data being present.
 */
export const EN_GB_FORMATS: LocaleFormats = {
    date: 'dd/MM/yyyy',
    dateLong: 'd MMMM yyyy',
    time: 'HH:mm',
    dateTime: '{{date}}, {{time}}',
    months: [
        'January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December',
    ],
    monthsShort: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
    days: ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'],
    daysShort: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'],
};

const pad = (n: number) => String(n).padStart(2, '0');

/** Coerce whatever a screen passed us into a Date, or null if unusable. */
export function toDate(value: unknown): Date | null {
    if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
    if (typeof value === 'number') {
        const d = new Date(value);
        return Number.isNaN(d.getTime()) ? null : d;
    }
    if (typeof value === 'string' && value.trim()) {
        const d = new Date(value);
        return Number.isNaN(d.getTime()) ? null : d;
    }
    return null;
}

/**
 * Render `date` through a token pattern using `f`'s month and day names.
 * Unknown tokens are left as-is rather than throwing, so a malformed pattern
 * in a downloaded pack degrades to visible nonsense instead of a crash on a
 * screen the user may need (recovery, consent).
 */
export function formatPattern(date: Date, pattern: string, f: LocaleFormats): string {
    return pattern.replace(TOKEN, (t) => {
        // Quoted literal: strip the delimiters, unescape doubled quotes. A bare
        // `''` is ICU's way of writing one apostrophe and unquotes to empty.
        if (t.startsWith("'")) return t.slice(1, -1).replace(/''/g, "'") || "'";
        switch (t) {
            case 'yyyy': return String(date.getFullYear());
            case 'yy': return pad(date.getFullYear() % 100);
            case 'MMMM': return f.months[date.getMonth()] ?? '';
            case 'MMM': return f.monthsShort[date.getMonth()] ?? '';
            case 'MM': return pad(date.getMonth() + 1);
            case 'M': return String(date.getMonth() + 1);
            case 'dddd': return f.days[date.getDay()] ?? '';
            case 'ddd': return f.daysShort[date.getDay()] ?? '';
            case 'dd': return pad(date.getDate());
            case 'd': return String(date.getDate());
            case 'HH': return pad(date.getHours());
            case 'H': return String(date.getHours());
            case 'mm': return pad(date.getMinutes());
            case 'ss': return pad(date.getSeconds());
            default: return t;
        }
    });
}

/** Short numeric date, the default for `{{when, date}}`. */
export function formatDate(value: unknown, f: LocaleFormats, long = false): string {
    const d = toDate(value);
    if (!d) return '';
    return formatPattern(d, long ? f.dateLong : f.date, f);
}

/** Clock time, `{{when, time}}`. */
export function formatTime(value: unknown, f: LocaleFormats): string {
    const d = toDate(value);
    if (!d) return '';
    return formatPattern(d, f.time, f);
}

/** Date and time composed through the locale's own joining pattern. */
export function formatDateTime(value: unknown, f: LocaleFormats, long = false): string {
    const d = toDate(value);
    if (!d) return '';
    return f.dateTime
        .replace('{{date}}', formatPattern(d, long ? f.dateLong : f.date, f))
        .replace('{{time}}', formatPattern(d, f.time, f));
}

/**
 * A value that must survive translation untouched: hashes, DIDs, MRENCLAVE
 * and RTMR measurements, base64 handles, JWTs, version numbers.
 *
 * Grouping separators or digit shaping inside a measurement would make two
 * identical values look different, which on an attestation screen is a
 * correctness bug rather than a cosmetic one. This formatter exists so that
 * intent is explicit at the call site and greppable.
 */
export function formatTechnical(value: unknown): string {
    return value === null || value === undefined ? '' : String(value);
}

/**
 * Plain integer rendering for counts. Deliberately NOT locale-aware: the
 * wallet's counts are small (files, devices, sessions) and adding thousands
 * separators for them buys nothing while risking the technical-value trap
 * above. Revisit only if a genuinely large user-facing number appears.
 */
export function formatCount(value: unknown): string {
    const n = Number(value);
    return Number.isFinite(n) ? String(Math.trunc(n)) : '';
}
