import { calendarDate } from '@/services/calendar-date';

describe('calendarDate', () => {
    it('keeps the day the chip states, whatever the time zone', () => {
        const d = calendarDate('1985-08-28');
        expect(d && [d.getFullYear(), d.getMonth() + 1, d.getDate()]).toEqual([1985, 8, 28]);
    });
    it('refuses what is not a calendar date', () => {
        expect(calendarDate('2028-02-30')).toBeNull();
        expect(calendarDate('280411')).toBeNull();
        expect(calendarDate(undefined)).toBeNull();
    });
});
