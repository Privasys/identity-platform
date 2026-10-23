import { disclosureRpId, voucherRpId } from '@/services/voucher-rp';

const jwt = (claims: object) =>
    'e30.' + Buffer.from(JSON.stringify(claims)).toString('base64url') + '.sig';

describe('disclosureRpId', () => {
    it('presents a paid disclosure under the rp its voucher was issued to', () => {
        const v = jwt({ rp_id: 'privasys-platform', claims: ['privasys:age_over_18'] });
        expect(voucherRpId(v)).toBe('privasys-platform');
        expect(disclosureRpId('privasys.id', v)).toBe('privasys-platform');
    });
    it('keeps the sign-in rpId without a voucher, or with one that names none', () => {
        expect(disclosureRpId('privasys.id', undefined)).toBe('privasys.id');
        expect(disclosureRpId('app.example', jwt({ claims: [] }))).toBe('app.example');
        expect(disclosureRpId('app.example', 'not-a-jwt')).toBe('app.example');
    });
});
