import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AuthUI, type AuthUIConfig } from '../src/ui';

// A gate with its flows replaced by recorders: what start() lets through.
function gate(cfg: Partial<AuthUIConfig>, state = 'idle') {
    const calls: string[] = [];
    const ui = new AuthUI({
        apiBase: 'https://idp.test', appName: 'Example', headless: true,
        onSocialAuth: async (provider, own) => { calls.push(`social:${provider}:${own ? 'own' : 'platform'}`); },
        ...cfg,
    } as AuthUIConfig);
    const u = ui as unknown as Record<string, unknown>;
    u.state = state;
    u.startPush = () => calls.push('push');
    u.startWallet = () => calls.push('wallet');
    u.cleanup = () => calls.push('cleanup');
    return { ui, calls };
}

test('a social choice starts only a provider the gate offers', () => {
    const { ui, calls } = gate({ socialProviders: ['microsoft'] });
    ui.start({ method: 'social', provider: 'github' });
    ui.start({ method: 'social', provider: 'microsoft', own: true });
    assert.deepEqual(calls, []);
    ui.start({ method: 'social', provider: 'microsoft' });
    assert.deepEqual(calls, ['social:microsoft:platform']);
});

test('an own registration starts only when the client has one', () => {
    const { ui, calls } = gate({ socialOwn: [{ provider: 'microsoft', displayName: 'Contoso Staff' }] });
    ui.start({ method: 'social', provider: 'microsoft' });
    assert.deepEqual(calls, []);
    ui.start({ method: 'social', provider: 'microsoft', own: true });
    assert.deepEqual(calls, ['social:microsoft:own']);
});

test('a method the adopter left out cannot be started', () => {
    const { ui, calls } = gate({ methods: ['wallet'], socialProviders: ['microsoft'] });
    ui.start({ method: 'social', provider: 'microsoft' });
    const other = gate({ methods: ['social'], socialProviders: ['microsoft'] });
    other.ui.start({ method: 'wallet' });
    assert.deepEqual([...calls, ...other.calls], []);
});

test('the wallet goes by push when the device has a binding, unless the page asks for the QR code', () => {
    const push = gate({ pushToken: 'device' });
    push.ui.start({ method: 'wallet' });
    const qr = gate({ pushToken: 'device' });
    qr.ui.start({ method: 'wallet', qr: true });
    const none = gate({});
    none.ui.start({ method: 'wallet' });
    assert.deepEqual([push.calls, qr.calls, none.calls], [['push'], ['wallet'], ['wallet']]);
});

test('nothing starts while a flow runs, except the switch from a waiting push to the QR code', () => {
    const busy = gate({ socialProviders: ['microsoft'] }, 'authenticating');
    busy.ui.start({ method: 'social', provider: 'microsoft' });
    busy.ui.start({ method: 'wallet', qr: true });
    assert.deepEqual(busy.calls, []);
    const waiting = gate({ pushToken: 'device' }, 'push-waiting');
    waiting.ui.start({ method: 'social', provider: 'microsoft' });
    waiting.ui.start({ method: 'wallet' });
    assert.deepEqual(waiting.calls, []);
    waiting.ui.start({ method: 'wallet', qr: true });
    assert.deepEqual(waiting.calls, ['cleanup', 'wallet']);
});

test('the options name what the gate offers, and nothing the adopter left out', () => {
    const { ui } = gate({ methods: ['social'], socialProviders: ['microsoft'], pushToken: 'device',
        socialOwn: [{ provider: 'microsoft', displayName: 'Contoso Staff' }] });
    const o = ui.gateOptions();
    assert.equal(o.wallet, false);
    assert.equal(o.push, false);
    assert.deepEqual(o.providers.map((p) => [p.id, p.name, !!p.icon]), [['microsoft', 'Microsoft', true]]);
    assert.deepEqual(o.own.map((r) => r.displayName), ['Contoso Staff']);
    const walletOnly = gate({ methods: ['wallet'], socialProviders: ['microsoft'] }).ui.gateOptions();
    assert.deepEqual([walletOnly.providers, walletOnly.own, walletOnly.wallet], [[], [], true]);
});
