import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DirectWebSocket, directBody, directUrl, headerRecord, sendDirect } from '../src/direct-request';

test('a path resolves on the direct origin', () => {
    assert.equal(directUrl('https://drive.example.org', '/api/files?x=1'), 'https://drive.example.org/api/files?x=1');
});

test('a path that would carry the token elsewhere is refused', () => {
    for (const bad of ['https://evil.example/x', '//evil.example/x', 'api/files', '']) {
        assert.throws(() => directUrl('https://drive.example.org', bad), JSON.stringify(bad));
    }
    assert.throws(() => directUrl('http://drive.example.org', '/x'));
});

test('a body is encoded the way a sealed request encodes it', () => {
    const dec = (b?: Uint8Array) => new TextDecoder().decode(b);
    assert.deepEqual(directBody(undefined), {});
    assert.equal(dec(directBody('raw').bytes), 'raw');
    assert.equal(directBody('raw').contentType, undefined);
    const json = directBody({ a: 1 });
    assert.equal(dec(json.bytes), '{"a":1}');
    assert.equal(json.contentType, 'application/json');
    const bytes = new Uint8Array([1, 2]);
    assert.equal(directBody(bytes).bytes, bytes);
});

test('the request carries the bearer, no cookie, and follows no redirect', async () => {
    let seen: { url: string; init: RequestInit } | null = null;
    const fetchImpl = (async (url: string, init: RequestInit) => {
        seen = { url, init };
        return new Response('ok', { status: 200, headers: { 'x-a': '1' } });
    }) as unknown as typeof fetch;
    const resp = await sendDirect({
        origin: 'https://drive.example.org', token: 'tok', method: 'post', path: '/api/x',
        body: { a: 1 }, init: { headers: { 'X-Custom': 'v' } }, fetchImpl,
    });
    assert.ok(seen);
    const { url, init } = seen!;
    assert.equal(url, 'https://drive.example.org/api/x');
    assert.equal(init.method, 'POST');
    assert.equal(init.credentials, 'omit');
    assert.equal(init.redirect, 'error');
    const h = new Headers(init.headers);
    assert.equal(h.get('authorization'), 'Bearer tok');
    assert.equal(h.get('content-type'), 'application/json');
    assert.equal(h.get('x-custom'), 'v');
    assert.deepEqual(headerRecord(resp.headers), { 'content-type': 'text/plain;charset=UTF-8', 'x-a': '1' });
});

test('a GET sends no body, and a caller content type is kept', async () => {
    const inits: RequestInit[] = [];
    const fetchImpl = (async (_u: string, init: RequestInit) => {
        inits.push(init);
        return new Response(null, { status: 204 });
    }) as unknown as typeof fetch;
    await sendDirect({ origin: 'https://d.example', token: 't', method: 'GET', path: '/', body: { a: 1 }, fetchImpl });
    await sendDirect({
        origin: 'https://d.example', token: 't', method: 'PUT', path: '/', body: { a: 1 },
        init: { headers: { 'Content-Type': 'application/merge-patch+json' } }, fetchImpl,
    });
    assert.equal(inits[0].body, undefined);
    assert.equal(new Headers(inits[1].headers).get('content-type'), 'application/merge-patch+json');
});

class FakeSocket {
    static last: FakeSocket | null = null;
    readyState = 0;
    binaryType = 'blob';
    sent: unknown[] = [];
    onopen: (() => void) | null = null;
    onmessage: ((ev: { data: unknown }) => void) | null = null;
    onerror: (() => void) | null = null;
    onclose: ((ev: { code: number; reason: string; wasClean: boolean }) => void) | null = null;
    constructor(readonly url: string, readonly protocols: string[]) { FakeSocket.last = this; }
    send(d: unknown) { this.sent.push(d); }
    close(code: number, reason: string) { this.readyState = 3; this.onclose?.({ code, reason, wasClean: true }); }
    open() { this.readyState = 1; this.onopen?.(); }
}
const makeFake = (u: string, p: string[]) => new FakeSocket(u, p) as unknown as WebSocket;

test('a direct socket carries the token as a subprotocol and queues until open', async () => {
    const ws = new DirectWebSocket('https://drive.example.org', '/ws?x=1', async () => 'tok', makeFake);
    ws.send({ a: 1 });
    await new Promise((r) => setTimeout(r, 0));
    const fake = FakeSocket.last!;
    assert.equal(fake.url, 'wss://drive.example.org/ws?x=1');
    assert.deepEqual(fake.protocols, ['privasys.v1', 'privasys.bearer.tok']);
    assert.equal(fake.binaryType, 'arraybuffer');
    assert.equal(fake.sent.length, 0);
    fake.open();
    await ws.ready;
    assert.equal(ws.open, true);
    assert.equal(new TextDecoder().decode(fake.sent[0] as Uint8Array), '{"a":1}');

    const got: string[] = [];
    ws.onMessage((d) => got.push(new TextDecoder().decode(d)));
    fake.onmessage!({ data: 'text' });
    fake.onmessage!({ data: new TextEncoder().encode('bin').buffer });
    assert.deepEqual(got, ['text', 'bin']);

    let closed: number | null = null;
    ws.onClose((i) => { closed = i.code; });
    ws.close();
    assert.equal(closed, 1000);
    assert.throws(() => ws.send('x'));
});

test('a direct socket that cannot get a token, or leaves the origin, never opens', async () => {
    FakeSocket.last = null;
    const noToken = new DirectWebSocket('https://d.example', '/ws', async () => { throw new Error('signed out'); }, makeFake);
    await assert.rejects(noToken.ready, /signed out/);
    const away = new DirectWebSocket('https://d.example', '//evil.example/ws', async () => 'tok', makeFake);
    await assert.rejects(away.ready, /stay on the direct origin/);
    await new Promise((r) => setTimeout(r, 0));
    assert.equal(FakeSocket.last, null);
});
