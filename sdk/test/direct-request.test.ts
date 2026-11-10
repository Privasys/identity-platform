import { test } from 'node:test';
import assert from 'node:assert/strict';
import { directBody, directUrl, headerRecord, sendDirect } from '../src/direct-request';

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
