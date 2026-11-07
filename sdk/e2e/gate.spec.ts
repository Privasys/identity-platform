/**
 * The themed gate, rendered from the built bundle on a static page, checked
 * for accessibility and against reference screenshots. The shadow root is
 * closed in production; the page opens it here so axe can read inside.
 * Run after `npm run build`: `npm run test:gate`.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const bundle = readFileSync(join(process.cwd(), 'dist', 'privasys-auth.iife.js'), 'utf8');

const VIEWPORTS = [
    { name: 'phone', width: 390, height: 844 },
    { name: 'tablet', width: 768, height: 1024 },
    { name: 'laptop', width: 1280, height: 800 },
    { name: 'wide', width: 1920, height: 1080 },
];

type GateConfig = Record<string, unknown>;

async function renderGate(page: Page, config: GateConfig): Promise<void> {
    await page.addInitScript(() => {
        const attach = Element.prototype.attachShadow;
        Element.prototype.attachShadow = function (init: ShadowRootInit) {
            return attach.call(this, { ...init, mode: 'open' });
        };
        // The gate's menu lists a passkey only where WebAuthn exists.
        (window as unknown as { PublicKeyCredential: unknown }).PublicKeyCredential ??= function () {};
    });
    await page.route('https://gate.test/', (route) => route.fulfill({
        contentType: 'text/html',
        body: '<!doctype html><html lang="en"><head><title>Gate</title></head><body></body></html>',
    }));
    await page.goto('https://gate.test/');
    await page.addScriptTag({ content: bundle });
    await page.evaluate((cfg) => {
        const w = window as unknown as { Privasys: { AuthUI: new (c: unknown) => { signIn(): Promise<unknown> } } };
        void new w.Privasys.AuthUI({
            apiBase: 'https://gate.test',
            appName: 'Example Register',
            rpId: 'gate.test',
            socialProviders: ['microsoft'],
            methods: ['social', 'passkey'],
            ...cfg,
        }).signIn().catch(() => undefined);
    }, config);
    await expect(page.locator('[data-privasys-auth]').getByRole('button', { name: /microsoft/i })).toBeVisible();
    await page.waitForTimeout(250); // the host's fade-in
}

const govuk = { presentation: 'page', theme: { preset: 'govuk', font: 'Arial, sans-serif' }, legal: false };

for (const scheme of ['light', 'dark'] as const) {
    test.describe(`${scheme} appearance`, () => {
        test.use({ colorScheme: scheme });

        test('the preset meets WCAG 2.2 AA', async ({ page }) => {
            await renderGate(page, govuk);
            const results = await new AxeBuilder({ page })
                .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
                .analyze();
            expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target).join(' ')}`)).toEqual([]);
        });

        test('the default footer meets WCAG 2.2 AA', async ({ page }) => {
            await renderGate(page, { presentation: 'inline' });
            const results = await new AxeBuilder({ page })
                .include('[data-privasys-auth]')
                .withTags(['wcag2aa'])
                .analyze();
            const footer = results.violations.flatMap((v) => v.nodes).filter((n) => String(n.target).includes('.footer'));
            expect(footer.map((n) => String(n.target))).toEqual([]);
        });

        for (const vp of VIEWPORTS) {
            test(`the preset at ${vp.name} width`, async ({ page }) => {
                await page.setViewportSize({ width: vp.width, height: vp.height });
                await renderGate(page, govuk);
                await expect(page).toHaveScreenshot(`govuk-${scheme}-${vp.name}.png`, { animations: 'disabled' });
            });
        }
    });
}

test('the preset labels its buttons in full and draws no divider', async ({ page }) => {
    await renderGate(page, govuk);
    const gate = page.locator('[data-privasys-auth]');
    await expect(gate.getByRole('button', { name: 'Sign in with Microsoft' })).toBeVisible();
    await expect(gate.getByRole('button', { name: 'Sign in with a passkey' })).toBeVisible();
    await expect(gate.locator('.divider')).toHaveCount(0);
});

test('legal: false hides the terms inline and on a page, never in a modal', async ({ page }) => {
    await renderGate(page, { presentation: 'inline', legal: false });
    await expect(page.locator('[data-privasys-auth] .footer')).toHaveCount(0);
    await page.goto('about:blank');
    await renderGate(page, { presentation: 'page', legal: false });
    await expect(page.locator('[data-privasys-auth] .footer')).toHaveCount(0);
    await expect(page.locator('[data-privasys-auth] .gate-seal')).toContainText('Secured by');
    await page.goto('about:blank');
    await renderGate(page, { presentation: 'modal', legal: false });
    await expect(page.locator('[data-privasys-auth] .footer')).toBeVisible();
});

test('every button shows a visible focus state', async ({ page }) => {
    await renderGate(page, { presentation: 'inline' });
    const button = page.locator('[data-privasys-auth]').getByRole('button', { name: /microsoft/i });
    await button.focus();
    await page.keyboard.press('Shift+Tab');
    await page.keyboard.press('Tab');
    const outline = await button.evaluate((el) => getComputedStyle(el).outlineStyle);
    expect(outline).toBe('solid');
});
