import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitiseTheme, themeClasses, themeProperties, themeRules, themeStylesheet } from '../src/theme';

test('a valid theme is kept', () => {
    const theme = {
        font: `"Brand Sans", arial, sans-serif`,
        colours: { primary: '#00703c', link: '#1D7' },
        radius: 0,
    };
    assert.deepEqual(sanitiseTheme(theme), theme);
});

test('a bad value is dropped whole, and an empty theme is no theme', () => {
    for (const bad of [
        undefined, null, 'theme', 42, {},
        { preset: 'govuk' },
        { font: 'x'.repeat(201) },
        { font: '' },
        { font: 'Arial; background:url(//evil)' },
        { font: 'url(x)' },
        { font: 'back\\slash' },
        { colours: { primary: 'red' } },
        { colours: { primary: '#12' } },
        { colours: { primary: '#00703c;}' } },
        { colours: { primary: 'rgb(0,0,0)' } },
        { colours: { unknown: '#000' } },
        { colours: 'red' },
        { radius: 25 },
        { radius: -1 },
        { radius: 1.5 },
        { radius: '4' },
    ]) {
        assert.equal(sanitiseTheme(bad), undefined, JSON.stringify(bad));
    }
});

test('a bad value does not take the good ones with it', () => {
    assert.deepEqual(
        sanitiseTheme({ radius: 99, colours: { primary: 'red', link: '#000' }, font: 'Arial' }),
        { colours: { link: '#000' }, font: 'Arial' },
    );
});

test('values become properties, never stylesheet text', () => {
    const theme = sanitiseTheme({ font: 'Arial', colours: { primary: '#012345' }, radius: 4 })!;
    assert.deepEqual(themeProperties(theme), {
        '--pv-font': 'Arial',
        '--pv-radius': '4px',
        '--pv-primary': '#012345',
    });
    const css = themeStylesheet(theme);
    assert.ok(!css.includes('#012345'));
    assert.ok(!css.includes('Arial'));
    assert.ok(css.includes('var(--pv-primary)'));
});

test('only the tokens set get rules, so the default gate keeps the rest', () => {
    const rules = themeRules({ radius: 0 });
    assert.ok(rules.includes('--pv-radius'));
    assert.ok(!rules.includes('--pv-text'));
    assert.ok(rules.startsWith(':host(.themed) .btn-provider'));
    assert.ok(themeRules({ font: 'Arial' }).includes(':host(.themed), :host(.themed) button'));
});

test('a theme is one class and the rules for its own tokens', () => {
    assert.deepEqual(themeClasses({ radius: 0 }), ['themed']);
    assert.equal(themeStylesheet({ radius: 0 }), themeRules({ radius: 0 }));
});
