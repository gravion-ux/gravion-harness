'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  CHECKS,
  headerValues,
  parseSetCookie,
  runCheck,
  splitSetCookieHeader,
} = require('../src/checkers');

const TARGET = { type: 'url', value: 'https://example.com/' };

function cookieContext(overrides = {}) {
  return {
    probe: {
      ok: true,
      url: 'https://example.com/',
      method: 'GET',
      status: 200,
      headers: {},
      ...overrides,
    },
    target: TARGET,
  };
}

test('the cookie check is registered under the name steps refer to', () => {
  assert.equal(typeof CHECKS.cookies, 'function');
});

test('a cookie value parses into its name, value and attributes', () => {
  const cookie = parseSetCookie('session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax');

  assert.equal(cookie.name, 'session');
  assert.equal(cookie.value, 'abc123');
  assert.equal(cookie.attributes.secure, true);
  assert.equal(cookie.attributes.httponly, true);
  assert.equal(cookie.attributes.samesite, 'Lax');
  assert.equal(cookie.attributes.path, '/');
});

test('a cookie without a value or a name parses defensively', () => {
  assert.equal(parseSetCookie(''), null);
  assert.equal(parseSetCookie('  ; Secure'), null);
  assert.equal(parseSetCookie('flagonly; Secure').name, 'flagonly');
});

test('a combined Set-Cookie header splits on cookie boundaries, not on dates', () => {
  const combined = 'session=abc; Expires=Wed, 21 Oct 2030 07:28:00 GMT; Path=/, theme=dark; Path=/';
  const parts = splitSetCookieHeader(combined);

  assert.equal(parts.length, 2);
  assert.match(parts[0], /^session=abc/);
  assert.match(parts[0], /21 Oct 2030/);
  assert.match(parts[1], /^theme=dark/);
});

test('header values come back as a list for string and array values alike', () => {
  const headers = { 'Set-Cookie': ['a=1', 'b=2'], 'x-one': 'single' };

  assert.deepEqual(headerValues(headers, 'set-cookie'), ['a=1', 'b=2']);
  assert.deepEqual(headerValues(headers, 'X-One'), ['single']);
  assert.deepEqual(headerValues(headers, 'x-absent'), []);
  assert.deepEqual(headerValues(null, 'set-cookie'), []);
});

test('a response that sets no cookies produces no cookie findings', () => {
  assert.deepEqual(runCheck('cookies', cookieContext()), []);
  assert.deepEqual(runCheck('cookies', cookieContext({ ok: false })), []);
});

test('a fully attributed cookie produces no findings', () => {
  const findings = runCheck('cookies', cookieContext({
    cookies: ['session=abc; Path=/; Secure; HttpOnly; SameSite=Lax'],
  }));

  assert.deepEqual(findings, []);
});

test('a bare cookie over HTTPS reports Secure, HttpOnly and SameSite', () => {
  const findings = runCheck('cookies', cookieContext({
    cookies: ['session=abc; Path=/'],
  }));

  const titles = findings.map((finding) => finding.title);
  assert.deepEqual(titles, [
    'Cookie "session" is set without the Secure attribute',
    'Cookie "session" is set without the HttpOnly attribute',
    'Cookie "session" is set without a SameSite attribute',
  ]);
  assert.deepEqual(findings.map((finding) => finding.severity), ['low', 'low', 'info']);
  assert.equal(findings[0].category, 'cookie-security');
  assert.equal(findings[0].evidence.response.status, 200);
  assert.ok(findings[0].steps.length > 0, 'the finding must carry reproduction steps');
});

test('a bare cookie over HTTP is not reported for the missing Secure attribute', () => {
  const findings = runCheck('cookies', cookieContext({
    url: 'http://example.com/',
    cookies: ['session=abc; Path=/'],
  }));

  const titles = findings.map((finding) => finding.title);
  assert.ok(!titles.some((title) => title.includes('Secure attribute')));
  assert.ok(titles.some((title) => title.includes('HttpOnly')));
});

test('SameSite=None without Secure is one medium finding, not two findings', () => {
  const findings = runCheck('cookies', cookieContext({
    cookies: ['tracking=xyz; Path=/; HttpOnly; SameSite=None'],
  }));

  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'medium');
  assert.match(findings[0].title, /SameSite=None without the Secure attribute/);
});

test('SameSite=None together with Secure is accepted', () => {
  const findings = runCheck('cookies', cookieContext({
    cookies: ['tracking=xyz; Path=/; Secure; HttpOnly; SameSite=None'],
  }));

  assert.deepEqual(findings, []);
});

test('each cookie in a response is reported under its own name', () => {
  const findings = runCheck('cookies', cookieContext({
    cookies: [
      'session=abc; Secure; HttpOnly; SameSite=Strict',
      'prefs=dark; Path=/',
    ],
  }));

  assert.ok(findings.length > 0);
  assert.ok(findings.every((finding) => finding.title.includes('"prefs"')));
});

test('cookies are also read from the Set-Cookie header when the probe did not capture them', () => {
  const findings = runCheck('cookies', cookieContext({
    cookies: undefined,
    headers: { 'set-cookie': ['session=abc; Path=/', 'theme=dark; Secure; HttpOnly; SameSite=Lax'] },
  }));

  const titles = findings.map((finding) => finding.title);
  assert.ok(titles.some((title) => title.includes('"session"')));
  assert.ok(!titles.some((title) => title.includes('"theme"')));
});

test('a combined Set-Cookie header with an Expires date is read as one cookie', () => {
  const findings = runCheck('cookies', cookieContext({
    cookies: undefined,
    headers: { 'set-cookie': 'session=abc; Expires=Wed, 21 Oct 2030 07:28:00 GMT; Secure; HttpOnly; SameSite=Lax' },
  }));

  assert.deepEqual(findings, []);
});

test('HSTS is reported on HTTPS and skipped on HTTP', () => {
  const httpsFindings = runCheck('security_headers', {
    probe: { ok: true, url: 'https://example.com/', method: 'GET', status: 200, headers: {} },
    target: TARGET,
  });
  assert.ok(httpsFindings.some((finding) => finding.title === 'Missing Strict-Transport-Security header'));

  const httpFindings = runCheck('security_headers', {
    probe: { ok: true, url: 'http://example.com/', method: 'GET', status: 200, headers: {} },
    target: TARGET,
  });
  assert.ok(!httpFindings.some((finding) => finding.title === 'Missing Strict-Transport-Security header'));
});
