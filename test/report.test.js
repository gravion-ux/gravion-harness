'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createFinding, mergeFinding, severityCounts, sortFindings } = require('../src/findings');
const { buildReport, renderMarkdown } = require('../src/report');
const { runCheck } = require('../src/checkers');

test('a finding gets a stable identifier from its title, target and category', () => {
  const first = createFinding({ title: 'Missing header', target: { type: 'url', value: 'https://a.example/' }, category: 'headers' });
  const second = createFinding({ title: 'Missing header', target: { type: 'url', value: 'https://a.example/' }, category: 'headers' });
  const other = createFinding({ title: 'Missing header', target: { type: 'url', value: 'https://b.example/' }, category: 'headers' });

  assert.equal(first.id, second.id);
  assert.notEqual(first.id, other.id);
});

test('an unknown severity becomes informational', () => {
  const finding = createFinding({ title: 'x', severity: 'catastrophic' });

  assert.equal(finding.severity, 'info');
  assert.equal(finding.score, 0);
});

test('findings sort by severity and then by score', () => {
  const findings = [
    createFinding({ title: 'low', severity: 'low' }),
    createFinding({ title: 'critical', severity: 'critical' }),
    createFinding({ title: 'high', severity: 'high' }),
    createFinding({ title: 'info', severity: 'info' }),
  ];

  assert.deepEqual(sortFindings(findings).map((finding) => finding.severity), ['critical', 'high', 'low', 'info']);
});

test('severity counts add up', () => {
  const findings = [
    createFinding({ title: 'a', severity: 'high' }),
    createFinding({ title: 'b', severity: 'high' }),
    createFinding({ title: 'c', severity: 'low' }),
  ];

  assert.deepEqual(severityCounts(findings), { critical: 0, high: 2, medium: 0, low: 1, info: 0 });
});

test('a repeated finding is merged instead of duplicated', () => {
  let findings = [];
  findings = mergeFinding(findings, createFinding({ title: 'Same', target: { type: 'url', value: 'https://a.example/' } }));
  findings = mergeFinding(findings, createFinding({ title: 'Same', target: { type: 'url', value: 'https://a.example/' } }));

  assert.equal(findings.length, 1);
  assert.equal(findings[0].occurrences, 2);
});

test('the security header check reports each missing header', () => {
  const findings = runCheck('security_headers', {
    probe: {
      ok: true,
      url: 'https://example.com/',
      method: 'GET',
      status: 200,
      headers: { 'content-type': 'text/html' },
    },
    target: { type: 'url', value: 'https://example.com/' },
  });

  const titles = findings.map((finding) => finding.title);

  assert.ok(titles.includes('Missing Content-Security-Policy header'));
  assert.ok(titles.includes('Missing X-Content-Type-Options header'));
  assert.ok(titles.includes('Missing X-Frame-Options header'));
  assert.ok(titles.includes('Missing Referrer-Policy header'));
});

test('a header that is present is not reported', () => {
  const findings = runCheck('security_headers', {
    probe: {
      ok: true,
      url: 'https://example.com/',
      headers: {
        'content-security-policy': "default-src 'self'",
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'SAMEORIGIN',
        'referrer-policy': 'no-referrer',
      },
    },
    target: { type: 'url', value: 'https://example.com/' },
  });

  assert.equal(findings.length, 0);
});

test('a private key in the body is reported as critical with the body as evidence', () => {
  const findings = runCheck('info_exposure', {
    probe: {
      ok: true,
      url: 'https://example.com/.env',
      method: 'GET',
      status: 200,
      headers: {},
      body: '-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----',
    },
    target: { type: 'url', value: 'https://example.com/.env' },
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'critical');
  assert.match(findings[0].evidence.bodyExcerpt, /BEGIN RSA PRIVATE KEY/);
});

test('a stack trace in the body is reported as medium', () => {
  const findings = runCheck('info_exposure', {
    probe: {
      ok: true,
      url: 'https://example.com/',
      headers: {},
      body: 'Traceback (most recent call last):\n  File "app.py", line 3',
    },
    target: { type: 'url', value: 'https://example.com/' },
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'medium');
});

test('a clean body produces no exposure finding', () => {
  const findings = runCheck('info_exposure', {
    probe: { ok: true, url: 'https://example.com/', headers: {}, body: '<html>hello</html>' },
    target: { type: 'url', value: 'https://example.com/' },
  });

  assert.equal(findings.length, 0);
});

test('a server error is reported', () => {
  const findings = runCheck('status', {
    probe: { ok: true, url: 'https://example.com/', status: 500, statusText: 'Internal Server Error', headers: {} },
    target: { type: 'url', value: 'https://example.com/' },
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'medium');
  assert.match(findings[0].title, /500/);
});

test('a redirect that leaves the scope is recorded as an informational finding', () => {
  const findings = runCheck('status', {
    probe: {
      ok: true,
      url: 'https://example.com/',
      status: 302,
      headers: {},
      blockedRedirect: 'redirect to https://elsewhere.example/ leaves the engagement scope',
    },
    target: { type: 'url', value: 'https://example.com/' },
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'info');
  assert.match(findings[0].description, /outside the authorised scope/);
});

test('an unknown check name produces nothing', () => {
  assert.deepEqual(runCheck('not_a_check', { probe: { ok: true } }), []);
});

test('the Markdown report carries the findings, the evidence and the audit state', () => {
  const finding = createFinding({
    title: 'Missing Content-Security-Policy header',
    severity: 'low',
    category: 'security-headers',
    target: { type: 'url', value: 'https://example.com/' },
    description: 'The header is absent.',
    impact: 'Injection has fewer obstacles.',
    remediation: 'Send the header.',
    steps: ['Request the page', 'Inspect the headers'],
    evidence: {
      capturedAt: '2026-01-01T00:00:00.000Z',
      request: { method: 'GET', url: 'https://example.com/' },
      response: { status: 200, headers: { 'content-type': 'text/html' }, bodyBytes: 12 },
      bodyExcerpt: '<html></html>',
    },
    program: 'example',
  });

  const report = buildReport({
    name: 'Example engagement',
    objective: 'review the target',
    program: 'example',
    accessMode: 'smart',
    provider: 'deterministic',
    targets: [{ type: 'url', value: 'https://example.com/', program: 'example' }],
    actionsRun: 3,
    actionsBlocked: 1,
    auditEntries: 12,
    auditVerified: true,
    findings: [finding],
    methodology: ['Requests were read-only.'],
  });

  const markdown = renderMarkdown(report);

  assert.match(markdown, /# Example engagement/);
  assert.match(markdown, /Missing Content-Security-Policy header/);
  assert.match(markdown, /\*\*Evidence\*\*/);
  assert.match(markdown, /GET https:\/\/example\.com\//);
  assert.match(markdown, /content-type/);
  assert.match(markdown, /The chain was verified after the run and is intact/);
  assert.match(markdown, /\| Low \| 1 \|/);
  assert.match(markdown, /3 action\(s\) ran and 1 were blocked/);
});
