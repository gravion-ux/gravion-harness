'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { createServer } = require('../src/server');
const { AccessController } = require('../src/access');
const { AuditLog } = require('../src/audit');
const { buildReport } = require('../src/report');
const { createFinding } = require('../src/findings');

/**
 * Builds a harness double with the surface the local server uses.
 *
 * @param {object} [overrides]
 * @returns {object}
 */
function fakeHarness(overrides = {}) {
  const finding = createFinding({
    title: 'Missing X-Frame-Options header',
    severity: 'low',
    target: { type: 'url', value: 'https://example.com/' },
  });

  return {
    access: new AccessController({ mode: 'smart' }),
    provider: { type: 'deterministic' },
    targets: [{ type: 'url', value: 'https://example.com/', program: 'example' }],
    audit: new AuditLog(),
    plan: async () => ({ steps: [], blocked: [], provider: 'deterministic', model: 'offline', error: null }),
    run: async () => ({
      findings: [finding],
      markdown: '# Example engagement',
      report: buildReport({
        name: 'Example engagement',
        objective: 'review the target',
        actionsRun: 1,
        actionsBlocked: 0,
        auditEntries: 2,
        auditVerified: true,
        findings: [finding],
      }),
    }),
    ...overrides,
  };
}

/**
 * Starts the server on an ephemeral loopback port.
 *
 * @param {object} [harness]
 * @returns {Promise<object>}
 */
async function startServer(harness = fakeHarness()) {
  const service = createServer(harness);
  const { url } = await service.listen(0, '127.0.0.1');
  return { service, url };
}

test('the web UI is served on the loopback interface', async () => {
  const { service, url } = await startServer();

  try {
    const response = await fetch(`${url}/`);
    const html = await response.text();

    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type'), /text\/html/);
    assert.match(html, /Gravion/);
  } finally {
    await service.close();
  }
});

test('the status endpoint reports the harness state', async () => {
  const { service, url } = await startServer();

  try {
    const response = await fetch(`${url}/api/status`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.mode, 'smart');
    assert.deepEqual(body.modes, ['ask', 'smart', 'full']);
    assert.equal(body.provider, 'deterministic');
    assert.equal(body.targets.length, 1);
    assert.equal(body.findings, 0);
    assert.equal(body.running, false);
    assert.equal(body.audit.ok, true);
  } finally {
    await service.close();
  }
});

test('the chat endpoint answers a command', async () => {
  const { service, url } = await startServer();

  try {
    const response = await fetch(`${url}/api/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'help' }),
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.match(body.reply, /Gravion Harness — commands/);
    assert.equal(body.running, false);
  } finally {
    await service.close();
  }
});

test('the chat endpoint refuses an empty message', async () => {
  const { service, url } = await startServer();

  try {
    const response = await fetch(`${url}/api/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: '   ' }),
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error, 'message is required');
  } finally {
    await service.close();
  }
});

test('the chat endpoint reports an invalid JSON body', async () => {
  const { service, url } = await startServer();

  try {
    const response = await fetch(`${url}/api/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{ not json',
    });
    const body = await response.json();

    assert.equal(response.status, 500);
    assert.match(body.error, /invalid JSON body/);
  } finally {
    await service.close();
  }
});

test('the approval endpoint refuses an unknown decision', async () => {
  const { service, url } = await startServer();

  try {
    const response = await fetch(`${url}/api/approval`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ decision: 'maybe' }),
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error, 'decision must be approve or deny');
  } finally {
    await service.close();
  }
});

test('the approval endpoint reports that nothing was pending', async () => {
  const { service, url } = await startServer();

  try {
    const response = await fetch(`${url}/api/approval`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ decision: 'approve' }),
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.answered, false);
    assert.equal(body.pendingApproval, null);
  } finally {
    await service.close();
  }
});

test('the findings endpoint lists the collected findings', async () => {
  const { service, url } = await startServer();

  try {
    const before = await (await fetch(`${url}/api/findings`)).json();
    assert.deepEqual(before.findings, []);

    await fetch(`${url}/api/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'run review the target' }),
    });
    await service.router.state.runPromise;

    const after = await (await fetch(`${url}/api/findings`)).json();
    assert.equal(after.findings.length, 1);
    assert.equal(after.findings[0].title, 'Missing X-Frame-Options header');
  } finally {
    await service.close();
  }
});

test('the report endpoint serves the markdown report', async () => {
  const { service, url } = await startServer();

  try {
    const missing = await fetch(`${url}/api/report`);
    assert.equal(missing.status, 404);

    await fetch(`${url}/api/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'run review the target' }),
    });
    await service.router.state.runPromise;

    const response = await fetch(`${url}/api/report`);
    const body = await response.text();

    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type'), /text\/markdown/);
    assert.equal(body, '# Example engagement');
  } finally {
    await service.close();
  }
});

test('an unknown path is reported as not found', async () => {
  const { service, url } = await startServer();

  try {
    const response = await fetch(`${url}/api/nope`);
    const body = await response.json();

    assert.equal(response.status, 404);
    assert.equal(body.error, 'not found');
  } finally {
    await service.close();
  }
});

test('the web root can be pointed at a different directory', async () => {
  const service = createServer(fakeHarness(), { webRoot: path.join(__dirname, '..', 'web') });
  const { url } = await service.listen(0, '127.0.0.1');

  try {
    const response = await fetch(`${url}/index.html`);
    assert.equal(response.status, 200);
  } finally {
    await service.close();
  }
});
