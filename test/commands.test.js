'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { ApprovalBroker, createCommandRouter, parseCommand } = require('../src/commands');
const { AccessController } = require('../src/access');
const { AuditLog } = require('../src/audit');
const { buildReport } = require('../src/report');
const { createFinding } = require('../src/findings');

/**
 * Builds a harness double with the surface the command router uses.
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
    plan: async () => ({
      steps: [
        { id: 'a', title: 'read the page', kind: 'http', risk: 'low', target: { type: 'url', value: 'https://example.com/' } },
      ],
      blocked: [],
      provider: 'deterministic',
      model: 'offline',
      error: null,
    }),
    run: async () => ({
      findings: [finding],
      markdown: '# Example engagement',
      report: buildReport({
        name: 'Example engagement',
        objective: 'review the target',
        actionsRun: 2,
        actionsBlocked: 1,
        auditEntries: 3,
        auditVerified: true,
        findings: [finding],
      }),
    }),
    ...overrides,
  };
}

test('a command line is split into a name and an argument', () => {
  assert.deepEqual(parseCommand('run review the target'), {
    name: 'run',
    argument: 'review the target',
  });
  assert.deepEqual(parseCommand('  STATUS  '), { name: 'status', argument: '' });
  assert.deepEqual(parseCommand(''), { name: '', argument: '' });
  assert.deepEqual(parseCommand(null), { name: '', argument: '' });
});

test('an approval request can be described and answered', async () => {
  const broker = new ApprovalBroker();
  const action = {
    id: 'a',
    title: 'delete the staging database',
    kind: 'command',
    risk: 'critical',
    riskReason: 'the command looks destructive (recursive delete)',
    target: { type: 'host', value: 'staging.example.com' },
  };

  const pending = broker.request(action);
  const described = broker.describe();

  assert.equal(described.id, 'a');
  assert.equal(described.risk, 'critical');
  assert.equal(described.target.value, 'staging.example.com');

  assert.equal(broker.approve('priya'), true);
  assert.deepEqual(await pending, { approved: true, approver: 'priya' });
  assert.equal(broker.describe(), null);
});

test('a denied approval resolves the request with a refusal', async () => {
  const broker = new ApprovalBroker();
  const pending = broker.request({ id: 'b', title: 'write a file' });

  assert.equal(broker.deny(), true);
  assert.deepEqual(await pending, { approved: false, approver: 'operator' });
});

test('answering when nothing is pending reports that nothing was answered', () => {
  const broker = new ApprovalBroker();

  assert.equal(broker.approve(), false);
  assert.equal(broker.deny(), false);
  assert.equal(broker.describe(), null);
});

test('the help command lists the available commands', async () => {
  const router = createCommandRouter(fakeHarness());
  const result = await router.handle('help');

  assert.match(result.reply, /Gravion Harness — commands/);
  assert.match(result.reply, /mode ask\|smart\|full/);
});

test('an unknown command is reported instead of being ignored', async () => {
  const router = createCommandRouter(fakeHarness());
  const result = await router.handle('nonsense');

  assert.match(result.reply, /Unknown command "nonsense"/);
});

test('an empty command line produces no reply', async () => {
  const router = createCommandRouter(fakeHarness());
  const result = await router.handle('   ');

  assert.equal(result.reply, '');
});

test('the access mode can be changed and an unknown mode is refused', async () => {
  const harness = fakeHarness();
  const router = createCommandRouter(harness);

  const changed = await router.handle('mode full');
  assert.equal(harness.access.mode, 'full');
  assert.match(changed.reply, /access mode is now full/);

  const refused = await router.handle('mode nonsense');
  assert.match(refused.reply, /unknown mode/);
  assert.equal(harness.access.mode, 'full');
});

test('the status command reports the mode, targets and audit state', async () => {
  const router = createCommandRouter(fakeHarness());
  const result = await router.handle('status');

  assert.match(result.reply, /access mode: smart/);
  assert.match(result.reply, /targets: 1/);
  assert.match(result.reply, /pending approval: none/);
  assert.equal(result.data.mode, 'smart');
});

test('the targets command lists the loaded targets', async () => {
  const router = createCommandRouter(fakeHarness());
  const result = await router.handle('targets');

  assert.match(result.reply, /url: https:\/\/example\.com\/ \(example\)/);
  assert.equal(result.data.targets.length, 1);
});

test('the targets command says so when nothing is loaded', async () => {
  const router = createCommandRouter(fakeHarness({ targets: [] }));
  const result = await router.handle('targets');

  assert.match(result.reply, /No targets are loaded/);
});

test('the plan command shows the proposed steps and their risk', async () => {
  const router = createCommandRouter(fakeHarness());
  const result = await router.handle('plan review the target');

  assert.match(result.reply, /Plan from deterministic/);
  assert.match(result.reply, /1\. \[low\] read the page/);
});

test('the plan command without an objective shows the usage', async () => {
  const router = createCommandRouter(fakeHarness());
  const result = await router.handle('plan');

  assert.match(result.reply, /Usage: plan <objective>/);
});

test('a run collects the findings and the results command reports them', async () => {
  const router = createCommandRouter(fakeHarness());

  const started = await router.handle('run review the target');
  assert.match(started.reply, /Engagement started/);

  await router.state.runPromise;

  const results = await router.handle('results');
  assert.match(results.reply, /Engagement finished\. 1 finding\(s\)\./);
  assert.match(results.reply, /2 action\(s\) ran, 1 were blocked/);

  const findings = await router.handle('findings');
  assert.match(findings.reply, /\[low\] Missing X-Frame-Options header/);
});

test('the results command says so before an engagement has run', async () => {
  const router = createCommandRouter(fakeHarness());
  const result = await router.handle('results');

  assert.match(result.reply, /no result yet/i);
});

test('the findings command says so when nothing has been collected', async () => {
  const router = createCommandRouter(fakeHarness());
  const result = await router.handle('findings');

  assert.match(result.reply, /No findings have been collected yet/);
});

test('a failed engagement is reported rather than thrown', async () => {
  const router = createCommandRouter(fakeHarness({
    run: async () => {
      throw new Error('the provider is unreachable');
    },
  }));

  await router.handle('run review the target');
  await router.state.runPromise.catch(() => {});

  const result = await router.handle('results');
  assert.match(result.reply, /The engagement failed: the provider is unreachable/);
});

test('the report command writes the markdown report to disk', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'gravion-report-'));
  const target = path.join(directory, 'report.md');

  const router = createCommandRouter(fakeHarness());
  await router.handle('run review the target');
  await router.state.runPromise;

  const result = await router.handle(`report ${target}`);
  assert.match(result.reply, /Report written to/);

  const written = await fs.readFile(target, 'utf8');
  assert.equal(written, '# Example engagement');

  await fs.rm(directory, { recursive: true, force: true });
});

test('the report command says so before an engagement has run', async () => {
  const router = createCommandRouter(fakeHarness());
  const result = await router.handle('report');

  assert.match(result.reply, /no report yet/i);
});

test('the audit command verifies the chain', async () => {
  const router = createCommandRouter(fakeHarness());
  const result = await router.handle('audit');

  assert.match(result.reply, /Audit chain is intact/);
  assert.equal(result.data.ok, true);
});

test('a pending approval is answered from the same command language', async () => {
  const harness = fakeHarness({
    access: new AccessController({ mode: 'ask' }),
    run: async () => {
      // In `ask` mode the controller asks the broker, which the router has
      // already bound to the operator's `approve` command.
      const decision = await harness.access.authorize({
        id: 'a',
        title: 'delete the staging database',
        kind: 'command',
        risk: 'critical',
        target: { type: 'host', value: 'staging.example.com' },
      });
      return {
        findings: [],
        markdown: '# Example engagement',
        report: buildReport({ name: 'Example engagement', auditVerified: true }),
        decision,
      };
    },
  });

  const router = createCommandRouter(harness);

  await router.handle('run review the target');
  await new Promise((resolve) => setTimeout(resolve, 20));

  const pending = router.broker.describe();
  assert.ok(pending, 'the run should have parked an approval request');
  assert.equal(pending.risk, 'critical');

  const approved = await router.handle('approve');
  assert.match(approved.reply, /Approved\./);

  await router.state.runPromise;
  assert.equal(router.state.lastReport.engagement.name, 'Example engagement');
});

test('approving when nothing is pending is reported plainly', async () => {
  const router = createCommandRouter(fakeHarness());

  const approved = await router.handle('approve');
  assert.match(approved.reply, /no pending approval request/i);

  const denied = await router.handle('deny');
  assert.match(denied.reply, /no pending approval request/i);
});

test('the clear command forgets the collected findings', async () => {
  const router = createCommandRouter(fakeHarness());

  await router.handle('run review the target');
  await router.state.runPromise;
  assert.equal(router.state.findings.length, 1);

  const cleared = await router.handle('clear');
  assert.match(cleared.reply, /Cleared\./);
  assert.equal(router.state.findings.length, 0);
  assert.equal(router.state.lastMarkdown, null);
});

test('quit asks the caller to leave', async () => {
  const router = createCommandRouter(fakeHarness());
  const result = await router.handle('quit');

  assert.match(result.reply, /Goodbye\./);
  assert.equal(result.data.quit, true);
});
