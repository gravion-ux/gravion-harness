'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { AccessController, normalizeMode } = require('../src/access');
const { ApprovalPolicy } = require('../src/approval');

function action(overrides = {}) {
  return {
    id: 'step-1',
    kind: 'http',
    risk: 'low',
    tool: '',
    target: { type: 'url', value: 'https://example.com/' },
    ...overrides,
  };
}

test('the three access modes are recognised and unknown modes fall back to smart', () => {
  assert.equal(normalizeMode('ask'), 'ask');
  assert.equal(normalizeMode('SMART'), 'smart');
  assert.equal(normalizeMode('full'), 'full');
  assert.equal(normalizeMode('nonsense'), 'smart');
  assert.equal(normalizeMode(undefined), 'smart');
});

test('ask mode requires an approval for every action', async () => {
  const controller = new AccessController({ mode: 'ask', requestApproval: async () => true });

  for (const risk of ['safe', 'low', 'medium', 'high', 'critical']) {
    const decision = await controller.authorize(action({ risk }));
    assert.equal(decision.decision, 'ask', `${risk} should have been escalated`);
    assert.equal(decision.approved, true);
  }
});

test('ask mode fails closed when there is nobody to ask', async () => {
  const controller = new AccessController({ mode: 'ask' });

  const decision = await controller.authorize(action({ risk: 'safe' }));

  assert.equal(decision.approved, false);
  assert.match(decision.reason, /no approver/);
});

test('smart mode runs safe and low risk work on its own', async () => {
  const controller = new AccessController({ mode: 'smart' });

  assert.equal((await controller.authorize(action({ risk: 'safe' }))).approved, true);
  assert.equal((await controller.authorize(action({ risk: 'low' }))).approved, true);
});

test('smart mode escalates medium and higher risk work', async () => {
  const controller = new AccessController({ mode: 'smart', requestApproval: async () => true });

  const decision = await controller.authorize(action({ risk: 'medium' }));
  assert.equal(decision.decision, 'ask');
  assert.equal(decision.approved, true);

  const denied = await controller.authorize(action({ risk: 'high' }));
  assert.equal(denied.decision, 'ask');
});

test('full mode runs everything without escalating', async () => {
  const controller = new AccessController({ mode: 'full' });

  for (const risk of ['safe', 'low', 'medium', 'high', 'critical']) {
    const decision = await controller.authorize(action({ risk }));
    assert.equal(decision.approved, true, `${risk} should have run in full mode`);
    assert.equal(decision.decision, 'auto');
  }
});

test('a deny rule wins in every mode, including full access', async () => {
  const policy = new ApprovalPolicy({
    default: 'ask',
    rules: [{ match: { kind: 'command' }, decision: 'deny', reason: 'no local commands' }],
  });

  for (const mode of ['ask', 'smart', 'full']) {
    const controller = new AccessController({ mode, policy });
    const decision = await controller.authorize(action({ kind: 'command', risk: 'safe' }));

    assert.equal(decision.approved, false, `${mode} mode should have denied the command`);
    assert.equal(decision.decision, 'deny');
    assert.match(decision.reason, /no local commands/);
  }
});

test('a policy tier can clear an action that the mode would have escalated', async () => {
  const policy = new ApprovalPolicy({ default: 'ask', tiers: { medium: 'auto' } });
  const controller = new AccessController({ mode: 'smart', policy });

  const decision = await controller.authorize(action({ risk: 'medium' }));

  assert.equal(decision.approved, true);
  assert.equal(decision.decision, 'auto');
});

test('the first matching policy rule wins', () => {
  const policy = new ApprovalPolicy({
    default: 'ask',
    rules: [
      { match: { kind: 'http' }, decision: 'deny', reason: 'no http' },
      { match: { kind: '*' }, decision: 'auto', reason: 'everything else' },
    ],
  });

  assert.equal(policy.evaluate(action({ kind: 'http' })).decision, 'deny');
  assert.equal(policy.evaluate(action({ kind: 'dns' })).decision, 'auto');
});

test('a rule clause only matches the values it lists', () => {
  const policy = new ApprovalPolicy({
    default: 'ask',
    rules: [
      { match: { kind: 'http', risk: ['high', 'critical'] }, decision: 'deny', reason: 'risky http' },
    ],
  });

  assert.equal(policy.evaluate(action({ kind: 'http', risk: 'high' })).decision, 'deny');
  assert.equal(policy.evaluate(action({ kind: 'http', risk: 'low' })).decision, 'ask');
  assert.equal(policy.evaluate(action({ kind: 'tls', risk: 'high' })).decision, 'ask');
});

test('an unknown risk tier is treated conservatively', () => {
  const policy = new ApprovalPolicy({ default: 'auto' });

  assert.equal(policy.evaluate(action({ risk: 'wat' })).tier, 'high');
});

test('an invalid policy is rejected when it is built', () => {
  assert.throws(() => new ApprovalPolicy({ default: 'maybe' }), /unknown default decision/);
  assert.throws(() => new ApprovalPolicy({ rules: [{ decision: 'perhaps' }] }), /unknown decision/);
  assert.throws(() => new ApprovalPolicy({ tiers: { safe: 'sometimes' } }), /unknown decision for tier/);
});

test('a policy can be loaded from a file', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'gravion-policy-'));
  const file = path.join(directory, 'policy.json');
  await fs.writeFile(file, JSON.stringify({ default: 'deny', tiers: { safe: 'auto' } }), 'utf8');

  const policy = ApprovalPolicy.fromFile(file);

  assert.equal(policy.defaultDecision, 'deny');
  assert.equal(policy.evaluate(action({ risk: 'safe' })).decision, 'auto');
  assert.equal(policy.evaluate(action({ risk: 'low' })).decision, 'deny');

  await fs.rm(directory, { recursive: true, force: true });
});
