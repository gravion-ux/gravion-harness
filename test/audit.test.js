'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { AuditLog, GENESIS } = require('../src/audit');

async function scratch() {
  return fs.mkdtemp(path.join(os.tmpdir(), 'gravion-audit-'));
}

test('records are appended with a sequence number and a timestamp', async () => {
  const log = new AuditLog({ clock: () => new Date('2026-01-01T00:00:00.000Z') });

  const first = await log.append({ event: 'plan', action: 'objective' });
  const second = await log.append({ event: 'execute', action: 'step' });

  assert.equal(first.seq, 1);
  assert.equal(second.seq, 2);
  assert.equal(first.ts, '2026-01-01T00:00:00.000Z');
  assert.equal(first.prev, GENESIS);
  assert.equal(second.prev, first.hash);
});

test('the log is written as one JSON record per line', async () => {
  const directory = await scratch();
  const file = path.join(directory, 'audit.jsonl');
  const log = new AuditLog({ path: file });

  await log.append({ event: 'plan', action: 'one' });
  await log.append({ event: 'execute', action: 'two' });

  const raw = await fs.readFile(file, 'utf8');
  const lines = raw.trim().split('\n');

  assert.equal(lines.length, 2);
  assert.equal(JSON.parse(lines[0]).event, 'plan');
  assert.equal(JSON.parse(lines[1]).event, 'execute');

  await fs.rm(directory, { recursive: true, force: true });
});

test('the chain verifies for an untouched log', async () => {
  const directory = await scratch();
  const file = path.join(directory, 'audit.jsonl');
  const log = new AuditLog({ path: file });

  await log.append({ event: 'plan', action: 'one' });
  await log.append({ event: 'execute', action: 'two' });
  await log.append({ event: 'execute', action: 'three' });

  const verification = await log.verify();

  assert.equal(verification.ok, true);
  assert.equal(verification.entries, 3);
  assert.equal(verification.brokenAt, null);

  await fs.rm(directory, { recursive: true, force: true });
});

test('an edited record breaks the chain', async () => {
  const directory = await scratch();
  const file = path.join(directory, 'audit.jsonl');
  const log = new AuditLog({ path: file });

  await log.append({ event: 'plan', action: 'one' });
  await log.append({ event: 'execute', action: 'two' });

  const raw = await fs.readFile(file, 'utf8');
  const records = raw.trim().split('\n');
  const tampered = JSON.parse(records[1]);
  tampered.action = 'something else';
  records[1] = JSON.stringify(tampered);
  await fs.writeFile(file, `${records.join('\n')}\n`, 'utf8');

  const verification = await log.verify();

  assert.equal(verification.ok, false);
  assert.equal(verification.brokenAt, 2);
  assert.match(verification.reason, /hash does not match/);

  await fs.rm(directory, { recursive: true, force: true });
});

test('a removed record breaks the chain', async () => {
  const directory = await scratch();
  const file = path.join(directory, 'audit.jsonl');
  const log = new AuditLog({ path: file });

  await log.append({ event: 'plan', action: 'one' });
  await log.append({ event: 'execute', action: 'two' });
  await log.append({ event: 'execute', action: 'three' });

  const raw = await fs.readFile(file, 'utf8');
  const records = raw.trim().split('\n');
  records.splice(1, 1);
  await fs.writeFile(file, `${records.join('\n')}\n`, 'utf8');

  const verification = await log.verify();

  assert.equal(verification.ok, false);
  assert.equal(verification.brokenAt, 2);
  assert.match(verification.reason, /previous-record hash/);

  await fs.rm(directory, { recursive: true, force: true });
});

test('a corrupted line is reported rather than skipped', async () => {
  const directory = await scratch();
  const file = path.join(directory, 'audit.jsonl');
  const log = new AuditLog({ path: file });

  await log.append({ event: 'plan', action: 'one' });
  await fs.appendFile(file, 'this is not json\n', 'utf8');

  const verification = await log.verify();

  assert.equal(verification.ok, false);
  assert.match(verification.reason, /not valid JSON/);

  await fs.rm(directory, { recursive: true, force: true });
});

test('secrets never reach the log', async () => {
  const log = new AuditLog();

  const record = await log.append({
    event: 'execute',
    action: 'request',
    meta: {
      authorization: 'Basic dXNlcjpwYXNz',
      api_key: 'abcdef1234567890',
      nested: { password: 'hunter2hunter2' },
      list: ['sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAA'],
    },
  });

  const serialized = JSON.stringify(record);
  assert.doesNotMatch(serialized, /dXNlcjpwYXNz/);
  assert.doesNotMatch(serialized, /abcdef1234567890/);
  assert.doesNotMatch(serialized, /hunter2hunter2/);
  assert.doesNotMatch(serialized, /sk-ant-api03/);
  assert.match(serialized, /REDACTED/);
});

test('a missing log file reads as an empty log', async () => {
  const directory = await scratch();
  const log = new AuditLog({ path: path.join(directory, 'nothing.jsonl') });

  assert.deepEqual(await log.read(), []);
  assert.equal((await log.verify()).ok, true);
  assert.equal((await log.verify()).entries, 0);

  await fs.rm(directory, { recursive: true, force: true });
});
