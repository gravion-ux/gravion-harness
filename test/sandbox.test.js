'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { Sandbox, SandboxError } = require('../src/sandbox');

async function scratch() {
  return fs.mkdtemp(path.join(os.tmpdir(), 'gravion-sandbox-'));
}

test('a command that is not allowlisted is refused', async () => {
  const root = await scratch();
  const sandbox = new Sandbox({ root, allowedCommands: ['node'] });

  await assert.rejects(
    () => sandbox.run('rm', ['-rf', '/']),
    (error) => error instanceof SandboxError && error.code === 'E_COMMAND_NOT_ALLOWED'
  );

  await fs.rm(root, { recursive: true, force: true });
});

test('an allowlisted command runs and its output is captured', async () => {
  const root = await scratch();
  const sandbox = new Sandbox({ root, allowedCommands: ['node'] });

  const result = await sandbox.run(process.execPath, ['-e', 'process.stdout.write("hello")']);

  assert.equal(result.ok, true);
  assert.equal(result.stdout, 'hello');
  assert.equal(result.code, 0);
  assert.ok(result.durationMs >= 0);

  await fs.rm(root, { recursive: true, force: true });
});

test('the allowlist matches the base name of a full path', () => {
  const sandbox = new Sandbox({ allowedCommands: ['curl', '/usr/bin/nmap'] });

  assert.equal(sandbox.isAllowedCommand('curl'), true);
  assert.equal(sandbox.isAllowedCommand('/usr/bin/nmap'), true);
  assert.equal(sandbox.isAllowedCommand('/opt/tools/nmap'), false);
  assert.equal(sandbox.isAllowedCommand('curl --version'), false);
  assert.equal(sandbox.isAllowedCommand(''), false);
});

test('the working directory cannot escape the sandbox root', async () => {
  const root = await scratch();
  const sandbox = new Sandbox({ root, allowedCommands: ['node'] });

  await assert.rejects(
    () => sandbox.run(process.execPath, ['-e', ''], { cwd: '../..' }),
    (error) => error instanceof SandboxError && error.code === 'E_CWD_OUTSIDE'
  );

  await fs.rm(root, { recursive: true, force: true });
});

test('shell metacharacters are passed as literal arguments', async () => {
  const root = await scratch();
  const sandbox = new Sandbox({ root, allowedCommands: ['node'] });

  const result = await sandbox.run(process.execPath, [
    '-e',
    'process.stdout.write(process.argv[1])',
    '; rm -rf / #',
  ]);

  assert.equal(result.stdout, '; rm -rf / #');

  await fs.rm(root, { recursive: true, force: true });
});

test('the environment is limited to the allowlisted variables', async () => {
  const root = await scratch();
  process.env.GRAVION_TEST_SECRET = 'do-not-leak';
  const sandbox = new Sandbox({ root, allowedCommands: ['node'] });

  const result = await sandbox.run(process.execPath, [
    '-e',
    'process.stdout.write(String(process.env.GRAVION_TEST_SECRET))',
  ]);

  assert.equal(result.stdout, 'undefined');
  delete process.env.GRAVION_TEST_SECRET;

  await fs.rm(root, { recursive: true, force: true });
});

test('an explicitly configured environment variable is passed through', async () => {
  const root = await scratch();
  const sandbox = new Sandbox({
    root,
    allowedCommands: ['node'],
    env: { GRAVION_TEST_ALLOWED: 'yes' },
  });

  const result = await sandbox.run(process.execPath, [
    '-e',
    'process.stdout.write(String(process.env.GRAVION_TEST_ALLOWED))',
  ]);

  assert.equal(result.stdout, 'yes');

  await fs.rm(root, { recursive: true, force: true });
});

test('a command that runs too long is killed and reported', async () => {
  const root = await scratch();
  const sandbox = new Sandbox({ root, allowedCommands: ['node'], timeoutMs: 300 });

  const result = await sandbox.run(process.execPath, ['-e', 'setTimeout(() => {}, 10000)']);

  assert.equal(result.ok, false);
  assert.match(result.error, /timed out/);

  await fs.rm(root, { recursive: true, force: true });
});

test('a failing command reports its exit code without throwing', async () => {
  const root = await scratch();
  const sandbox = new Sandbox({ root, allowedCommands: ['node'] });

  const result = await sandbox.run(process.execPath, ['-e', 'process.exit(3)']);

  assert.equal(result.ok, false);
  assert.equal(result.code, 3);

  await fs.rm(root, { recursive: true, force: true });
});
