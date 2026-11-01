'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const {
  buildScopeSpec,
  discoverHosts,
  expandCidr,
  expandTargets,
  inferType,
  loadTargetList,
  parseTargetList,
} = require('../src/targets');

test('the target type is inferred from the value', () => {
  assert.equal(inferType('https://example.com/api'), 'url');
  assert.equal(inferType('10.0.0.0/24'), 'cidr');
  assert.equal(inferType('10.0.0.1'), 'ip');
  assert.equal(inferType('example.com'), 'host');
  assert.equal(inferType('api.example.com'), 'host');
});

test('a target list is parsed from plain text', () => {
  const targets = parseTargetList([
    '# a comment',
    '',
    'https://app.example.com/',
    'api.example.com',
    '10.0.0.0/24',
  ].join('\n'));

  assert.equal(targets.length, 3);
  assert.equal(targets[0].type, 'url');
  assert.equal(targets[1].type, 'host');
  assert.equal(targets[2].type, 'cidr');
});

test('a target line can carry a programme and a note', () => {
  const targets = parseTargetList('example.com, program=hackerone, note=main site');

  assert.equal(targets[0].value, 'example.com');
  assert.equal(targets[0].program, 'hackerone');
  assert.equal(targets[0].note, 'main site');
});

test('a JSON object per line is accepted', () => {
  const targets = parseTargetList('{"url": "https://example.com/", "program": "example"}');

  assert.equal(targets.length, 1);
  assert.equal(targets[0].type, 'url');
  assert.equal(targets[0].value, 'https://example.com/');
  assert.equal(targets[0].program, 'example');
});

test('a CIDR block expands into individual addresses', () => {
  assert.deepEqual(expandCidr('10.0.0.0/30'), ['10.0.0.0', '10.0.0.1', '10.0.0.2', '10.0.0.3']);
  assert.deepEqual(expandCidr('not a cidr'), []);
});

test('a CIDR block that is too large is not expanded', () => {
  assert.deepEqual(expandCidr('10.0.0.0/8', 256), []);
});

test('expanding a list adds the host behind a URL and removes duplicates', () => {
  const targets = parseTargetList('https://app.example.com/\napp.example.com');

  const expanded = expandTargets(targets);
  const values = expanded.map((target) => `${target.type}:${target.value}`);

  assert.ok(values.includes('url:https://app.example.com/'));
  assert.ok(values.includes('host:app.example.com'));
  assert.equal(new Set(values).size, values.length);
});

test('the scope is derived from the target list', () => {
  const targets = parseTargetList('https://app.example.com/\napi.example.com');
  const spec = buildScopeSpec(targets);

  assert.equal(spec.allow.length, 2);
  assert.equal(spec.allow[0].type, 'url');
  assert.equal(spec.allow[1].type, 'host');
});

test('a JSON target file is loaded', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'gravion-targets-'));
  const file = path.join(directory, 'targets.json');
  await fs.writeFile(file, JSON.stringify([
    { url: 'https://example.com/', program: 'example' },
    'other.example.com',
  ]), 'utf8');

  const targets = loadTargetList(file);

  assert.equal(targets.length, 2);
  assert.equal(targets[0].value, 'https://example.com/');
  assert.equal(targets[0].program, 'example');
  assert.equal(targets[1].type, 'host');

  await fs.rm(directory, { recursive: true, force: true });
});

test('a malformed JSON target file reports the file name', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'gravion-targets-'));
  const file = path.join(directory, 'targets.json');
  await fs.writeFile(file, '{ not json', 'utf8');

  assert.throws(() => loadTargetList(file), /is not valid JSON/);

  await fs.rm(directory, { recursive: true, force: true });
});

test('discovery resolves candidate names and keeps only the ones that resolve', async () => {
  const resolver = {
    async resolve4(hostname) {
      if (hostname === 'api.example.com') {
        return ['203.0.113.10'];
      }
      throw new Error('NXDOMAIN');
    },
  };

  const discovered = await discoverHosts('example.com', ['api', 'missing', 'www'], { resolver });

  assert.equal(discovered.length, 1);
  assert.equal(discovered[0].value, 'api.example.com');
  assert.deepEqual(discovered[0].addresses, ['203.0.113.10']);
  assert.equal(discovered[0].source, 'discovery');
});

test('discovery refuses a candidate that is not a plain label', async () => {
  const resolver = { async resolve4() { return ['203.0.113.10']; } };

  const discovered = await discoverHosts('example.com', ['../evil', 'with space'], { resolver });

  assert.equal(discovered.length, 0);
});
