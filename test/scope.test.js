'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { Scope, cidrContains, hostMatches, ipv4ToInt, parseCidr } = require('../src/scope');

test('host matching is exact, case-insensitive and wildcard aware', () => {
  assert.equal(hostMatches('example.com', 'example.com'), true);
  assert.equal(hostMatches('EXAMPLE.com', 'example.com'), true);
  assert.equal(hostMatches('example.com', 'evil.com'), false);
  assert.equal(hostMatches('*.example.com', 'api.example.com'), true);
  assert.equal(hostMatches('*.example.com', 'a.b.example.com'), true);
  assert.equal(hostMatches('*.example.com', 'example.com'), false);
  assert.equal(hostMatches('*.example.com', 'notexample.com'), false);
});

test('CIDR parsing and containment work for IPv4', () => {
  assert.equal(ipv4ToInt('192.168.1.1'), 3232235777);
  assert.equal(ipv4ToInt('999.1.1.1'), null);
  assert.equal(ipv4ToInt('1.2.3'), null);
  assert.deepEqual(parseCidr('10.0.0.0/8'), { base: 167772160, bits: 8 });
  assert.equal(parseCidr('10.0.0.0/33'), null);
  assert.equal(cidrContains('10.0.0.0/8', '10.1.2.3'), true);
  assert.equal(cidrContains('10.0.0.0/8', '11.1.2.3'), false);
  assert.equal(cidrContains('192.168.1.0/24', '192.168.1.255'), true);
  assert.equal(cidrContains('192.168.1.0/24', '192.168.2.1'), false);
  assert.equal(cidrContains('0.0.0.0/0', '8.8.8.8'), true);
});

test('a target with no matching allow rule is denied', () => {
  const scope = new Scope({ allow: [{ type: 'host', value: 'example.com' }] });

  assert.equal(scope.isAllowed({ type: 'host', value: 'example.com' }), true);
  assert.equal(scope.isAllowed({ type: 'host', value: 'evil.com' }), false);
  assert.equal(scope.isAllowed({ type: 'ip', value: '10.0.0.1' }), false);
});

test('a deny rule wins over an allow rule', () => {
  const scope = new Scope({
    allow: [{ type: 'host', value: 'example.com' }],
    deny: [{ type: 'host', value: 'admin.example.com' }],
  });

  assert.equal(scope.isAllowed({ type: 'host', value: 'example.com' }), true);
  assert.equal(scope.isAllowed({ type: 'host', value: 'admin.example.com' }), false);

  const explanation = scope.explain({ type: 'host', value: 'admin.example.com' });
  assert.match(explanation.reason, /deny rule/);
});

test('a URL is constrained by scheme and by port', () => {
  const scope = new Scope({
    allow: [{ type: 'host', value: 'example.com' }],
    allowedSchemes: ['https'],
    allowedPorts: [443],
  });

  assert.equal(scope.isAllowed({ type: 'url', value: 'https://example.com/' }), true);
  assert.equal(scope.isAllowed({ type: 'url', value: 'http://example.com/' }), false);
  assert.equal(scope.isAllowed({ type: 'url', value: 'https://example.com:8443/' }), false);
});

test('a URL rule matches the scheme, host, port and path prefix', () => {
  const scope = new Scope({
    allow: [{ type: 'url', value: 'https://example.com/api/' }],
  });

  assert.equal(scope.isAllowed({ type: 'url', value: 'https://example.com/api/users' }), true);
  assert.equal(scope.isAllowed({ type: 'url', value: 'https://example.com/other' }), false);
  assert.equal(scope.isAllowed({ type: 'url', value: 'http://example.com/api/' }), false);
  assert.equal(scope.isAllowed({ type: 'url', value: 'https://evil.com/api/' }), false);
});

test('a path rule only accepts paths under its root', () => {
  const scope = new Scope({ allow: [{ type: 'path', value: '/srv/lab' }] });

  assert.equal(scope.isAllowed({ type: 'path', value: '/srv/lab/app' }), true);
  assert.equal(scope.isAllowed({ type: 'path', value: '/srv/lab' }), false);
  assert.equal(scope.isAllowed({ type: 'path', value: '/srv/other/app' }), false);
  assert.equal(scope.isAllowed({ type: 'path', value: '/srv/lab/../secret' }), false);
});

test('an invalid rule is rejected when the scope is built', () => {
  assert.throws(() => new Scope({ allow: [{ type: 'nonsense', value: 'x' }] }), /unknown scope rule type/);
  assert.throws(() => new Scope({ allow: [{ type: 'host' }] }), /needs a value/);
  assert.throws(() => new Scope({ allow: [{ type: 'cidr', value: '999.0.0.0/8' }] }), /invalid CIDR/);
  assert.throws(() => new Scope({ allow: [{ type: 'url', value: 'not a url' }] }), /invalid URL/);
});

test('the scope can be serialised for a model provider', () => {
  const scope = new Scope({
    description: 'example engagement',
    allow: [{ type: 'host', value: 'example.com', note: 'programme' }],
    deny: [{ type: 'host', value: 'admin.example.com' }],
  });

  const spec = scope.toSpec();

  assert.equal(spec.description, 'example engagement');
  assert.deepEqual(spec.allow, [{ type: 'host', value: 'example.com', note: 'programme' }]);
  assert.deepEqual(spec.deny, [{ type: 'host', value: 'admin.example.com', note: '' }]);
});

test('a malformed target is denied rather than throwing', () => {
  const scope = new Scope({ allow: [{ type: 'host', value: 'example.com' }] });

  assert.equal(scope.isAllowed(null), false);
  assert.equal(scope.isAllowed({}), false);
  assert.equal(scope.isAllowed({ type: 'host' }), false);
});
