'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createProvider, listProviders } = require('../src/providers');
const { buildPrompt, extractJson, normalizePlan, normalizeStep } = require('../src/providers/plan');
const { OpenAIProvider } = require('../src/providers/openai');
const { AnthropicProvider } = require('../src/providers/anthropic');

test('the registry lists the available providers', () => {
  const providers = listProviders();

  assert.ok(providers.includes('deterministic'));
  assert.ok(providers.includes('openai'));
  assert.ok(providers.includes('anthropic'));
});

test('an unknown provider is reported rather than silently replaced', () => {
  assert.throws(() => createProvider('not-a-provider'), /unknown provider/);
});

test('the offline provider needs no key and no network', async () => {
  const provider = createProvider('deterministic');

  const result = await provider.propose({
    objective: 'review the target',
    scope: { allow: [{ type: 'url', value: 'https://example.com/' }], deny: [] },
  });

  assert.ok(result.steps.length > 0);
  assert.equal(result.provider, 'deterministic');
  assert.equal(result.model, 'offline');
  assert.equal(result.steps[0].kind, 'http');
  assert.equal(result.steps[0].target.value, 'https://example.com/');
});

test('the offline provider proposes a TLS step for an HTTPS target', async () => {
  const provider = createProvider('deterministic');

  const result = await provider.propose({
    scope: { allow: [{ type: 'url', value: 'https://example.com/' }] },
  });

  assert.ok(result.steps.some((step) => step.kind === 'tls'));
});

test('the prompt names the allowed and the denied targets', () => {
  const prompt = buildPrompt({
    objective: 'find misconfigurations',
    scope: {
      allow: [{ type: 'host', value: 'example.com', note: 'programme' }],
      deny: [{ type: 'host', value: 'admin.example.com' }],
    },
  });

  assert.match(prompt, /find misconfigurations/);
  assert.match(prompt, /host: example\.com \(programme\)/);
  assert.match(prompt, /host: admin\.example\.com/);
  assert.match(prompt, /JSON only/);
});

test('a JSON plan is extracted from a reply that wraps it in prose', () => {
  const parsed = extractJson('Here is the plan:\n```json\n{"steps":[{"id":"a"}]}\n```\nHope that helps.');

  assert.ok(parsed);
  assert.equal(parsed.steps.length, 1);
});

test('a JSON plan is extracted from a bare reply', () => {
  const parsed = extractJson('{"steps":[]}');

  assert.ok(parsed);
  assert.deepEqual(parsed.steps, []);
});

test('a reply without JSON is reported as no plan', () => {
  assert.equal(extractJson('I cannot help with that.'), null);
  assert.equal(extractJson(''), null);
  assert.equal(extractJson(null), null);
});

test('a malformed step is dropped instead of failing the whole plan', () => {
  const steps = normalizePlan({
    steps: [
      { id: 'good', kind: 'http', target: { type: 'url', value: 'https://example.com/' } },
      { id: 'no-target', kind: 'http' },
      { id: 'bad-kind', kind: 'teleport', target: { type: 'url', value: 'https://example.com/' } },
      { id: 'bad-target-type', kind: 'http', target: { type: 'planet', value: 'x' } },
      { id: 'command-without-tool', kind: 'command', target: { type: 'host', value: 'example.com' } },
    ],
  });

  assert.equal(steps.length, 1);
  assert.equal(steps[0].id, 'good');
});

test('an unknown check name is removed from a step', () => {
  const step = normalizeStep({
    kind: 'http',
    target: { type: 'url', value: 'https://example.com/' },
    check: ['security_headers', 'made_up_check'],
  });

  assert.deepEqual(step.check, ['security_headers']);
});

test('the method of an HTTP step is normalised and restricted', () => {
  assert.equal(normalizeStep({ kind: 'http', target: { type: 'url', value: 'https://a/' }, method: 'get' }).method, 'GET');
  assert.equal(normalizeStep({ kind: 'http', target: { type: 'url', value: 'https://a/' }, method: 'TRACE' }).method, 'GET');
});

test('the OpenAI-compatible provider posts to the configured base URL', async () => {
  const calls = [];
  const provider = new OpenAIProvider({
    apiKey: 'test-key',
    baseUrl: 'http://127.0.0.1:11434/v1',
    model: 'llama3',
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return {
        ok: true,
        status: 200,
        json: async () => ({
          choices: [{ message: { content: '{"steps":[{"id":"a","kind":"http","target":{"type":"url","value":"https://example.com/"}}]}' } }],
        }),
      };
    },
  });

  const result = await provider.propose({ objective: 'test', scope: { allow: [] } });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'http://127.0.0.1:11434/v1/chat/completions');
  assert.equal(calls[0].options.headers.authorization, 'Bearer test-key');
  assert.equal(JSON.parse(calls[0].options.body).model, 'llama3');
  assert.equal(result.steps.length, 1);
  assert.equal(result.error, null);
});

test('the OpenAI-compatible provider reports an HTTP error', async () => {
  const provider = new OpenAIProvider({
    apiKey: 'k',
    fetchImpl: async () => ({ ok: false, status: 401, text: async () => 'unauthorized' }),
  });

  const result = await provider.propose({ objective: 'test', scope: { allow: [] } });

  assert.equal(result.steps.length, 0);
  assert.match(result.error, /HTTP 401/);
});

test('the OpenAI-compatible provider reports a reply without a plan', async () => {
  const provider = new OpenAIProvider({
    apiKey: 'k',
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ choices: [{ message: { content: 'I refuse.' } }] }),
    }),
  });

  const result = await provider.propose({ objective: 'test', scope: { allow: [] } });

  assert.equal(result.steps.length, 0);
  assert.match(result.error, /did not contain a JSON plan/);
});

test('the Anthropic provider posts to the messages API', async () => {
  const calls = [];
  const provider = new AnthropicProvider({
    apiKey: 'test-key',
    model: 'claude-test',
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return {
        ok: true,
        status: 200,
        json: async () => ({
          content: [{ type: 'text', text: '{"steps":[{"id":"a","kind":"http","target":{"type":"url","value":"https://example.com/"}}]}' }],
        }),
      };
    },
  });

  const result = await provider.propose({ objective: 'test', scope: { allow: [] } });

  assert.equal(calls[0].url, 'https://api.anthropic.com/v1/messages');
  assert.equal(calls[0].options.headers['x-api-key'], 'test-key');
  assert.equal(calls[0].options.headers['anthropic-version'], '2023-06-01');
  assert.equal(result.steps.length, 1);
});

test('a provider failure never throws out of propose', async () => {
  const provider = new OpenAIProvider({
    apiKey: 'k',
    fetchImpl: async () => {
      throw new Error('connection refused');
    },
  });

  const result = await provider.propose({ objective: 'test', scope: { allow: [] } });

  assert.equal(result.steps.length, 0);
  assert.match(result.error, /connection refused/);
});
