'use strict';

/**
 * Provider registry.
 *
 * A provider turns an objective and a scope into a plan. The harness itself
 * does not care which provider produced the plan, so an operator can switch
 * between an offline run, a local model and a hosted API without changing
 * anything else.
 */

const deterministic = require('./deterministic');
const { OpenAIProvider } = require('./openai');
const { AnthropicProvider } = require('./anthropic');

const PROVIDERS = Object.freeze({
  deterministic,
  openai: OpenAIProvider,
  anthropic: AnthropicProvider,
});

/**
 * Lists the available provider names.
 *
 * @returns {string[]}
 */
function listProviders() {
  return Object.keys(PROVIDERS);
}

/**
 * Creates a provider from a configuration object.
 *
 * A ready-made provider may be passed straight through, so an operator (or a
 * test) can supply their own implementation without registering it first.
 *
 * @param {object|string} [config]
 * @returns {{type: string, propose: Function}}
 */
function createProvider(config = {}) {
  if (config && typeof config === 'object' && typeof config.propose === 'function') {
    return config;
  }

  const settings = typeof config === 'string' ? { type: config } : (config || {});
  const type = String(settings.type || process.env.GRAVION_HARNESS_PROVIDER || 'deterministic').toLowerCase();

  if (type === 'deterministic' || type === 'offline' || type === 'local') {
    return { type: 'deterministic', ...deterministic };
  }

  if (type === 'openai' || type === 'openai-compatible' || type === 'ollama' || type === 'local-api') {
    const provider = new OpenAIProvider(settings);
    return { type: provider.type, propose: (request) => provider.propose(request), model: provider.model };
  }

  if (type === 'anthropic' || type === 'claude') {
    const provider = new AnthropicProvider(settings);
    return { type: provider.type, propose: (request) => provider.propose(request), model: provider.model };
  }

  throw new Error(`unknown provider: ${type}. Known providers: ${listProviders().join(', ')}`);
}

module.exports = {
  PROVIDERS,
  AnthropicProvider,
  OpenAIProvider,
  createProvider,
  deterministic,
  listProviders,
};
