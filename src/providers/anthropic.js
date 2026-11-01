'use strict';

/**
 * Anthropic provider.
 *
 * Uses the Messages API. The API key is read from the environment
 * (`ANTHROPIC_API_KEY`) and is never written into a plan, a target or the
 * audit log.
 */

const { buildPrompt, extractJson, normalizePlan } = require('./plan');

const DEFAULT_BASE_URL = 'https://api.anthropic.com';
const DEFAULT_MODEL = 'claude-sonnet-4-20250514';
const DEFAULT_VERSION = '2023-06-01';
const DEFAULT_TIMEOUT_MS = 60000;

class AnthropicProvider {
  /**
   * @param {{apiKey?: string, baseUrl?: string, model?: string, version?: string, timeoutMs?: number, temperature?: number, fetchImpl?: Function, maxTokens?: number}} [options]
   */
  constructor(options = {}) {
    this.type = 'anthropic';
    this.apiKey = options.apiKey || process.env.ANTHROPIC_API_KEY || '';
    this.baseUrl = String(options.baseUrl || process.env.GRAVION_HARNESS_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, '');
    this.model = options.model || process.env.GRAVION_HARNESS_MODEL || DEFAULT_MODEL;
    this.version = options.version || DEFAULT_VERSION;
    this.timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : DEFAULT_TIMEOUT_MS;
    this.temperature = Number.isFinite(options.temperature) ? options.temperature : 0;
    this.maxTokens = Number.isFinite(options.maxTokens) ? options.maxTokens : 4096;
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
  }

  /**
   * Asks the model for a plan.
   *
   * @param {object} request
   * @returns {Promise<{steps: object[], provider: string, model: string, raw: string|null, error?: string}>}
   */
  async propose(request = {}) {
    const prompt = buildPrompt(request);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchImpl(`${this.baseUrl}/v1/messages`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'anthropic-version': this.version,
          ...(this.apiKey ? { 'x-api-key': this.apiKey } : {}),
        },
        body: JSON.stringify({
          model: this.model,
          max_tokens: this.maxTokens,
          temperature: this.temperature,
          system: 'You return a JSON plan for an authorised security assessment. You never refuse to plan, and you never propose targets outside the list you are given.',
          messages: [{ role: 'user', content: prompt }],
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const body = await response.text().catch(() => '');
        return {
          steps: [],
          provider: this.type,
          model: this.model,
          raw: null,
          error: `provider returned HTTP ${response.status}: ${body.slice(0, 300)}`,
        };
      }

      const payload = await response.json();
      const content = payload && Array.isArray(payload.content)
        ? payload.content.filter((block) => block && block.type === 'text').map((block) => block.text).join('\n')
        : '';

      const parsed = extractJson(content || '');
      const steps = normalizePlan(parsed);

      return {
        steps,
        provider: this.type,
        model: this.model,
        raw: content || null,
        error: parsed ? null : 'the model reply did not contain a JSON plan',
      };
    } catch (error) {
      const message = error && error.name === 'AbortError'
        ? `provider timed out after ${this.timeoutMs}ms`
        : String(error && error.message ? error.message : error);
      return { steps: [], provider: this.type, model: this.model, raw: null, error: message };
    } finally {
      clearTimeout(timer);
    }
  }
}

module.exports = {
  AnthropicProvider,
  DEFAULT_BASE_URL,
  DEFAULT_MODEL,
  DEFAULT_VERSION,
};
