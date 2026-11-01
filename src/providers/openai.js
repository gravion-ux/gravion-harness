'use strict';

/**
 * OpenAI-compatible provider.
 *
 * "OpenAI-compatible" covers the official API and everything that speaks the
 * same chat-completions shape: Ollama, LM Studio, vLLM, llama.cpp's server,
 * Groq, Together, OpenRouter, and the local model runners the operator
 * already has on their machine.
 *
 * Point `baseUrl` at whichever one you use:
 *
 *   Ollama        http://127.0.0.1:11434/v1
 *   LM Studio     http://127.0.0.1:1234/v1
 *   vLLM          http://127.0.0.1:8000/v1
 *   Groq          https://api.groq.com/openai/v1
 *   OpenRouter    https://openrouter.ai/api/v1
 *
 * The API key is read from the environment, never from the plan and never
 * from a target.
 */

const { buildPrompt, extractJson, normalizePlan } = require('./plan');

const DEFAULT_BASE_URL = 'https://api.openai.com/v1';
const DEFAULT_MODEL = 'gpt-4o-mini';
const DEFAULT_TIMEOUT_MS = 60000;

class OpenAIProvider {
  /**
   * @param {{apiKey?: string, baseUrl?: string, model?: string, timeoutMs?: number, temperature?: number, fetchImpl?: Function}} [options]
   */
  constructor(options = {}) {
    this.type = 'openai';
    this.apiKey = options.apiKey || process.env.OPENAI_API_KEY || process.env.GRAVION_HARNESS_API_KEY || '';
    this.baseUrl = String(options.baseUrl || process.env.GRAVION_HARNESS_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, '');
    this.model = options.model || process.env.GRAVION_HARNESS_MODEL || DEFAULT_MODEL;
    this.timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : DEFAULT_TIMEOUT_MS;
    this.temperature = Number.isFinite(options.temperature) ? options.temperature : 0;
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
      const response = await this.fetchImpl(`${this.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(this.apiKey ? { authorization: `Bearer ${this.apiKey}` } : {}),
        },
        body: JSON.stringify({
          model: this.model,
          temperature: this.temperature,
          messages: [
            {
              role: 'system',
              content: 'You return a JSON plan for an authorised security assessment. You never refuse to plan, and you never propose targets outside the list you are given.',
            },
            { role: 'user', content: prompt },
          ],
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
      const content = payload && payload.choices && payload.choices[0]
        ? payload.choices[0].message && payload.choices[0].message.content
        : null;

      const parsed = extractJson(content || '');
      const steps = normalizePlan(parsed);

      return {
        steps,
        provider: this.type,
        model: this.model,
        raw: typeof content === 'string' ? content : null,
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
  DEFAULT_BASE_URL,
  DEFAULT_MODEL,
  OpenAIProvider,
};
