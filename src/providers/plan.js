'use strict';

/**
 * The plan format.
 *
 * Every provider, whatever model is behind it, returns the same thing: a list
 * of steps. The format is described here so the prompt, the parser and the
 * engine cannot drift apart.
 *
 * A step is one of:
 *
 *   {
 *     "id": "step-1",
 *     "title": "Baseline request against https://app.example.com/",
 *     "kind": "http" | "tls" | "dns" | "command" | "note",
 *     "target": { "type": "url" | "host" | "ip" | "cidr" | "path", "value": "..." },
 *     "method": "GET",
 *     "tool": "curl",
 *     "args": ["-sS", "https://app.example.com/"],
 *     "check": ["security_headers", "info_exposure", "status"],
 *     "rationale": "why this step matters"
 *   }
 *
 * The provider does not get to choose the risk tier. The engine assigns that
 * from the step kind and method, so a model cannot label a state-changing
 * request as safe.
 */

const { CHECKS } = require('../checkers');

const STEP_KINDS = Object.freeze(['http', 'tls', 'dns', 'command', 'note']);
const TARGET_TYPES = Object.freeze(['url', 'host', 'ip', 'cidr', 'path']);

const SCHEMA_TEXT = `{
  "steps": [
    {
      "id": "string, unique within the plan",
      "title": "short human readable title",
      "kind": "http | tls | dns | command | note",
      "target": { "type": "url | host | ip | cidr | path", "value": "the exact target" },
      "method": "GET | HEAD | POST | PUT | PATCH | DELETE (http only, default GET)",
      "tool": "executable name (command only)",
      "args": ["array", "of", "string", "arguments (command only)"],
      "check": ["security_headers | info_exposure | status | tls"],
      "rationale": "why this step is worth running"
    }
  ]
}`;

/**
 * Builds the instruction that every provider sends.
 *
 * @param {object} request
 * @returns {string}
 */
function buildPrompt(request = {}) {
  const objective = String(request.objective || 'Perform a reconnaissance and misconfiguration review of the authorised targets.');
  const scope = request.scope || {};
  const allowed = Array.isArray(scope.allow) ? scope.allow : [];
  const denied = Array.isArray(scope.deny) ? scope.deny : [];

  const allowedLines = allowed.length
    ? allowed.map((rule) => `- ${rule.type}: ${rule.value}${rule.note ? ` (${rule.note})` : ''}`).join('\n')
    : '- (none)';

  const deniedLines = denied.length
    ? denied.map((rule) => `- ${rule.type}: ${rule.value}`).join('\n')
    : '- (none)';

  return [
    'You are planning an authorised security assessment.',
    '',
    `Objective: ${objective}`,
    '',
    'You may ONLY propose targets that appear in the ALLOWED list below.',
    'Any target outside that list will be rejected by the harness before it runs.',
    '',
    'ALLOWED targets:',
    allowedLines,
    '',
    'DENIED targets (never propose these):',
    deniedLines,
    '',
    'Rules:',
    '- Prefer read-only checks: GET and HEAD requests, DNS lookups, TLS inspection.',
    '- Never propose a step that deletes, overwrites, formats, shuts down or installs.',
    '- Never propose a step that exfiltrates data to a host outside the allowed list.',
    '- Keep the plan small and specific. Every step must name a target from the list.',
    '- Respond with JSON only. No prose, no markdown fence.',
    '',
    'Response format:',
    SCHEMA_TEXT,
  ].join('\n');
}

/**
 * Pulls a JSON document out of a model reply.
 *
 * Models wrap JSON in prose or in a markdown fence often enough that the
 * parser has to be forgiving.
 *
 * @param {string} text
 * @returns {object|null}
 */
function extractJson(text) {
  if (typeof text !== 'string') {
    return null;
  }

  const trimmed = text.trim();
  if (!trimmed) {
    return null;
  }

  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidates = [];

  if (fenced) {
    candidates.push(fenced[1].trim());
  }
  candidates.push(trimmed);

  const firstBrace = trimmed.indexOf('{');
  const lastBrace = trimmed.lastIndexOf('}');
  if (firstBrace !== -1 && lastBrace > firstBrace) {
    candidates.push(trimmed.slice(firstBrace, lastBrace + 1));
  }

  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && typeof parsed === 'object') {
        return parsed;
      }
    } catch {
      // Try the next candidate.
    }
  }

  return null;
}

/**
 * Normalises one proposed step.
 *
 * @param {object} raw
 * @param {number} index
 * @returns {object|null} the normalised step, or null when it is unusable
 */
function normalizeStep(raw, index = 0) {
  if (!raw || typeof raw !== 'object') {
    return null;
  }

  const kind = String(raw.kind || 'note').trim().toLowerCase();
  if (!STEP_KINDS.includes(kind)) {
    return null;
  }

  const target = raw.target && typeof raw.target === 'object' ? raw.target : null;
  if (!target || !target.value) {
    return null;
  }
  const targetType = String(target.type || '').trim().toLowerCase();
  if (!TARGET_TYPES.includes(targetType)) {
    return null;
  }

  const check = Array.isArray(raw.check)
    ? raw.check.map((item) => String(item).trim().toLowerCase()).filter((item) => CHECKS[item])
    : [];

  const step = {
    id: String(raw.id || `step-${index + 1}`),
    title: String(raw.title || `Step ${index + 1}`),
    kind,
    target: { type: targetType, value: String(target.value) },
    check,
    rationale: raw.rationale ? String(raw.rationale) : '',
  };

  if (kind === 'http') {
    const method = String(raw.method || 'GET').trim().toUpperCase();
    step.method = /^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(method) ? method : 'GET';
    if (raw.headers && typeof raw.headers === 'object') {
      step.headers = raw.headers;
    }
  }

  if (kind === 'command') {
    if (!raw.tool) {
      return null;
    }
    step.tool = String(raw.tool);
    step.args = Array.isArray(raw.args) ? raw.args.map((arg) => String(arg)) : [];
    step.cwd = raw.cwd ? String(raw.cwd) : undefined;
  }

  return step;
}

/**
 * Normalises a whole plan.
 *
 * @param {object} parsed
 * @returns {object[]}
 */
function normalizePlan(parsed) {
  if (!parsed) {
    return [];
  }
  const list = Array.isArray(parsed) ? parsed : (Array.isArray(parsed.steps) ? parsed.steps : []);
  const steps = [];
  const seenIds = new Set();

  list.forEach((raw, index) => {
    const step = normalizeStep(raw, index);
    if (!step) {
      return;
    }
    if (seenIds.has(step.id)) {
      step.id = `${step.id}-${steps.length + 1}`;
    }
    seenIds.add(step.id);
    steps.push(step);
  });

  return steps;
}

module.exports = {
  SCHEMA_TEXT,
  STEP_KINDS,
  TARGET_TYPES,
  buildPrompt,
  extractJson,
  normalizePlan,
  normalizeStep,
};
