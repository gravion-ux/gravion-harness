'use strict';

/**
 * The offline provider.
 *
 * This provider needs no API key, no network and no model. It produces a
 * deterministic plan from the engagement scope, which makes it useful in three
 * places:
 *
 *  - as the default, so the harness is useful the moment it is installed
 *  - as the provider in the test suite, where a live model would make the
 *    tests non-deterministic
 *  - as the fallback when a configured provider is unreachable
 *
 * It is also a real scanner: it proposes the read-only checks that a
 * reconnaissance pass consists of.
 */

const { DEFAULT_WELL_KNOWN_PATHS } = require('../wellknown');

/**
 * Builds the deterministic plan for an engagement.
 *
 * @param {object} request
 * @returns {Promise<{steps: object[], provider: string, model: string}>}
 */
async function propose(request = {}) {
  const scope = request.scope || {};
  const options = request.options || {};
  const allow = Array.isArray(scope.allow) ? scope.allow : [];
  const steps = [];

  const includeWellKnown = options.includeWellKnown !== false;
  const urls = allow.filter((rule) => rule.type === 'url');

  for (const rule of urls) {
    let parsed;
    try {
      parsed = new URL(rule.value);
    } catch {
      continue;
    }

    steps.push({
      id: `probe-${steps.length + 1}`,
      title: `Baseline request against ${rule.value}`,
      kind: 'http',
      target: { type: 'url', value: rule.value },
      method: 'GET',
      check: ['security_headers', 'info_exposure', 'status'],
      rationale: 'Establishes the baseline response, its headers and anything the body exposes.',
    });

    if (parsed.protocol === 'https:') {
      steps.push({
        id: `tls-${steps.length + 1}`,
        title: `TLS inspection of ${parsed.hostname}`,
        kind: 'tls',
        target: { type: 'url', value: rule.value },
        check: ['tls'],
        rationale: 'Checks the certificate chain, validity dates and negotiated protocol.',
      });
    }

    if (includeWellKnown) {
      const base = parsed.origin;
      for (const candidate of DEFAULT_WELL_KNOWN_PATHS) {
        steps.push({
          id: `wellknown-${steps.length + 1}`,
          title: `Check ${candidate} on ${base}`,
          kind: 'http',
          target: { type: 'url', value: `${base}${candidate}` },
          method: 'GET',
          check: ['status', 'info_exposure'],
          rationale: `Looks for ${candidate}, a path that is commonly left readable by mistake.`,
        });
      }
    }
  }

  const hosts = allow.filter((rule) => rule.type === 'host');
  for (const rule of hosts) {
    steps.push({
      id: `host-${steps.length + 1}`,
      title: `Resolve ${rule.value}`,
      kind: 'dns',
      target: { type: 'host', value: rule.value },
      check: [],
      rationale: 'Resolves the host so the report records the addresses that were in scope.',
    });
  }

  return {
    steps,
    provider: 'deterministic',
    model: 'offline',
    raw: null,
  };
}

module.exports = {
  name: 'deterministic',
  propose,
};
