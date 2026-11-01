'use strict';

/**
 * Best-effort redaction of common credential formats.
 *
 * The audit log records what the harness did. It must never become the place
 * where a secret is stored, so every value that reaches the log goes through
 * this module first.
 *
 * This is pattern matching, not a complete secret scanner.
 */

const PATTERNS = Object.freeze([
  {
    name: 'private key',
    re: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g,
    replacement: '[REDACTED PRIVATE KEY]',
  },
  {
    name: 'github token',
    re: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
    replacement: '[REDACTED GITHUB TOKEN]',
  },
  {
    name: 'aws access key',
    re: /\bAKIA[0-9A-Z]{16}\b/g,
    replacement: '[REDACTED AWS ACCESS KEY]',
  },
  {
    name: 'stripe key',
    re: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    replacement: '[REDACTED API KEY]',
  },
  {
    name: 'openai style key',
    re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b/g,
    replacement: '[REDACTED API KEY]',
  },
  {
    name: 'google api key',
    re: /\bAIza[0-9A-Za-z_-]{30,}/g,
    replacement: '[REDACTED GOOGLE API KEY]',
  },
  {
    name: 'slack token',
    re: /\b(?:xox[baprs]-)[0-9A-Za-z-]{10,}\b/g,
    replacement: '[REDACTED SLACK TOKEN]',
  },
  {
    name: 'gitlab token',
    re: /\bglpat-[0-9A-Za-z_-]{20,}\b/g,
    replacement: '[REDACTED GITLAB TOKEN]',
  },
  {
    name: 'jwt',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    replacement: '[REDACTED JWT]',
  },
]);

const AUTHORIZATION_RE =
  /(\b(?:proxy-)?authorization["']?\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|[^\r\n]*)/gi;

const NAMED_SECRET_RE =
  /([A-Za-z0-9_.-]*(?:api[_-]?key|secret|token|password|passwd|passphrase|credential|authorization)[A-Za-z0-9_.-]*)(\s*["']?\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|Bearer\s+[A-Za-z0-9._~+/=-]{8,}|[^\s"'`]+)/gi;

/**
 * Object keys whose *value* is a credential regardless of its shape.
 *
 * A value such as `Basic dXNlcjpwYXNz` carries no recognisable token format,
 * so a pattern list cannot catch it. The key name is the only signal, and a
 * field called `authorization` or `api_key` is a credential by definition.
 */
const SECRET_KEY_RE =
  /^(?:.*[_-])?(?:api[_-]?key|access[_-]?key|secret[_-]?key|secret|token|auth[_-]?token|password|passwd|passphrase|credential|credentials|authorization|private[_-]?key|client[_-]?secret|session[_-]?id|cookie)(?:[_-].*)?$/i;

/**
 * Redacts credential-shaped substrings from a single string.
 *
 * @param {unknown} value
 * @returns {string}
 */
function redactSecrets(value) {
  if (value == null) {
    return '';
  }
  let text = String(value);

  for (const pattern of PATTERNS) {
    text = text.replace(pattern.re, pattern.replacement);
  }

  // An Authorization field carries a scheme *and* a credential. Redacting the
  // scheme alone would leave `Basic dXNlcjpwYXNz` in clear text, so the whole
  // value of the field is replaced. The quote style is preserved so a JSON
  // document stays parseable.
  text = text.replace(AUTHORIZATION_RE, (match, prefix, rawValue) => {
    const quote = rawValue.startsWith('"') ? '"' : rawValue.startsWith("'") ? "'" : '';
    return `${prefix}${quote}[REDACTED]${quote}`;
  });

  text = text.replace(NAMED_SECRET_RE, (match, name, separator, rawValue) => {
    const quote = rawValue.startsWith('"') ? '"' : rawValue.startsWith("'") ? "'" : '';
    return `${name}${separator}${quote}[REDACTED]${quote}`;
  });

  text = text.replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, '$1[REDACTED]');

  return text;
}

/**
 * Redacts every string inside a JSON-like value. Object keys are preserved,
 * because the key name is usually the useful part of the record — unless the
 * key names a credential, in which case the whole value is replaced.
 *
 * @param {unknown} value
 * @param {number} [depth]
 * @returns {unknown}
 */
function redactDeep(value, depth = 0) {
  if (depth > 12) {
    return '[TRUNCATED]';
  }
  if (typeof value === 'string') {
    return redactSecrets(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactDeep(item, depth + 1));
  }
  if (value && typeof value === 'object') {
    const result = {};
    for (const [key, item] of Object.entries(value)) {
      if (SECRET_KEY_RE.test(key)) {
        result[key] = redactSecretValue(item, depth);
      } else {
        result[key] = redactDeep(item, depth + 1);
      }
    }
    return result;
  }
  return value;
}

/**
 * Replaces the value of a credential-named field.
 *
 * The structure is kept for objects, because a reader still needs to know that
 * an authorization header had a scheme and a credential; every leaf is
 * replaced.
 *
 * @param {unknown} value
 * @param {number} depth
 * @returns {unknown}
 */
function redactSecretValue(value, depth) {
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value === 'string') {
    return '[REDACTED]';
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return '[REDACTED]';
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSecretValue(item, depth + 1));
  }
  if (depth > 12) {
    return '[TRUNCATED]';
  }
  const result = {};
  for (const [key, item] of Object.entries(value)) {
    result[key] = redactSecretValue(item, depth + 1);
  }
  return result;
}

module.exports = {
  PATTERNS,
  redactDeep,
  redactSecrets,
};
