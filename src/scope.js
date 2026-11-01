'use strict';

/**
 * Target scope for authorized security testing.
 *
 * The harness may only touch what the engagement explicitly authorises. This
 * module is the single place that decides whether a target is inside that
 * boundary, and it is deliberately conservative:
 *
 *  - A target with no matching allow rule is denied.
 *  - A deny rule always wins, whatever it is matched against.
 *  - A URL is constrained by scheme and port on top of the host match.
 *
 * Nothing here performs I/O. The scope is a pure decision function so it can
 * be reasoned about and tested without a network.
 */

const fs = require('node:fs');
const path = require('node:path');

const RULE_TYPES = Object.freeze(['host', 'ip', 'cidr', 'url', 'path']);

const DEFAULT_SCHEMES = Object.freeze(['http', 'https']);

/**
 * Normalises a host for comparison: lower case, no trailing dot.
 *
 * @param {unknown} host
 * @returns {string}
 */
function normalizeHost(host) {
  return String(host == null ? '' : host).trim().toLowerCase().replace(/\.$/, '');
}

/**
 * True when `host` matches `pattern`. The pattern may be exact or a wildcard
 * of the form `*.example.com`, which matches `a.example.com` but never
 * `example.com` itself.
 *
 * @param {string} pattern
 * @param {string} host
 * @returns {boolean}
 */
function hostMatches(pattern, host) {
  const normalizedPattern = normalizeHost(pattern);
  const normalizedHost = normalizeHost(host);

  if (!normalizedPattern || !normalizedHost) {
    return false;
  }
  if (normalizedPattern === normalizedHost) {
    return true;
  }
  if (normalizedPattern.startsWith('*.')) {
    const suffix = normalizedPattern.slice(1);
    return normalizedHost.endsWith(suffix) && normalizedHost.length > suffix.length;
  }
  return false;
}

/**
 * Converts a dotted-quad IPv4 address to a 32-bit integer.
 *
 * @param {string} address
 * @returns {number|null}
 */
function ipv4ToInt(address) {
  const parts = String(address).trim().split('.');
  if (parts.length !== 4) {
    return null;
  }
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) {
      return null;
    }
    const octet = Number(part);
    if (octet > 255) {
      return null;
    }
    value = value * 256 + octet;
  }
  return value;
}

/**
 * Parses `10.0.0.0/8` into the address value and the prefix length.
 *
 * @param {string} cidr
 * @returns {{base: number, bits: number}|null}
 */
function parseCidr(cidr) {
  const [address, prefixText] = String(cidr).trim().split('/');
  const base = ipv4ToInt(address);
  if (base === null) {
    return null;
  }
  if (!/^\d{1,2}$/.test(String(prefixText))) {
    return null;
  }
  const bits = Number(prefixText);
  if (bits < 0 || bits > 32) {
    return null;
  }
  return { base, bits };
}

/**
 * True when `address` falls inside `cidr`.
 *
 * @param {string} cidr
 * @param {string} address
 * @returns {boolean}
 */
function cidrContains(cidr, address) {
  const network = parseCidr(cidr);
  const target = ipv4ToInt(address);
  if (!network || target === null) {
    return false;
  }
  if (network.bits === 0) {
    return true;
  }
  const blockSize = 2 ** (32 - network.bits);
  return Math.floor(target / blockSize) === Math.floor(network.base / blockSize);
}

/**
 * Normalises a rule into a stable shape and validates it.
 *
 * @param {object} rule
 * @returns {object}
 */
function normalizeRule(rule) {
  if (!rule || typeof rule !== 'object') {
    throw new TypeError('a scope rule must be an object');
  }
  const type = String(rule.type || '').trim().toLowerCase();
  if (!RULE_TYPES.includes(type)) {
    throw new TypeError(`unknown scope rule type: ${rule.type}`);
  }
  const value = String(rule.value == null ? '' : rule.value).trim();
  if (!value) {
    throw new TypeError(`scope rule of type ${type} needs a value`);
  }

  const normalized = { type, value, note: rule.note ? String(rule.note) : '' };

  if (type === 'cidr' && !parseCidr(value)) {
    throw new TypeError(`invalid CIDR rule: ${value}`);
  }
  if (type === 'url') {
    let parsed;
    try {
      parsed = new URL(value);
    } catch {
      throw new TypeError(`invalid URL rule: ${value}`);
    }
    normalized.url = parsed;
    normalized.host = normalizeHost(parsed.hostname);
    normalized.pathPrefix = parsed.pathname || '/';
  }
  if (type === 'host') {
    normalized.host = normalizeHost(value);
  }
  if (type === 'path') {
    normalized.root = path.resolve(value);
  }

  return normalized;
}

class Scope {
  /**
   * @param {object} [spec]
   */
  constructor(spec = {}) {
    if (!spec || typeof spec !== 'object') {
      throw new TypeError('a scope spec must be an object');
    }

    this.allow = Array.isArray(spec.allow) ? spec.allow.map(normalizeRule) : [];
    this.deny = Array.isArray(spec.deny) ? spec.deny.map(normalizeRule) : [];
    this.allowedSchemes = Array.isArray(spec.allowedSchemes) && spec.allowedSchemes.length
      ? spec.allowedSchemes.map((scheme) => String(scheme).toLowerCase())
      : [...DEFAULT_SCHEMES];
    this.allowedPorts = Array.isArray(spec.allowedPorts) && spec.allowedPorts.length
      ? spec.allowedPorts.map(Number).filter((port) => Number.isInteger(port) && port > 0 && port < 65536)
      : null;
    this.description = spec.description ? String(spec.description) : '';
  }

  /**
   * Builds a scope from a JSON file.
   *
   * @param {string} filePath
   * @returns {Scope}
   */
  static fromFile(filePath) {
    const resolved = path.resolve(filePath);
    const raw = fs.readFileSync(resolved, 'utf8');
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error(`scope file ${resolved} is not valid JSON: ${error.message}`);
    }
    return new Scope(parsed);
  }

  /**
   * The scope as a plain object, safe to hand to a model provider.
   *
   * @returns {object}
   */
  toSpec() {
    return {
      description: this.description,
      allowedSchemes: [...this.allowedSchemes],
      allowedPorts: this.allowedPorts ? [...this.allowedPorts] : null,
      allow: this.allow.map((rule) => ({ type: rule.type, value: rule.value, note: rule.note })),
      deny: this.deny.map((rule) => ({ type: rule.type, value: rule.value, note: rule.note })),
    };
  }

  /**
   * True when a deny rule matches the target.
   *
   * @param {object} target
   * @returns {object|null} the matching deny rule
   */
  matchDeny(target) {
    for (const rule of this.deny) {
      if (this.ruleMatches(rule, target)) {
        return rule;
      }
    }
    return null;
  }

  /**
   * True when an allow rule matches the target.
   *
   * @param {object} target
   * @returns {object|null} the matching allow rule
   */
  matchAllow(target) {
    for (const rule of this.allow) {
      if (this.ruleMatches(rule, target)) {
        return rule;
      }
    }
    return null;
  }

  /**
   * Decides whether a target is inside the engagement boundary.
   *
   * @param {{type: string, value: string}} target
   * @returns {{allowed: boolean, reason: string, rule: object|null}}
   */
  explain(target) {
    if (!target || typeof target !== 'object' || !target.type || !target.value) {
      return { allowed: false, reason: 'target must be an object with a type and a value', rule: null };
    }

    const denied = this.matchDeny(target);
    if (denied) {
      return {
        allowed: false,
        reason: `matched a deny rule (${denied.type} ${denied.value})`,
        rule: denied,
      };
    }

    const allowed = this.matchAllow(target);
    if (!allowed) {
      return { allowed: false, reason: 'no allow rule matched this target', rule: null };
    }

    if (target.type === 'url') {
      const schemeCheck = this.checkUrlConstraints(target);
      if (!schemeCheck.allowed) {
        return schemeCheck;
      }
    }

    return {
      allowed: true,
      reason: `matched allow rule (${allowed.type} ${allowed.value})`,
      rule: allowed,
    };
  }

  /**
   * Convenience wrapper around {@link Scope#explain}.
   *
   * @param {{type: string, value: string}} target
   * @returns {boolean}
   */
  isAllowed(target) {
    return this.explain(target).allowed;
  }

  /**
   * Checks the scheme and port constraints that apply to a URL target.
   *
   * @param {object} target
   * @returns {{allowed: boolean, reason: string, rule: object|null}}
   */
  checkUrlConstraints(target) {
    let parsed;
    try {
      parsed = new URL(target.value);
    } catch {
      return { allowed: false, reason: 'target is not a valid URL', rule: null };
    }

    const scheme = parsed.protocol.replace(/:$/, '').toLowerCase();
    if (!this.allowedSchemes.includes(scheme)) {
      return { allowed: false, reason: `scheme ${scheme} is not in the allowed scheme list`, rule: null };
    }

    const port = parsed.port ? Number(parsed.port) : (scheme === 'https' ? 443 : 80);
    if (this.allowedPorts && !this.allowedPorts.includes(port)) {
      return { allowed: false, reason: `port ${port} is not in the allowed port list`, rule: null };
    }

    return { allowed: true, reason: 'scheme and port are allowed', rule: null };
  }

  /**
   * True when a single rule matches a target.
   *
   * @param {object} rule
   * @param {object} target
   * @returns {boolean}
   */
  ruleMatches(rule, target) {
    const type = String(target.type || '').toLowerCase();

    switch (rule.type) {
      case 'host': {
        if (type === 'host') {
          return hostMatches(rule.host, target.value);
        }
        if (type === 'url') {
          let parsed;
          try {
            parsed = new URL(target.value);
          } catch {
            return false;
          }
          return hostMatches(rule.host, parsed.hostname);
        }
        return false;
      }

      case 'ip': {
        if (type !== 'ip' && type !== 'host') {
          return false;
        }
        return normalizeHost(rule.value) === normalizeHost(target.value);
      }

      case 'cidr': {
        if (type !== 'ip' && type !== 'host') {
          return false;
        }
        return cidrContains(rule.value, target.value);
      }

      case 'url': {
        if (type !== 'url') {
          return false;
        }
        let parsed;
        try {
          parsed = new URL(target.value);
        } catch {
          return false;
        }
        if (!hostMatches(rule.host, parsed.hostname)) {
          return false;
        }
        const rulePort = rule.url.port ? Number(rule.url.port) : (rule.url.protocol === 'https:' ? 443 : 80);
        const targetPort = parsed.port ? Number(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80);
        if (rulePort !== targetPort) {
          return false;
        }
        return parsed.pathname.startsWith(rule.pathPrefix);
      }

      case 'path': {
        if (type !== 'path') {
          return false;
        }
        const resolved = path.resolve(String(target.value));
        const relative = path.relative(rule.root, resolved);
        return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
      }

      default:
        return false;
    }
  }
}

module.exports = {
  DEFAULT_SCHEMES,
  RULE_TYPES,
  Scope,
  cidrContains,
  hostMatches,
  ipv4ToInt,
  normalizeHost,
  normalizeRule,
  parseCidr,
};
