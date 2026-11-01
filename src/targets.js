'use strict';

/**
 * Target lists.
 *
 * The operator's authorisation comes from a target list: either a personal
 * list of their own assets, or the scope file of a bug bounty program. The
 * harness reads that list, expands it, discovers related hosts, and derives
 * the engagement scope from it, so the operator does not have to author the
 * scope and the list separately.
 *
 * Supported input per line:
 *
 *   https://app.example.com/api/       a URL
 *   api.example.com                    a host
 *   10.0.0.0/24                        a CIDR block
 *   203.0.113.7                        an address
 *   /srv/lab                           a local path
 *   example.com, program=hackerone, note=main site
 *
 * A JSON array of objects is also accepted, with the fields `value` (or
 * `url` / `host` / `ip` / `cidr`), `program` and `note`.
 */

const fs = require('node:fs');
const path = require('node:path');
const dns = require('node:dns').promises;

const { parseCidr, ipv4ToInt } = require('./scope');

const MAX_CIDR_HOSTS = 256;

/**
 * Guesses the type of a raw target string.
 *
 * @param {string} value
 * @returns {string} one of url, cidr, ip, path, host
 */
function inferType(value) {
  const text = String(value || '').trim();
  if (!text) {
    return 'host';
  }
  if (/^https?:\/\//i.test(text)) {
    return 'url';
  }
  if (text.includes('/')) {
    if (parseCidr(text)) {
      return 'cidr';
    }
    if (/^([A-Za-z]:)?[\\/]/.test(text) || text.startsWith('/')) {
      return 'path';
    }
  }
  if (ipv4ToInt(text) !== null) {
    return 'ip';
  }
  return 'host';
}

/**
 * Splits a target line into comma-separated segments.
 *
 * A comma inside a quoted value is part of the value, not a separator.
 *
 * @param {string} text
 * @returns {string[]}
 */
function splitSegments(text) {
  const segments = [];
  let current = '';
  let quote = null;

  for (const char of String(text == null ? '' : text)) {
    if (quote) {
      current += char;
      if (char === quote) {
        quote = null;
      }
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      current += char;
      continue;
    }
    if (char === ',') {
      segments.push(current);
      current = '';
      continue;
    }
    current += char;
  }

  segments.push(current);
  return segments.map((segment) => segment.trim()).filter((segment) => segment.length > 0);
}

/**
 * Removes one layer of matching quotes from a value.
 *
 * @param {string} value
 * @returns {string}
 */
function stripQuotes(value) {
  const text = String(value == null ? '' : value);
  if (text.length >= 2) {
    const first = text[0];
    const last = text[text.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return text.slice(1, -1);
    }
  }
  return text;
}

/**
 * Parses the `key=value` segments of a target line.
 *
 * Each segment is read on its own, so a value may contain spaces. A segment
 * that carries no key continues the value of the previous key, which is how
 * `note=main site, staging` keeps both words.
 *
 * @param {string[]} segments
 * @returns {{attributes: object, continuations: Set<number>}}
 */
function parseAttributeSegments(segments) {
  const attributes = {};
  const continuations = new Set();
  let lastKey = null;

  segments.forEach((segment, index) => {
    const match = segment.match(/^(\w+)\s*=\s*(.*)$/);
    if (match) {
      const key = match[1].toLowerCase();
      attributes[key] = stripQuotes(match[2].trim());
      lastKey = key;
      return;
    }
    if (lastKey) {
      const previous = attributes[lastKey];
      attributes[lastKey] = previous ? `${previous}, ${segment}` : segment;
      continuations.add(index);
    }
  });

  return { attributes, continuations };
}

/**
 * Parses a target list into normalised target records.
 *
 * @param {string} text
 * @returns {object[]}
 */
function parseTargetList(text) {
  const targets = [];
  const lines = String(text == null ? '' : text).split(/\r?\n/);

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }

    // A JSON object per line.
    if (line.startsWith('{')) {
      try {
        const parsed = JSON.parse(line);
        const value = parsed.value || parsed.url || parsed.host || parsed.ip || parsed.cidr || parsed.target;
        if (value) {
          targets.push(makeTarget(value, parsed));
        }
        continue;
      } catch {
        // Fall through to the plain-text parser.
      }
    }

    const segments = splitSegments(line);
    const first = segments[0];
    if (!first) {
      continue;
    }

    const rest = segments.slice(1);
    const { attributes, continuations } = parseAttributeSegments(rest);
    const noteParts = rest.filter((part, index) => !/^\w+\s*=/.test(part) && !continuations.has(index));
    const value = attributes.url || attributes.host || attributes.ip || attributes.cidr || attributes.target || first;

    targets.push(makeTarget(value, {
      program: attributes.program || attributes.bounty || '',
      note: attributes.note || noteParts.join(', '),
      type: attributes.type || '',
    }));
  }

  return targets;
}

/**
 * Builds a normalised target record.
 *
 * @param {string} value
 * @param {object} [extra]
 * @returns {object}
 */
function makeTarget(value, extra = {}) {
  const cleaned = String(value == null ? '' : value).trim();
  const type = extra.type && ['url', 'host', 'ip', 'cidr', 'path'].includes(String(extra.type).toLowerCase())
    ? String(extra.type).toLowerCase()
    : inferType(cleaned);

  return {
    type,
    value: cleaned,
    program: extra.program ? String(extra.program) : '',
    note: extra.note ? String(extra.note) : '',
    source: extra.source ? String(extra.source) : 'list',
  };
}

/**
 * Reads a target list from disk. JSON files may hold an array of objects or
 * of strings; every other file is read as line-based text.
 *
 * @param {string} filePath
 * @returns {object[]}
 */
function loadTargetList(filePath) {
  const resolved = path.resolve(filePath);
  const raw = fs.readFileSync(resolved, 'utf8');

  if (resolved.toLowerCase().endsWith('.json')) {
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error(`target file ${resolved} is not valid JSON: ${error.message}`);
    }
    const list = Array.isArray(parsed) ? parsed : (Array.isArray(parsed.targets) ? parsed.targets : []);
    return list.map((item) => {
      if (typeof item === 'string') {
        return makeTarget(item, { source: resolved });
      }
      return makeTarget(item.value || item.url || item.host || item.ip || item.cidr || item.target || '', {
        program: item.program || item.bounty || '',
        note: item.note || '',
        type: item.type || '',
        source: resolved,
      });
    }).filter((target) => target.value);
  }

  return parseTargetList(raw).map((target) => ({ ...target, source: resolved }));
}

/**
 * Expands a CIDR block into individual addresses.
 *
 * @param {string} cidr
 * @param {number} [limit]
 * @returns {string[]}
 */
function expandCidr(cidr, limit = MAX_CIDR_HOSTS) {
  const network = parseCidr(cidr);
  if (!network) {
    return [];
  }
  const size = 2 ** (32 - network.bits);
  if (size > limit) {
    return [];
  }
  const addresses = [];
  for (let offset = 0; offset < size; offset += 1) {
    const value = network.base + offset;
    addresses.push([
      (value >>> 24) & 255,
      (value >>> 16) & 255,
      (value >>> 8) & 255,
      value & 255,
    ].join('.'));
  }
  return addresses;
}

/**
 * Expands a target list into the concrete set of things to test.
 *
 * A CIDR block becomes individual addresses, a URL also yields its host, and
 * duplicates are removed while the original order is kept.
 *
 * @param {object[]} targets
 * @param {{maxCidrHosts?: number}} [options]
 * @returns {object[]}
 */
function expandTargets(targets, options = {}) {
  const limit = Number.isFinite(options.maxCidrHosts) ? options.maxCidrHosts : MAX_CIDR_HOSTS;
  const expanded = [];
  const seen = new Set();

  const push = (target) => {
    const key = `${target.type}:${target.value}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    expanded.push(target);
  };

  for (const target of targets) {
    push(target);

    if (target.type === 'cidr') {
      for (const address of expandCidr(target.value, limit)) {
        push(makeTarget(address, { program: target.program, note: target.note, source: 'cidr' }));
      }
    }

    if (target.type === 'url') {
      try {
        const parsed = new URL(target.value);
        push(makeTarget(parsed.hostname, {
          program: target.program,
          note: target.note,
          source: 'url-host',
        }));
      } catch {
        // Not a parseable URL; the raw target stays in the list.
      }
    }
  }

  return expanded;
}

/**
 * Resolves a hostname to its addresses.
 *
 * @param {string} hostname
 * @param {object} [resolver]
 * @returns {Promise<string[]>}
 */
async function resolveHost(hostname, resolver = dns) {
  try {
    const addresses = await resolver.resolve4(hostname);
    return Array.isArray(addresses) ? addresses : [];
  } catch {
    return [];
  }
}

/**
 * Discovers hosts under a seed domain by resolving candidate names.
 *
 * The wordlist is supplied by the operator, so the harness never guesses
 * names on its own. Resolution is the only check performed here: a name that
 * does not resolve is not a target.
 *
 * @param {string} seed
 * @param {string[]} words
 * @param {{resolver?: object, limit?: number}} [options]
 * @returns {Promise<object[]>}
 */
async function discoverHosts(seed, words, options = {}) {
  const root = String(seed || '').trim().replace(/^\.+|\.+$/g, '').toLowerCase();
  if (!root) {
    return [];
  }
  const resolver = options.resolver || dns;
  const limit = Number.isFinite(options.limit) ? options.limit : 500;
  const discovered = [];

  for (const word of Array.isArray(words) ? words : []) {
    if (discovered.length >= limit) {
      break;
    }
    const label = String(word).trim().toLowerCase();
    if (!label || label.includes('/') || label.includes(' ')) {
      continue;
    }
    const hostname = `${label}.${root}`;
    const addresses = await resolveHost(hostname, resolver);
    if (addresses.length) {
      discovered.push({
        type: 'host',
        value: hostname,
        program: options.program || '',
        note: `discovered under ${root}`,
        source: 'discovery',
        addresses,
      });
    }
  }

  return discovered;
}

/**
 * Derives a scope specification from a target list.
 *
 * The list *is* the authorisation, so every target becomes an allow rule.
 *
 * @param {object[]} targets
 * @param {{deny?: object[]}} [options]
 * @returns {object}
 */
function buildScopeSpec(targets, options = {}) {
  const allow = [];
  const seen = new Set();

  for (const target of targets) {
    const rule = { type: target.type, value: target.value };
    if (target.program) {
      rule.note = target.program;
    }
    const key = `${rule.type}:${rule.value}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    allow.push(rule);
  }

  return {
    description: options.description || 'derived from the operator target list',
    allowedSchemes: options.allowedSchemes || ['http', 'https'],
    allowedPorts: options.allowedPorts || null,
    allow,
    deny: (options.deny || []).map((target) => ({ type: target.type, value: target.value })),
  };
}

module.exports = {
  MAX_CIDR_HOSTS,
  buildScopeSpec,
  discoverHosts,
  expandCidr,
  expandTargets,
  inferType,
  loadTargetList,
  makeTarget,
  parseTargetList,
};
