'use strict';

/**
 * HTTP probing.
 *
 * The prober is deliberately explicit about redirects: it never follows one
 * blindly. Each hop is reported, and a hop that leaves the engagement scope
 * is blocked rather than followed. That matters for a scanner, because a
 * redirect to an unrelated host is exactly how a scan walks off its target.
 */

const tls = require('node:tls');

const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_MAX_BYTES = 512 * 1024;
const DEFAULT_MAX_REDIRECTS = 3;

/**
 * Reads at most `maxBytes` of a response body.
 *
 * @param {Response} response
 * @param {number} maxBytes
 * @returns {Promise<{text: string, bytes: number, truncated: boolean}>}
 */
async function readBody(response, maxBytes) {
  if (!response.body) {
    return { text: '', bytes: 0, truncated: false };
  }

  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  let truncated = false;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      bytes += value.length;
      if (bytes > maxBytes) {
        chunks.push(Buffer.from(value.subarray(0, value.length - (bytes - maxBytes))));
        truncated = true;
        break;
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    try {
      await reader.cancel();
    } catch {
      // The stream may already be closed.
    }
  }

  return { text: Buffer.concat(chunks).toString('utf8'), bytes, truncated };
}

/**
 * Performs a single HTTP request without following redirects.
 *
 * @param {string} url
 * @param {object} [options]
 * @returns {Promise<object>}
 */
async function requestOnce(url, options = {}) {
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : DEFAULT_TIMEOUT_MS;
  const maxBytes = Number.isFinite(options.maxBytes) ? options.maxBytes : DEFAULT_MAX_BYTES;
  const method = String(options.method || 'GET').toUpperCase();

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const startedAt = Date.now();

  try {
    const response = await fetch(url, {
      method,
      headers: options.headers || {},
      body: options.body,
      redirect: 'manual',
      signal: controller.signal,
    });

    const body = method === 'HEAD'
      ? { text: '', bytes: 0, truncated: false }
      : await readBody(response, maxBytes);

    return {
      ok: true,
      url,
      method,
      status: response.status,
      statusText: response.statusText,
      headers: Object.fromEntries(response.headers.entries()),
      body: body.text,
      bodyBytes: body.bytes,
      bodyTruncated: body.truncated,
      durationMs: Date.now() - startedAt,
      location: response.headers.get('location'),
    };
  } catch (error) {
    return {
      ok: false,
      url,
      method,
      status: null,
      statusText: null,
      headers: {},
      body: '',
      bodyBytes: 0,
      bodyTruncated: false,
      durationMs: Date.now() - startedAt,
      error: error && error.name === 'AbortError'
        ? `request timed out after ${timeoutMs}ms`
        : String(error && error.message ? error.message : error),
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Performs an HTTP request, following redirects one hop at a time.
 *
 * @param {string} url
 * @param {object} [options]
 * @param {(url: string) => boolean} [options.validateRedirect] a scope check for each hop
 * @returns {Promise<object>}
 */
async function probeHttp(url, options = {}) {
  const maxRedirects = Number.isFinite(options.maxRedirects)
    ? options.maxRedirects
    : DEFAULT_MAX_REDIRECTS;
  const validate = typeof options.validateRedirect === 'function' ? options.validateRedirect : null;

  const chain = [];
  let current = String(url);

  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    const result = await requestOnce(current, options);
    chain.push({
      url: current,
      status: result.status,
      location: result.location || null,
    });

    const isRedirect = result.status && result.status >= 300 && result.status < 400 && result.location;
    if (!isRedirect) {
      return {
        ...result,
        requestedUrl: String(url),
        redirects: chain,
        blockedRedirect: null,
      };
    }

    if (hop === maxRedirects) {
      return {
        ...result,
        requestedUrl: String(url),
        redirects: chain,
        blockedRedirect: 'redirect limit reached',
      };
    }

    let next;
    try {
      next = new URL(result.location, current).toString();
    } catch {
      return {
        ...result,
        requestedUrl: String(url),
        redirects: chain,
        blockedRedirect: `redirect target could not be parsed: ${result.location}`,
      };
    }

    if (validate && !validate(next)) {
      return {
        ...result,
        requestedUrl: String(url),
        redirects: chain,
        blockedRedirect: `redirect to ${next} leaves the engagement scope`,
      };
    }

    current = next;
  }

  return {
    ok: false,
    requestedUrl: String(url),
    url: current,
    method: String(options.method || 'GET').toUpperCase(),
    status: null,
    statusText: null,
    headers: {},
    body: '',
    bodyBytes: 0,
    bodyTruncated: false,
    durationMs: 0,
    redirects: chain,
    blockedRedirect: 'redirect limit reached',
    error: 'redirect limit reached',
  };
}

/**
 * Inspects the TLS configuration of a host.
 *
 * @param {string} host
 * @param {{port?: number, timeoutMs?: number}} [options]
 * @returns {Promise<object>}
 */
function inspectTls(host, options = {}) {
  const port = Number.isFinite(options.port) ? options.port : 443;
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : DEFAULT_TIMEOUT_MS;

  return new Promise((resolve) => {
    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false, timeout: timeoutMs },
      () => {
        const certificate = socket.getPeerCertificate(false) || {};
        const authorized = socket.authorized;
        const authorizationError = socket.authorizationError || null;

        socket.end();

        resolve({
          ok: true,
          host,
          port,
          authorized,
          authorizationError,
          protocol: socket.getProtocol ? socket.getProtocol() : null,
          subject: certificate.subject || null,
          issuer: certificate.issuer || null,
          validFrom: certificate.valid_from || null,
          validTo: certificate.valid_to || null,
          subjectAltName: certificate.subjectaltname || null,
          fingerprint256: certificate.fingerprint256 || null,
        });
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ ok: false, host, port, error: `TLS connection timed out after ${timeoutMs}ms` });
    });

    socket.on('error', (error) => {
      resolve({ ok: false, host, port, error: String(error && error.message ? error.message : error) });
    });
  });
}

module.exports = {
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_REDIRECTS,
  DEFAULT_TIMEOUT_MS,
  inspectTls,
  probeHttp,
  readBody,
  requestOnce,
};
