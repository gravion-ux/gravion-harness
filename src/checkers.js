'use strict';

/**
 * Built-in checks.
 *
 * A check takes the result of an action and turns it into findings. Every
 * finding keeps the raw response it was derived from, so the report can show
 * the evidence instead of only the conclusion.
 *
 * Checks are plain functions, so an operator can add their own without
 * touching the engine.
 */

const { createFinding } = require('./findings');

/**
 * The headers a well-configured web application is expected to send.
 */
const SECURITY_HEADERS = Object.freeze([
  {
    header: 'content-security-policy',
    severity: 'low',
    title: 'Missing Content-Security-Policy header',
    description: 'The response does not send a Content-Security-Policy header, so the browser has no document-level restriction on where scripts and resources may be loaded from.',
    impact: 'A successful content injection or XSS has fewer browser-side obstacles to exploitation.',
    remediation: 'Send a Content-Security-Policy header that restricts script, style, frame and connect sources to what the application actually needs.',
    tags: ['headers', 'hardening'],
  },
  {
    header: 'x-content-type-options',
    severity: 'low',
    title: 'Missing X-Content-Type-Options header',
    description: 'The response does not send X-Content-Type-Options: nosniff, so browsers may guess the content type of a response instead of using the declared one.',
    impact: 'Content that the server meant to be inert can be interpreted as an active type by the browser.',
    remediation: 'Send X-Content-Type-Options: nosniff on every response.',
    tags: ['headers', 'hardening'],
  },
  {
    header: 'x-frame-options',
    severity: 'low',
    title: 'Missing X-Frame-Options header',
    description: 'The response does not restrict framing, so the page can be embedded in a frame on another origin.',
    impact: 'The application can be framed by another site, which enables clickjacking against authenticated actions.',
    remediation: 'Send X-Frame-Options: SAMEORIGIN, or a frame-ancestors directive in the Content-Security-Policy header.',
    tags: ['headers', 'clickjacking'],
  },
  {
    header: 'referrer-policy',
    severity: 'info',
    title: 'Missing Referrer-Policy header',
    description: 'The response does not send a Referrer-Policy header, so the browser applies its own default and may send full URLs, including query strings, to third parties.',
    impact: 'URLs that carry identifiers or tokens in the query string can leak to third-party origins.',
    remediation: 'Send a Referrer-Policy header, for example strict-origin-when-cross-origin.',
    tags: ['headers', 'privacy'],
  },
]);

const EXPOSURE_PATTERNS = Object.freeze([
  {
    id: 'private-key',
    severity: 'critical',
    re: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/,
    title: 'Private key material returned in the response body',
    description: 'The response body contains a PEM private key block.',
    impact: 'Anyone who can read this response can impersonate the holder of the key, decrypt what it protects, or authenticate as the key owner.',
    remediation: 'Remove the key from anything the web tier can read, rotate the key, and store key material outside the document root.',
    tags: ['secret-exposure', 'critical'],
  },
  {
    id: 'aws-key',
    severity: 'critical',
    re: /\bAKIA[0-9A-Z]{16}\b/,
    title: 'AWS access key identifier returned in the response body',
    description: 'The response body contains an AWS access key identifier.',
    impact: 'Together with a valid secret it allows full access to the associated AWS account.',
    remediation: 'Rotate the key, remove it from the response path, and scan the repository history for the same value.',
    tags: ['secret-exposure', 'critical'],
  },
  {
    id: 'password',
    severity: 'high',
    re: /(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{6,}/i,
    title: 'Credential-like value returned in the response body',
    description: 'The response body contains a password-shaped assignment.',
    impact: 'Credentials in a response body are readable by anyone who can reach the endpoint, and they are frequently cached by intermediaries.',
    remediation: 'Remove the value from the response, rotate it, and make sure secrets are never serialised into a response.',
    tags: ['secret-exposure'],
  },
  {
    id: 'stack-trace',
    severity: 'medium',
    re: /(?:Traceback \(most recent call last\)|at [\w.$]+\([\w.]+:\d+\)|Microsoft \.NET Framework|PHP Warning|Fatal error|java\.lang\.[A-Za-z]+Exception)/,
    title: 'Stack trace or framework error detail returned in the response body',
    description: 'The response body contains a stack trace or framework-specific error detail.',
    impact: 'Stack traces reveal internal package names, file paths, query fragments and sometimes credentials, which shortens the path to a deeper compromise.',
    remediation: 'Return a generic error page to the client and log the detail server-side.',
    tags: ['information-disclosure'],
  },
  {
    id: 'directory-listing',
    severity: 'medium',
    re: /<title>\s*Index of\s+\//i,
    title: 'Directory listing enabled',
    description: 'The response is a generated index of a directory.',
    impact: 'Files that are not linked from anywhere else become discoverable, which often exposes backups, configuration files and source archives.',
    remediation: 'Disable directory indexing on the web server and remove any file that does not need to be published.',
    tags: ['information-disclosure', 'misconfiguration'],
  },
  {
    id: 'debug-toolbar',
    severity: 'low',
    re: /(?:__debug__|Xdebug|Werkzeug Debugger|Django Debug Toolbar)/i,
    title: 'Debug tooling exposed in the response',
    description: 'The response references debug tooling or debug endpoints.',
    impact: 'Debug interfaces usually expose internals and, when they are reachable, allow code execution.',
    remediation: 'Disable debug tooling in every environment that is reachable from outside the development machine.',
    tags: ['misconfiguration', 'information-disclosure'],
  },
]);

/**
 * Lower-cases a header name for lookup.
 *
 * @param {object} headers
 * @param {string} name
 * @returns {string|undefined}
 */
function headerValue(headers, name) {
  if (!headers || typeof headers !== 'object') {
    return undefined;
  }
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === wanted) {
      return value;
    }
  }
  return undefined;
}

/**
 * Builds the evidence block that is stored with a finding.
 *
 * @param {object} context
 * @returns {object}
 */
function buildEvidence(context) {
  const probe = context.probe || {};
  return {
    capturedAt: new Date().toISOString(),
    request: {
      method: probe.method || null,
      url: probe.url || null,
      requestedUrl: probe.requestedUrl || null,
    },
    response: {
      status: probe.status ?? null,
      statusText: probe.statusText || null,
      headers: probe.headers || {},
      bodyBytes: probe.bodyBytes ?? null,
      bodyTruncated: Boolean(probe.bodyTruncated),
    },
    bodyExcerpt: typeof probe.body === 'string' ? probe.body.slice(0, 4000) : null,
    redirects: probe.redirects || [],
    durationMs: probe.durationMs ?? null,
    command: context.command || null,
  };
}

/**
 * Checks the response headers.
 *
 * @param {object} context
 * @returns {object[]}
 */
function checkSecurityHeaders(context) {
  const probe = context.probe || {};
  if (!probe.ok || !probe.headers) {
    return [];
  }

  const findings = [];
  const isHttps = String(probe.url || '').startsWith('https:');

  for (const spec of SECURITY_HEADERS) {
    if (headerValue(probe.headers, spec.header) !== undefined) {
      continue;
    }
    if (spec.header === 'strict-transport-security' && !isHttps) {
      continue;
    }
    findings.push(createFinding({
      title: spec.title,
      severity: spec.severity,
      category: 'security-headers',
      target: context.target,
      description: spec.description,
      impact: spec.impact,
      remediation: spec.remediation,
      steps: [
        `Request ${probe.method || 'GET'} ${probe.url}`,
        `Inspect the response headers`,
        `Observe that ${spec.header} is absent`,
      ],
      evidence: buildEvidence(context),
      references: [],
      tags: spec.tags,
      program: context.program,
    }));
  }

  return findings;
}

/**
 * Checks the response body for exposed material.
 *
 * @param {object} context
 * @returns {object[]}
 */
function checkInfoExposure(context) {
  const probe = context.probe || {};
  if (!probe.ok || typeof probe.body !== 'string' || !probe.body) {
    return [];
  }

  const findings = [];

  for (const spec of EXPOSURE_PATTERNS) {
    const match = probe.body.match(spec.re);
    if (!match) {
      continue;
    }
    findings.push(createFinding({
      title: spec.title,
      severity: spec.severity,
      category: 'information-disclosure',
      target: context.target,
      description: spec.description,
      impact: spec.impact,
      remediation: spec.remediation,
      steps: [
        `Request ${probe.method || 'GET'} ${probe.url}`,
        `Search the response body for ${spec.id}`,
        `The pattern matches at offset ${match.index}`,
      ],
      evidence: buildEvidence(context),
      tags: spec.tags,
      program: context.program,
    }));
  }

  return findings;
}

/**
 * Checks the HTTP status of the response.
 *
 * @param {object} context
 * @returns {object[]}
 */
function checkStatus(context) {
  const probe = context.probe || {};
  if (!probe.ok || !probe.status) {
    return [];
  }

  const findings = [];

  if (probe.status >= 500) {
    findings.push(createFinding({
      title: `Server error response (HTTP ${probe.status})`,
      severity: 'medium',
      category: 'server-error',
      target: context.target,
      description: `The endpoint answered with HTTP ${probe.status}${probe.statusText ? ` ${probe.statusText}` : ''}.`,
      impact: 'A server error on a reachable endpoint can disclose internals and indicates that the request reached an unhandled code path.',
      remediation: 'Reproduce the request with the same parameters, find the unhandled path, and return a controlled error response.',
      steps: [`Request ${probe.method || 'GET'} ${probe.url}`, `Observe the HTTP ${probe.status} status`],
      evidence: buildEvidence(context),
      tags: ['reliability', 'information-disclosure'],
      program: context.program,
    }));
  }

  if (probe.blockedRedirect) {
    findings.push(createFinding({
      title: 'Redirect leaves the engagement scope',
      severity: 'info',
      category: 'scope',
      target: context.target,
      description: `The endpoint redirected the request, but the harness stopped: ${probe.blockedRedirect}. `
        + 'The redirect target is outside the authorised scope, so the harness did not follow it.',
      impact: 'The redirect target is outside the authorised scope, so the harness did not follow it. This is recorded so the scope boundary is visible in the report.',
      remediation: 'Extend the scope if this host should be tested, or leave the redirect as is.',
      steps: [`Request ${probe.method || 'GET'} ${probe.url}`, 'Observe the redirect and the blocked follow-up'],
      evidence: buildEvidence(context),
      tags: ['scope'],
      program: context.program,
    }));
  }

  return findings;
}

/**
 * Checks the TLS configuration of a host.
 *
 * @param {object} context
 * @returns {object[]}
 */
function checkTls(context) {
  const tlsResult = context.tls;
  if (!tlsResult || !tlsResult.ok) {
    return [];
  }

  const findings = [];

  if (tlsResult.validTo && new Date(tlsResult.validTo) < new Date()) {
    findings.push(createFinding({
      title: 'Expired TLS certificate',
      severity: 'high',
      category: 'tls',
      target: context.target,
      description: `The certificate for ${tlsResult.host} expired on ${tlsResult.validTo}.`,
      impact: 'Clients that enforce certificate validity refuse the connection, and users who click through the warning are trained to ignore it.',
      remediation: 'Renew the certificate and automate renewal so it cannot lapse again.',
      evidence: { capturedAt: new Date().toISOString(), tls: tlsResult },
      tags: ['tls'],
      program: context.program,
    }));
  }

  if (tlsResult.authorized === false && tlsResult.authorizationError) {
    const selfSigned = /self[- ]signed/i.test(String(tlsResult.authorizationError));
    findings.push(createFinding({
      title: selfSigned ? 'Self-signed TLS certificate' : 'TLS certificate does not validate',
      severity: selfSigned ? 'medium' : 'high',
      category: 'tls',
      target: context.target,
      description: `The TLS certificate for ${tlsResult.host} did not validate: ${tlsResult.authorizationError}.`,
      impact: 'A client that trusts the certificate cannot distinguish the real service from an interception.',
      remediation: 'Use a certificate issued by a public authority for the hostname clients connect to.',
      evidence: { capturedAt: new Date().toISOString(), tls: tlsResult },
      tags: ['tls'],
      program: context.program,
    }));
  }

  if (tlsResult.protocol && /TLSv1(\.0|\.1)?(\s|$)/.test(tlsResult.protocol)) {
    findings.push(createFinding({
      title: `Obsolete TLS protocol in use (${tlsResult.protocol})`,
      severity: 'medium',
      category: 'tls',
      target: context.target,
      description: `The service negotiated ${tlsResult.protocol}, which is deprecated.`,
      impact: 'Deprecated protocol versions have known weaknesses and are disallowed by current client policy.',
      remediation: 'Disable TLS 1.0 and 1.1 and require TLS 1.2 or later.',
      evidence: { capturedAt: new Date().toISOString(), tls: tlsResult },
      tags: ['tls'],
      program: context.program,
    }));
  }

  return findings;
}

/**
 * The built-in checks, keyed by the name a step refers to.
 */
const CHECKS = Object.freeze({
  security_headers: checkSecurityHeaders,
  info_exposure: checkInfoExposure,
  status: checkStatus,
  tls: checkTls,
});

/**
 * Runs a named check.
 *
 * @param {string} name
 * @param {object} context
 * @returns {object[]}
 */
function runCheck(name, context) {
  const check = CHECKS[name];
  if (!check) {
    return [];
  }
  const findings = check(context);
  return Array.isArray(findings) ? findings : [];
}

module.exports = {
  CHECKS,
  EXPOSURE_PATTERNS,
  SECURITY_HEADERS,
  buildEvidence,
  checkInfoExposure,
  checkSecurityHeaders,
  checkStatus,
  checkTls,
  headerValue,
  runCheck,
};
