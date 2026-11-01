'use strict';

/**
 * Local web server.
 *
 * Serves the chat and voice UI and a small JSON API on the loopback
 * interface. The server binds to 127.0.0.1 by default: it is an operator
 * console, not a service.
 *
 * The voice control uses the browser's own speech recognition, so the audio
 * never leaves the machine and no extra runtime is needed.
 */

const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');

const { createCommandRouter } = require('./commands');
const { ACCESS_MODES } = require('./access');

const DEFAULT_PORT = 8730;
const MAX_BODY_BYTES = 256 * 1024;

/**
 * Reads a JSON request body with a size limit.
 *
 * @param {object} request
 * @returns {Promise<object>}
 */
function readJson(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;

    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('request body is too large'));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });

    request.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw.trim()) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(new Error(`invalid JSON body: ${error.message}`));
      }
    });

    request.on('error', reject);
  });
}

/**
 * Sends a JSON response.
 *
 * @param {object} response
 * @param {number} status
 * @param {object} payload
 */
function sendJson(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  response.end(body);
}

/**
 * Creates the HTTP server.
 *
 * @param {object} harness
 * @param {{webRoot?: string, onEvent?: Function}} [options]
 * @returns {{server: http.Server, router: object, listen: Function, close: Function}}
 */
function createServer(harness, options = {}) {
  const webRoot = options.webRoot || path.join(__dirname, '..', 'web');
  const onEvent = typeof options.onEvent === 'function' ? options.onEvent : null;

  const router = createCommandRouter(harness, {
    onRunComplete: (result, error) => {
      if (onEvent) {
        onEvent({ type: 'run-complete', error: error || null, summary: result ? result.report.summary : null });
      }
    },
  });

  const server = http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url, 'http://127.0.0.1');

      if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
        const html = await fs.readFile(path.join(webRoot, 'index.html'), 'utf8');
        response.writeHead(200, {
          'content-type': 'text/html; charset=utf-8',
          'content-length': Buffer.byteLength(html),
          'cache-control': 'no-store',
        });
        response.end(html);
        return;
      }

      if (request.method === 'GET' && url.pathname === '/api/status') {
        const verification = await harness.audit.verify();
        sendJson(response, 200, {
          mode: harness.access.mode,
          modes: ACCESS_MODES,
          provider: harness.provider.type || 'unknown',
          targets: harness.targets,
          findings: router.state.findings.length,
          running: router.state.running,
          lastError: router.state.lastError,
          pendingApproval: router.broker.describe(),
          audit: verification,
        });
        return;
      }

      if (request.method === 'POST' && url.pathname === '/api/chat') {
        const body = await readJson(request);
        const message = String(body.message || '').trim();
        if (!message) {
          sendJson(response, 400, { error: 'message is required' });
          return;
        }
        const result = await router.handle(message);
        sendJson(response, 200, {
          reply: result.reply,
          pendingApproval: router.broker.describe(),
          running: router.state.running,
        });
        return;
      }

      if (request.method === 'POST' && url.pathname === '/api/approval') {
        const body = await readJson(request);
        const decision = String(body.decision || '').toLowerCase();
        if (decision !== 'approve' && decision !== 'deny') {
          sendJson(response, 400, { error: 'decision must be approve or deny' });
          return;
        }
        const answered = decision === 'approve'
          ? router.broker.approve(body.approver || 'operator')
          : router.broker.deny(body.approver || 'operator');
        sendJson(response, 200, { answered, pendingApproval: router.broker.describe() });
        return;
      }

      if (request.method === 'GET' && url.pathname === '/api/report') {
        if (!router.state.lastMarkdown) {
          sendJson(response, 404, { error: 'there is no report yet' });
          return;
        }
        response.writeHead(200, {
          'content-type': 'text/markdown; charset=utf-8',
          'content-length': Buffer.byteLength(router.state.lastMarkdown),
        });
        response.end(router.state.lastMarkdown);
        return;
      }

      if (request.method === 'GET' && url.pathname === '/api/findings') {
        sendJson(response, 200, { findings: router.state.findings });
        return;
      }

      sendJson(response, 404, { error: 'not found' });
    } catch (error) {
      sendJson(response, 500, { error: String(error && error.message ? error.message : error) });
    }
  });

  return {
    server,
    router,
    listen(port = DEFAULT_PORT, host = '127.0.0.1') {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          const address = server.address();
          resolve({ url: `http://${host}:${address.port}`, port: address.port });
        });
      });
    },
    close() {
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

module.exports = {
  DEFAULT_PORT,
  createServer,
  readJson,
  sendJson,
};
