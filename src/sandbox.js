'use strict';

/**
 * Sandboxed command execution.
 *
 * The harness runs local tools on the operator's machine. This module keeps
 * that execution predictable:
 *
 *  - Only an allowlisted executable may run. There is no pattern matching and
 *    no implicit `sh`, `cmd` or `powershell`.
 *  - Arguments are passed as an array to `execFile`, never as a shell string,
 *    so shell metacharacters are literal text and not syntax.
 *  - The working directory is forced inside the sandbox root.
 *  - The environment is built from a small allowlist, so a secret in the
 *    operator's environment is not handed to the tool.
 *  - The run has a timeout and an output cap.
 *
 * What this does *not* do: it does not provide an operating-system sandbox. A
 * tool that is allowed to run can still reach the network and the filesystem
 * the operator can reach. The sandbox is a controllable execution boundary,
 * not a jail.
 */

const path = require('node:path');
const fs = require('node:fs/promises');
const { execFile } = require('node:child_process');

/**
 * Environment variables that are passed through to a sandboxed command. They
 * are the ones a process usually cannot start without.
 */
const BASE_ENV_KEYS = Object.freeze([
  'PATH',
  'Path',
  'PATHEXT',
  'SYSTEMROOT',
  'SystemRoot',
  'COMSPEC',
  'HOME',
  'USERPROFILE',
  'TMP',
  'TEMP',
  'LANG',
  'LC_ALL',
  'TZ',
]);

class SandboxError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'SandboxError';
    this.code = code;
  }
}

class Sandbox {
  /**
   * @param {{root?: string, allowedCommands?: string[], env?: object, timeoutMs?: number, maxOutputBytes?: number}} [options]
   */
  constructor(options = {}) {
    this.root = path.resolve(options.root || process.cwd());
    this.allowedCommands = Array.isArray(options.allowedCommands)
      ? options.allowedCommands.map((command) => String(command))
      : [];
    this.env = options.env && typeof options.env === 'object' ? { ...options.env } : {};
    this.timeoutMs = Number.isFinite(options.timeoutMs) ? Number(options.timeoutMs) : 15000;
    this.maxOutputBytes = Number.isFinite(options.maxOutputBytes)
      ? Number(options.maxOutputBytes)
      : 256 * 1024;
  }

  /**
   * True when the executable is allowlisted.
   *
   * A rule that names a *program* (`nmap`, `node`) matches the base name of
   * the command, with a Windows `.exe` suffix ignored, so the rule `node`
   * allows `C:\Program Files\nodejs\node.exe`.
   *
   * A rule that names a *path* (`/usr/bin/nmap`) is bound to that exact path.
   * It is deliberately not widened to the base name, because an allowlist
   * that says `/usr/bin/nmap` means that binary and not whatever happens to
   * be called `nmap` somewhere else on the machine.
   *
   * A command that carries arguments (`nmap --script`) is never a command
   * name, so it can never match.
   *
   * @param {string} command
   * @returns {boolean}
   */
  isAllowedCommand(command) {
    if (!command || typeof command !== 'string') {
      return false;
    }

    const raw = command.trim();
    if (!raw) {
      return false;
    }

    const full = raw.toLowerCase();
    const base = path.basename(raw).toLowerCase();
    const baseWithoutExtension = base.endsWith('.exe') ? base.slice(0, -'.exe'.length) : base;

    return this.allowedCommands.some((allowed) => {
      const rule = String(allowed).trim().toLowerCase();
      if (!rule) {
        return false;
      }
      if (rule.includes('/') || rule.includes('\\')) {
        return rule === full;
      }
      return rule === base || rule === baseWithoutExtension;
    });
  }

  /**
   * Builds the environment for a sandboxed command.
   *
   * @returns {object}
   */
  buildEnv() {
    const env = {};
    for (const key of BASE_ENV_KEYS) {
      if (process.env[key] !== undefined && env[key] === undefined) {
        env[key] = process.env[key];
      }
    }
    for (const [key, value] of Object.entries(this.env)) {
      if (value === undefined || value === null) {
        continue;
      }
      env[String(key)] = String(value);
    }
    return env;
  }

  /**
   * Resolves a working directory and confirms it is inside the sandbox root.
   *
   * @param {string} [cwd]
   * @returns {Promise<string>}
   */
  async resolveCwd(cwd) {
    const base = this.root;
    const candidate = path.resolve(base, cwd || '.');
    const relative = path.relative(base, candidate);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new SandboxError(`working directory ${candidate} is outside the sandbox root`, 'E_CWD_OUTSIDE');
    }
    try {
      const real = await fs.realpath(candidate);
      const realRelative = path.relative(await fs.realpath(base), real);
      if (realRelative.startsWith('..') || path.isAbsolute(realRelative)) {
        throw new SandboxError(`working directory ${candidate} resolves outside the sandbox root`, 'E_CWD_OUTSIDE');
      }
      return real;
    } catch (error) {
      if (error instanceof SandboxError) {
        throw error;
      }
      // The directory does not exist yet; the lexical check above already
      // confirmed it is inside the root.
      return candidate;
    }
  }

  /**
   * Runs a command inside the sandbox.
   *
   * @param {string} command
   * @param {string[]} [args]
   * @param {{cwd?: string, timeoutMs?: number, input?: string}} [options]
   * @returns {Promise<{ok: boolean, code: number|null, signal: string|null, stdout: string, stderr: string, durationMs: number, error?: string}>}
   */
  async run(command, args = [], options = {}) {
    if (!this.isAllowedCommand(command)) {
      throw new SandboxError(`command ${command} is not in the sandbox allowlist`, 'E_COMMAND_NOT_ALLOWED');
    }

    const argv = Array.isArray(args) ? args.map((arg) => String(arg)) : [];
    const cwd = await this.resolveCwd(options.cwd);
    const timeout = Number.isFinite(options.timeoutMs) ? Number(options.timeoutMs) : this.timeoutMs;

    const startedAt = Date.now();

    return new Promise((resolve) => {
      execFile(
        command,
        argv,
        {
          cwd,
          env: this.buildEnv(),
          timeout,
          maxBuffer: this.maxOutputBytes,
          windowsHide: true,
          shell: false,
          encoding: 'utf8',
        },
        (error, stdout, stderr) => {
          const durationMs = Date.now() - startedAt;
          const result = {
            ok: !error,
            code: error && typeof error.code === 'number' ? error.code : (error ? 1 : 0),
            signal: error && error.signal ? error.signal : null,
            stdout: String(stdout || ''),
            stderr: String(stderr || ''),
            durationMs,
          };

          if (error) {
            if (error.killed || error.signal === 'SIGTERM') {
              result.error = `command timed out after ${timeout}ms`;
            } else if (error.code === 'ENOBUFS') {
              result.error = `command produced more than ${this.maxOutputBytes} bytes of output`;
            } else {
              result.error = error.message;
            }
          }

          resolve(result);
        }
      );
    });
  }
}

module.exports = {
  BASE_ENV_KEYS,
  Sandbox,
  SandboxError,
};
