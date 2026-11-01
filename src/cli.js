#!/usr/bin/env node
'use strict';

/**
 * The Gravion Harness command line.
 *
 * The same harness is reachable three ways: a one-shot command for a scripted
 * engagement, an interactive terminal chat, and a local web console with
 * voice input. All three use the same engine, the same scope and the same
 * audit log.
 */

const fs = require('node:fs');
const path = require('node:path');

const { Harness } = require('./engine');
const { Scope } = require('./scope');
const { ApprovalPolicy } = require('./approval');
const { ACCESS_MODES } = require('./access');
const { listProviders } = require('./providers');
const { loadTargetList, expandTargets, buildScopeSpec } = require('./targets');
const { runChat } = require('./chat');
const { createServer } = require('./server');

const DEFAULT_AUDIT_FILE = 'gravion-audit.jsonl';
const DEFAULT_REPORT_FILE = 'report.md';

const HELP_TEXT = `Gravion Harness

Usage:
  gravion-harness run    --targets <file> [--scope <file>] [--policy <file>]
                         [--objective <text>] [--mode ask|smart|full]
                         [--provider <name>] [--report <file>] [--audit <file>]
                         [--program <name>] [--operator <name>]
  gravion-harness plan   --targets <file> [--objective <text>] [--provider <name>]
  gravion-harness chat   --targets <file> [--scope <file>] [--policy <file>] [--mode ...]
  gravion-harness serve  --targets <file> [--port 8730] [--host 127.0.0.1]
  gravion-harness targets <file>
  gravion-harness audit  --audit <file>
  gravion-harness providers
  gravion-harness init   [--directory <dir>]

Access modes:
  ask    every action needs an explicit approval
  smart  read-only work runs on its own, anything else is escalated
  full   nothing is escalated, everything inside the scope runs
`;

/**
 * Parses `--flag value` and `--flag=value` arguments.
 *
 * @param {string[]} argv
 * @returns {object}
 */
function parseArgs(argv) {
  const options = {};
  const positional = [];

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument.startsWith('--')) {
      const withoutDashes = argument.slice(2);
      const equals = withoutDashes.indexOf('=');
      if (equals !== -1) {
        options[withoutDashes.slice(0, equals)] = withoutDashes.slice(equals + 1);
        continue;
      }
      const next = argv[index + 1];
      if (next === undefined || next.startsWith('--')) {
        options[withoutDashes] = true;
        continue;
      }
      options[withoutDashes] = next;
      index += 1;
      continue;
    }
    positional.push(argument);
  }

  return { options, positional };
}

/**
 * Builds a harness from the parsed options.
 *
 * @param {object} options
 * @returns {Harness}
 */
function buildHarness(options) {
  let targets = [];
  let scopeSpec = null;

  if (options.targets) {
    targets = loadTargetList(String(options.targets));
    scopeSpec = buildScopeSpec(targets, { description: `targets from ${options.targets}` });
  }

  if (options.scope) {
    scopeSpec = Scope.fromFile(String(options.scope));
  }

  const policy = options.policy ? ApprovalPolicy.fromFile(String(options.policy)) : null;
  const mode = options.mode ? String(options.mode).toLowerCase() : 'smart';

  if (!ACCESS_MODES.includes(mode)) {
    throw new Error(`unknown access mode "${mode}". Use one of: ${ACCESS_MODES.join(', ')}.`);
  }

  const provider = options.provider
    ? (String(options.provider).toLowerCase() === 'deterministic'
      ? 'deterministic'
      : { type: String(options.provider) })
    : 'deterministic';

  return new Harness({
    scope: scopeSpec || {},
    policy,
    accessMode: mode,
    audit: { path: options.audit ? String(options.audit) : DEFAULT_AUDIT_FILE, actor: options.operator ? String(options.operator) : 'harness' },
    sandbox: { root: process.cwd(), allowedCommands: options.commands ? String(options.commands).split(',') : [] },
    providerConfig: provider,
    targets: expandTargets(targets),
    program: options.program ? String(options.program) : '',
    operator: options.operator ? String(options.operator) : '',
  });
}

/**
 * Writes the starter files.
 *
 * @param {string} directory
 */
function writeStarterFiles(directory) {
  fs.mkdirSync(directory, { recursive: true });

  const scopePath = path.join(directory, 'scope.json');
  if (!fs.existsSync(scopePath)) {
    fs.writeFileSync(scopePath, `${JSON.stringify({
      description: 'Replace these entries with the targets you are authorised to test.',
      allowedSchemes: ['http', 'https'],
      allowedPorts: null,
      allow: [
        { type: 'url', value: 'https://app.example.com/', note: 'example programme' },
        { type: 'host', value: 'example.com', note: 'example programme' },
      ],
      deny: [],
    }, null, 2)}\n`, 'utf8');
  }

  const policyPath = path.join(directory, 'policy.json');
  if (!fs.existsSync(policyPath)) {
    fs.writeFileSync(policyPath, `${JSON.stringify({
      default: 'ask',
      tiers: {
        safe: 'auto',
        low: 'auto',
        medium: 'ask',
        high: 'ask',
        critical: 'deny',
      },
      rules: [
        { match: { kind: 'command' }, decision: 'ask', reason: 'local commands need a human' },
      ],
    }, null, 2)}\n`, 'utf8');
  }

  const targetsPath = path.join(directory, 'targets.txt');
  if (!fs.existsSync(targetsPath)) {
    fs.writeFileSync(targetsPath, '# One target per line.\n# https://app.example.com/\n# api.example.com\n# 10.0.0.0/24\n', 'utf8');
  }

  return { scopePath, policyPath, targetsPath };
}

/**
 * The entry point.
 *
 * @param {string[]} argv
 * @returns {Promise<number>}
 */
async function main(argv = process.argv.slice(2)) {
  const { options, positional } = parseArgs(argv);
  const command = positional[0] || 'help';

  switch (command) {
    case 'help':
    case '--help':
    case '-h':
      process.stdout.write(HELP_TEXT);
      return 0;

    case 'providers':
      process.stdout.write(`Providers: ${listProviders().join(', ')}\n`);
      return 0;

    case 'init': {
      const directory = options.directory ? String(options.directory) : '.';
      const written = writeStarterFiles(directory);
      process.stdout.write([
        `Wrote ${written.scopePath}`,
        `Wrote ${written.policyPath}`,
        `Wrote ${written.targetsPath}`,
        '',
        'Edit targets.txt with the targets you are authorised to test, then run:',
        `  gravion-harness run --targets ${path.join(directory, 'targets.txt')} --objective "review the authorised targets"`,
      ].join('\n') + '\n');
      return 0;
    }

    case 'targets': {
      const file = positional[1] || options.targets;
      if (!file) {
        process.stderr.write('usage: gravion-harness targets <file>\n');
        return 2;
      }
      const targets = expandTargets(loadTargetList(String(file)));
      process.stdout.write(`${targets.length} target(s)\n`);
      for (const target of targets) {
        process.stdout.write(`- ${target.type}: ${target.value}${target.program ? ` (${target.program})` : ''}\n`);
      }
      return 0;
    }

    case 'audit': {
      const file = options.audit ? String(options.audit) : DEFAULT_AUDIT_FILE;
      const { AuditLog } = require('./audit');
      const verification = await new AuditLog({ path: file }).verify();
      if (verification.ok) {
        process.stdout.write(`Audit chain is intact across ${verification.entries} record(s).\n`);
        return 0;
      }
      process.stderr.write(`Audit chain is BROKEN at record ${verification.brokenAt}: ${verification.reason}\n`);
      return 1;
    }

    case 'plan': {
      const harness = buildHarness(options);
      const objective = options.objective ? String(options.objective) : 'review the authorised targets';
      const plan = await harness.plan(objective);
      process.stdout.write(`Plan from ${plan.provider}${plan.model ? ` (${plan.model})` : ''}:\n`);
      for (const [index, step] of plan.steps.entries()) {
        process.stdout.write(`${index + 1}. [${step.risk}] ${step.title} → ${step.target.value}\n`);
      }
      if (plan.blocked.length) {
        process.stdout.write(`${plan.blocked.length} step(s) dropped as out of scope.\n`);
      }
      if (plan.error) {
        process.stderr.write(`provider error: ${plan.error}\n`);
      }
      return 0;
    }

    case 'run': {
      const harness = buildHarness(options);
      const objective = options.objective ? String(options.objective) : 'review the authorised targets';
      const result = await harness.run(objective);

      const reportFile = path.resolve(options.report ? String(options.report) : DEFAULT_REPORT_FILE);
      fs.writeFileSync(reportFile, result.markdown, 'utf8');
      fs.writeFileSync(path.join(path.dirname(reportFile), 'report.json'), `${JSON.stringify(result.report, null, 2)}\n`, 'utf8');

      const counts = result.report.summary.counts;
      process.stdout.write([
        `${result.report.summary.total} finding(s): critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}, info ${counts.info}`,
        `${result.report.summary.actionsRun} action(s) ran, ${result.report.summary.actionsBlocked} blocked`,
        `audit chain ${result.audit.ok ? 'intact' : 'BROKEN'} across ${result.audit.entries} record(s)`,
        `report written to ${reportFile}`,
      ].join('\n') + '\n');
      return 0;
    }

    case 'chat': {
      const harness = buildHarness(options);
      await runChat(harness);
      return 0;
    }

    case 'serve': {
      const harness = buildHarness(options);
      const app = createServer(harness);
      const port = Number(options.port || 8730);
      const host = String(options.host || '127.0.0.1');
      const address = await app.listen(port, host);
      process.stdout.write(`Gravion Harness is listening on ${address.url}\n`);
      process.stdout.write('Open that address in a browser. The mic button controls the harness by voice.\n');
      return new Promise(() => {});
    }

    default:
      process.stderr.write(`Unknown command "${command}".\n\n${HELP_TEXT}`);
      return 2;
  }
}

if (require.main === module) {
  main().then((code) => {
    if (code !== 0) {
      process.exitCode = code;
    }
  }).catch((error) => {
    process.stderr.write(`${String(error && error.message ? error.message : error)}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  HELP_TEXT,
  buildHarness,
  main,
  parseArgs,
  writeStarterFiles,
};
