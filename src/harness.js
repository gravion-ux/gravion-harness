'use strict';

/**
 * Public entry point.
 *
 * Everything an operator or an embedder needs is re-exported here, so the
 * package can be used with `require('gravion-harness')` without knowing how
 * the internals are split into files.
 */

const { ACCESS_MODES, AccessController, normalizeMode } = require('./access');
const { ApprovalBroker, createCommandRouter, parseCommand } = require('./commands');
const { ApprovalGate, ApprovalPolicy, DECISIONS, RISK_TIERS } = require('./approval');
const { AuditLog, canonicalize, hashRecord } = require('./audit');
const { CHECKS, runCheck } = require('./checkers');
const { runChat } = require('./chat');
const { Harness, classifyRisk, createHarness } = require('./engine');
const { createFinding, mergeFinding, severityCounts, sortFindings } = require('./findings');
const { inspectTls, probeHttp } = require('./probe');
const { createProvider, listProviders } = require('./providers');
const { PATTERNS, redactDeep, redactSecrets } = require('./redact');
const { buildReport, renderMarkdown } = require('./report');
const { Sandbox, SandboxError } = require('./sandbox');
const { Scope } = require('./scope');
const { createServer } = require('./server');
const {
  buildScopeSpec,
  discoverHosts,
  expandTargets,
  loadTargetList,
  parseTargetList,
} = require('./targets');
const { DEFAULT_WELL_KNOWN_PATHS } = require('./wellknown');

module.exports = {
  ACCESS_MODES,
  AccessController,
  ApprovalBroker,
  ApprovalGate,
  ApprovalPolicy,
  AuditLog,
  CHECKS,
  DECISIONS,
  DEFAULT_WELL_KNOWN_PATHS,
  Harness,
  PATTERNS,
  RISK_TIERS,
  Sandbox,
  SandboxError,
  Scope,
  buildReport,
  buildScopeSpec,
  canonicalize,
  classifyRisk,
  createCommandRouter,
  createFinding,
  createHarness,
  createProvider,
  createServer,
  discoverHosts,
  expandTargets,
  hashRecord,
  inspectTls,
  listProviders,
  loadTargetList,
  mergeFinding,
  normalizeMode,
  parseCommand,
  parseTargetList,
  probeHttp,
  redactDeep,
  redactSecrets,
  renderMarkdown,
  runChat,
  runCheck,
  severityCounts,
  sortFindings,
};
