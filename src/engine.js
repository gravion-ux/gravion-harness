'use strict';

/**
 * The harness engine.
 *
 * The engine is the part that makes the harness safe to point at a real
 * target, and the part that makes it useful:
 *
 *  1. A provider proposes a plan.
 *  2. Every proposed target is checked against the engagement scope. A step
 *     outside the scope is dropped before it can run, whatever the model said.
 *  3. The engine assigns the risk tier. The provider does not get a say, so a
 *     model cannot label a state-changing request as safe.
 *  4. The access mode decides whether the step runs, needs approval, or is
 *     denied.
 *  5. The step runs in the sandbox, or as a bounded HTTP/DNS/TLS probe.
 *  6. The built-in checks turn the raw result into findings, and the evidence
 *     is kept with the finding.
 *  7. Every one of those decisions is written to the audit log.
 */

const path = require('node:path');

const { Scope } = require('./scope');
const { AccessController } = require('./access');
const { ApprovalPolicy } = require('./approval');
const { AuditLog } = require('./audit');
const { Sandbox } = require('./sandbox');
const { createProvider } = require('./providers');
const { createFinding, mergeFinding } = require('./findings');
const { runCheck } = require('./checkers');
const { probeHttp, inspectTls } = require('./probe');
const { buildReport, renderMarkdown } = require('./report');
const { loadTargetList, buildScopeSpec, expandTargets } = require('./targets');

const dns = require('node:dns').promises;

/**
 * Tools that only read. A command that uses one of these is treated as a low
 * risk read-only action.
 */
const READ_ONLY_TOOLS = Object.freeze([
  'curl', 'wget', 'http', 'httpie', 'dig', 'nslookup', 'host', 'openssl',
  'ping', 'traceroute', 'tracepath', 'whois', 'nmap', 'nikto', 'gobuster',
  'ffuf', 'feroxbuster', 'httpx', 'katana', 'subfinder', 'amass', 'waybackurls',
  'jq', 'sed', 'awk', 'grep', 'head', 'tail', 'cat', 'ls', 'dir', 'find',
  'echo', 'printf', 'true', 'false', 'id', 'whoami', 'uname', 'date', 'node',
  'python', 'python3',
]);

/**
 * Argument patterns that make a command destructive regardless of the tool.
 * These are detected so the engine can escalate them instead of treating
 * `rm` as just another read-only program.
 */
const DESTRUCTIVE_PATTERNS = Object.freeze([
  { re: /\brm\s+(-[a-z]*\s+)*-[a-z]*r/i, reason: 'recursive delete' },
  { re: /\brm\s+(-[a-z]*\s+)*-[a-z]*f/i, reason: 'forced delete' },
  { re: /\bmkfs(\.|\s)/i, reason: 'filesystem format' },
  { re: /\bdd\s+.*\bof=/i, reason: 'raw device write' },
  { re: /\bshutdown\b|\breboot\b|\bhalt\b|\bpoweroff\b/i, reason: 'host power control' },
  { re: /\bformat\s+[a-z]:/i, reason: 'disk format' },
  { re: /\bdel\s+.*\/[sf]\b/i, reason: 'forced delete' },
  { re: /\b(?:curl|wget)\b[^|]*\|\s*(?:ba)?sh\b/i, reason: 'remote script piped into a shell' },
  { re: /\bchmod\s+(-R\s+)?777\s+\//i, reason: 'world-writable root' },
  { re: /\bchown\s+-R\s+[^ ]+\s+\//i, reason: 'recursive ownership change on root' },
  { re: /\biptables\s+-F\b/i, reason: 'firewall flush' },
  { re: /:\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:/, reason: 'fork bomb' },
  { re: /\bhistory\s+-c\b|\b>\s*~\/\.bash_history\b/i, reason: 'history tampering' },
]);

/**
 * Assigns a risk tier to a step. The engine owns this decision.
 *
 * @param {object} step
 * @returns {{risk: string, reason: string}}
 */
function classifyRisk(step) {
  const kind = step && step.kind ? step.kind : 'note';

  if (kind === 'note' || kind === 'dns' || kind === 'tls') {
    return { risk: 'safe', reason: `${kind} steps only read information` };
  }

  if (kind === 'http') {
    const method = String(step.method || 'GET').toUpperCase();
    if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
      return { risk: 'low', reason: `${method} is a read-only request` };
    }
    if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
      return { risk: 'medium', reason: `${method} can change state on the target` };
    }
    return { risk: 'high', reason: `${method} can remove or replace data on the target` };
  }

  if (kind === 'command') {
    const tool = String(step.tool || '').toLowerCase();
    const args = Array.isArray(step.args) ? step.args.join(' ') : '';

    // The destructive patterns are matched against the tool *and* its
    // arguments together, because the tool alone rarely says what the
    // command does: `rm` is destructive because of what it is asked to
    // delete, and `bash -c "curl … | sh"` is destructive because of the
    // script it is asked to run.
    const commandLine = `${tool} ${args}`.trim();

    for (const pattern of DESTRUCTIVE_PATTERNS) {
      if (pattern.re.test(commandLine)) {
        return { risk: 'critical', reason: `the command looks destructive (${pattern.reason})` };
      }
    }

    const base = path.basename(tool).toLowerCase();
    if (READ_ONLY_TOOLS.includes(base)) {
      return { risk: 'low', reason: `${base} is a known read-only tool` };
    }
    return { risk: 'high', reason: `${tool || 'the tool'} is not on the read-only tool list` };
  }

  return { risk: 'medium', reason: 'the step kind is not recognised' };
}

/**
 * The harness.
 */
class Harness {
  /**
   * @param {object} [options]
   */
  constructor(options = {}) {
    this.scope = options.scope instanceof Scope ? options.scope : new Scope(options.scope || {});
    this.access = options.access instanceof AccessController
      ? options.access
      : new AccessController({
        mode: options.accessMode || options.mode || 'smart',
        policy: options.policy,
        requestApproval: options.requestApproval,
      });
    this.audit = options.audit instanceof AuditLog ? options.audit : new AuditLog(options.audit || {});
    this.sandbox = options.sandbox instanceof Sandbox ? options.sandbox : new Sandbox(options.sandbox || {});
    this.provider = options.provider && typeof options.provider.propose === 'function'
      ? options.provider
      : createProvider(options.providerConfig || {});
    this.targets = Array.isArray(options.targets) ? options.targets : [];
    this.program = options.program || '';
    this.operator = options.operator || '';
    this.clock = typeof options.clock === 'function' ? options.clock : () => new Date();
    this.maxSteps = Number.isFinite(options.maxSteps) ? options.maxSteps : 200;
  }

  /**
   * Builds a harness from files on disk.
   *
   * @param {{targets?: string, scope?: string, policy?: string, mode?: string, audit?: string, operator?: string, provider?: string, program?: string}} [options]
   * @returns {Harness}
   */
  static fromFiles(options = {}) {
    let targets = [];
    let scopeSpec = null;

    if (options.targets) {
      targets = loadTargetList(options.targets);
      scopeSpec = buildScopeSpec(targets, { description: `targets from ${options.targets}` });
    }
    if (options.scope) {
      scopeSpec = Scope.fromFile(options.scope);
    }

    const policy = options.policy ? ApprovalPolicy.fromFile(options.policy) : null;

    return new Harness({
      scope: scopeSpec || {},
      policy,
      accessMode: options.mode || 'smart',
      audit: { path: options.audit || null, actor: options.operator || 'harness' },
      sandbox: { root: options.sandboxRoot || process.cwd(), allowedCommands: options.allowedCommands || [] },
      providerConfig: options.provider || 'deterministic',
      targets: expandTargets(targets),
      program: options.program || '',
      operator: options.operator || '',
      requestApproval: options.requestApproval,
    });
  }

  /**
   * Checks a URL against the engagement scope. Used for redirect targets.
   *
   * @param {string} url
   * @returns {boolean}
   */
  isUrlInScope(url) {
    return this.scope.isAllowed({ type: 'url', value: String(url) });
  }

  /**
   * Asks the provider for a plan and validates every step against the scope.
   *
   * @param {string} objective
   * @param {object} [context]
   * @returns {Promise<{steps: object[], blocked: object[], provider: string, model: string, error: string|null}>}
   */
  async plan(objective, context = {}) {
    const result = await this.provider.propose({
      objective,
      scope: this.scope.toSpec(),
      targets: this.targets,
      context,
    });

    const steps = [];
    const blocked = [];

    for (const rawStep of result.steps || []) {
      if (steps.length >= this.maxSteps) {
        break;
      }

      const step = { ...rawStep };
      const risk = classifyRisk(step);
      step.risk = risk.risk;
      step.riskReason = risk.reason;

      const explanation = this.scope.explain(step.target);
      if (!explanation.allowed) {
        blocked.push({ step, reason: explanation.reason });
        await this.audit.append({
          event: 'scope-block',
          action: step.title,
          target: step.target,
          decision: 'deny',
          reason: explanation.reason,
          meta: { stepId: step.id, kind: step.kind, risk: step.risk },
        });
        continue;
      }

      steps.push(step);
    }

    await this.audit.append({
      event: 'plan',
      action: objective,
      decision: 'accepted',
      reason: `provider ${result.provider || 'unknown'} returned ${(result.steps || []).length} step(s)`,
      meta: {
        provider: result.provider || null,
        model: result.model || null,
        accepted: steps.length,
        blocked: blocked.length,
        error: result.error || null,
      },
    });

    return {
      steps,
      blocked,
      provider: result.provider || 'unknown',
      model: result.model || null,
      error: result.error || null,
    };
  }

  /**
   * Runs a single step.
   *
   * @param {object} step
   * @returns {Promise<{status: string, step: object, findings: object[], result?: object, reason?: string}>}
   */
  async execute(step) {
    const risk = classifyRisk(step);
    const action = { ...step, risk: risk.risk };

    const explanation = this.scope.explain(action.target);
    if (!explanation.allowed) {
      await this.audit.append({
        event: 'scope-block',
        action: action.title,
        target: action.target,
        decision: 'deny',
        reason: explanation.reason,
        meta: { stepId: action.id, kind: action.kind },
      });
      return { status: 'blocked', step: action, findings: [], reason: explanation.reason };
    }

    const decision = await this.access.authorize(action, {
      stepId: action.id,
      objective: action.title,
    });

    await this.audit.append({
      event: 'authorize',
      action: action.title,
      target: action.target,
      decision: decision.decision,
      approved: decision.approved,
      approver: decision.approver,
      reason: decision.reason,
      meta: { stepId: action.id, kind: action.kind, risk: risk.risk, mode: decision.mode },
    });

    if (!decision.approved) {
      return { status: 'blocked', step: action, findings: [], reason: decision.reason };
    }

    let result;
    try {
      result = await this.runStep(action);
    } catch (error) {
      result = { ok: false, error: String(error && error.message ? error.message : error) };
    }

    const findings = this.collectFindings(action, result);

    await this.audit.append({
      event: 'execute',
      action: action.title,
      target: action.target,
      decision: 'executed',
      outcome: {
        ok: result.ok !== false,
        status: result.status ?? null,
        durationMs: result.durationMs ?? null,
        error: result.error ?? null,
        findings: findings.length,
      },
      meta: { stepId: action.id, kind: action.kind, risk: risk.risk },
    });

    return { status: 'completed', step: action, findings, result };
  }

  /**
   * Performs the actual work of a step.
   *
   * @param {object} step
   * @returns {Promise<object>}
   */
  async runStep(step) {
    switch (step.kind) {
      case 'http': {
        const probe = await probeHttp(step.target.value, {
          method: step.method || 'GET',
          headers: step.headers,
          timeoutMs: 10000,
          validateRedirect: (url) => this.isUrlInScope(url),
        });
        return probe;
      }

      case 'tls': {
        let parsed;
        try {
          parsed = new URL(step.target.value);
        } catch {
          return { ok: false, error: 'the TLS step target is not a valid URL' };
        }
        const port = parsed.port ? Number(parsed.port) : 443;
        return inspectTls(parsed.hostname, { port });
      }

      case 'dns': {
        try {
          const addresses = await dns.resolve4(step.target.value);
          return { ok: true, addresses, host: step.target.value };
        } catch (error) {
          return { ok: false, error: String(error && error.message ? error.message : error) };
        }
      }

      case 'command': {
        const output = await this.sandbox.run(step.tool, step.args || [], { cwd: step.cwd });
        return { ...output, command: `${step.tool} ${(step.args || []).join(' ')}`.trim() };
      }

      case 'note':
      default:
        return { ok: true, note: step.rationale || '' };
    }
  }

  /**
   * Runs the checks attached to a step.
   *
   * @param {object} step
   * @param {object} result
   * @returns {object[]}
   */
  collectFindings(step, result) {
    const findings = [];
    const context = {
      probe: result,
      tls: step.kind === 'tls' ? result : (result && result.tls ? result.tls : null),
      target: step.target,
      program: this.program,
      command: result && result.command ? result.command : null,
    };

    for (const checkName of step.check || []) {
      for (const finding of runCheck(checkName, context)) {
        findings.push(finding);
      }
    }

    return findings;
  }

  /**
   * Runs a full engagement: plan, execute, collect findings, build the report.
   *
   * @param {string} objective
   * @param {object} [context]
   * @returns {Promise<object>}
   */
  async run(objective, context = {}) {
    const startedAt = this.clock().toISOString();
    const plan = await this.plan(objective, context);

    let findings = [];
    let actionsRun = 0;
    let actionsBlocked = plan.blocked.length;

    for (const step of plan.steps) {
      const outcome = await this.execute(step);
      if (outcome.status === 'completed') {
        actionsRun += 1;
      } else {
        actionsBlocked += 1;
      }
      for (const finding of outcome.findings) {
        findings = mergeFinding(findings, finding);
      }
    }

    const verification = await this.audit.verify();

    const report = buildReport({
      name: context.name || 'Gravion Harness engagement',
      objective,
      program: this.program,
      operator: this.operator,
      accessMode: this.access.mode,
      provider: plan.provider,
      startedAt,
      finishedAt: this.clock().toISOString(),
      targets: this.targets,
      denied: plan.blocked.map((item) => ({ value: item.step.target.value, reason: item.reason })),
      scopeDescription: this.scope.description,
      actionsRun,
      actionsBlocked,
      auditEntries: verification.entries,
      auditVerified: verification.ok,
      findings,
      methodology: this.describeMethodology(plan),
      notes: plan.error ? [`The provider reported: ${plan.error}`] : [],
    });

    return {
      plan,
      findings,
      report,
      markdown: renderMarkdown(report),
      audit: verification,
    };
  }

  /**
   * Describes what the engagement actually did, for the report.
   *
   * @param {object} plan
   * @returns {string[]}
   */
  describeMethodology(plan) {
    const methods = [
      `Plan produced by the ${plan.provider} provider (${plan.model || 'unknown model'}).`,
      `Access mode: ${this.access.mode}.`,
      'Every proposed target was checked against the engagement scope before it ran.',
      'Risk tiers were assigned by the engine from the step kind and method, not by the provider.',
    ];

    const kinds = new Set((plan.steps || []).map((step) => step.kind));
    if (kinds.size) {
      methods.push(`Step kinds used: ${[...kinds].sort().join(', ')}.`);
    }

    const checks = new Set();
    for (const step of plan.steps || []) {
      for (const check of step.check || []) {
        checks.add(check);
      }
    }
    if (checks.size) {
      methods.push(`Checks applied: ${[...checks].sort().join(', ')}.`);
    }

    return methods;
  }
}

/**
 * Builds a harness from a configuration object.
 *
 * @param {object} [options]
 * @returns {Harness}
 */
function createHarness(options = {}) {
  return new Harness(options);
}

module.exports = {
  DESTRUCTIVE_PATTERNS,
  Harness,
  READ_ONLY_TOOLS,
  classifyRisk,
  createFinding,
  createHarness,
};
