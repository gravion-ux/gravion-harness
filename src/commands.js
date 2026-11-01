'use strict';

/**
 * Command routing.
 *
 * Both the terminal chat and the local web UI speak the same small command
 * language, so the operator can switch between them without learning two
 * things. The router is also what a voice transcript ends up in: the browser
 * turns speech into text, and the text is handled here.
 */

const fs = require('node:fs/promises');
const path = require('node:path');

const { ACCESS_MODES } = require('./access');

/**
 * Holds a pending approval request.
 *
 * In `ask` mode an action stops and waits for a human. The request is parked
 * here so the operator can answer it from the terminal prompt or from the web
 * UI, whichever they are using.
 */
class ApprovalBroker {
  constructor() {
    this.pending = null;
  }

  /**
   * @param {object} action
   * @param {object} context
   * @returns {Promise<{approved: boolean, approver: string}>}
   */
  request(action, context = {}) {
    return new Promise((resolve) => {
      this.pending = {
        action,
        context,
        resolve,
        requestedAt: new Date().toISOString(),
      };
    });
  }

  /**
   * @returns {object|null} a description of the pending request
   */
  describe() {
    if (!this.pending) {
      return null;
    }
    const { action } = this.pending;
    return {
      id: action.id,
      title: action.title,
      kind: action.kind,
      risk: action.risk,
      target: action.target,
      reason: action.riskReason,
      requestedAt: this.pending.requestedAt,
    };
  }

  /**
   * @param {string} [approver]
   * @returns {boolean} true when a request was answered
   */
  approve(approver = 'operator') {
    if (!this.pending) {
      return false;
    }
    const pending = this.pending;
    this.pending = null;
    pending.resolve({ approved: true, approver });
    return true;
  }

  /**
   * @param {string} [approver]
   * @returns {boolean} true when a request was answered
   */
  deny(approver = 'operator') {
    if (!this.pending) {
      return false;
    }
    const pending = this.pending;
    this.pending = null;
    pending.resolve({ approved: false, approver });
    return true;
  }
}

/**
 * Parses a command line into a name and its argument.
 *
 * @param {string} line
 * @returns {{name: string, argument: string}}
 */
function parseCommand(line) {
  const text = String(line == null ? '' : line).trim();
  if (!text) {
    return { name: '', argument: '' };
  }
  const separator = text.search(/\s/);
  if (separator === -1) {
    return { name: text.toLowerCase(), argument: '' };
  }
  return {
    name: text.slice(0, separator).toLowerCase(),
    argument: text.slice(separator + 1).trim(),
  };
}

const HELP_TEXT = [
  'Gravion Harness — commands',
  '',
  '  help                      show this list',
  '  status                    current mode, targets, findings and audit state',
  '  mode ask|smart|full       change the access mode',
  '  targets                   show the engagement targets',
  '  plan <objective>          ask the provider for a plan and show the steps',
  '  run <objective>           run the engagement and collect findings',
  '  findings                  list the findings collected so far',
  '  report [file]             write the Markdown report (default: report.md)',
  '  audit                     verify the audit log chain',
  '  approve / deny            answer a pending approval request',
  '  clear                     forget the collected findings',
  '  quit                      leave the chat',
].join('\n');

/**
 * Creates the router.
 *
 * @param {object} harness
 * @param {{reportPath?: string}} [options]
 * @returns {object}
 */
function createCommandRouter(harness, options = {}) {
  const broker = new ApprovalBroker();
  const state = {
    findings: [],
    lastPlan: null,
    lastMarkdown: null,
    lastReport: null,
    running: false,
    lastError: null,
    runPromise: null,
  };

  const onRunComplete = typeof options.onRunComplete === 'function' ? options.onRunComplete : null;

  /**
   * Starts an engagement in the background.
   *
   * The engagement is not awaited here, because in `ask` mode it pauses on an
   * approval request and the operator has to stay able to answer it.
   *
   * @param {string} objective
   * @returns {Promise<object>}
   */
  function startRun(objective) {
    state.running = true;
    state.lastError = null;

    state.runPromise = harness.run(objective)
      .then((result) => {
        state.findings = result.findings;
        state.lastMarkdown = result.markdown;
        state.lastReport = result.report;
        state.running = false;
        if (onRunComplete) {
          onRunComplete(result);
        }
        return result;
      })
      .catch((error) => {
        state.running = false;
        state.lastError = String(error && error.message ? error.message : error);
        if (onRunComplete) {
          onRunComplete(null, state.lastError);
        }
        throw error;
      });

    // The rejection is handled by the caller through `state.lastError`; keep
    // it from surfacing as an unhandled rejection.
    state.runPromise.catch(() => {});

    return state.runPromise;
  }

  if (harness.access) {
    harness.access.requestApproval = (action, context) => broker.request(action, context);
  }

  /**
   * Handles one command line.
   *
   * @param {string} line
   * @returns {Promise<{reply: string, data?: object}>}
   */
  async function handle(line) {
    const { name, argument } = parseCommand(line);

    switch (name) {
      case '':
        return { reply: '' };

      case 'help':
      case '?':
        return { reply: HELP_TEXT };

      case 'status': {
        const verification = await harness.audit.verify();
        return {
          reply: [
            `access mode: ${harness.access.mode}`,
            `provider: ${harness.provider.type || 'unknown'}`,
            `targets: ${harness.targets.length}`,
            `findings: ${state.findings.length}`,
            `audit records: ${verification.entries} (${verification.ok ? 'chain intact' : 'CHAIN BROKEN'})`,
            broker.pending ? `pending approval: ${broker.pending.action.title}` : 'pending approval: none',
          ].join('\n'),
          data: {
            mode: harness.access.mode,
            targets: harness.targets.length,
            findings: state.findings.length,
            audit: verification,
            pendingApproval: broker.describe(),
          },
        };
      }

      case 'mode': {
        const mode = argument.toLowerCase();
        if (!ACCESS_MODES.includes(mode)) {
          return { reply: `unknown mode. Use one of: ${ACCESS_MODES.join(', ')}.` };
        }
        harness.access.mode = mode;
        return { reply: `access mode is now ${mode}.`, data: { mode } };
      }

      case 'targets': {
        if (!harness.targets.length) {
          return { reply: 'No targets are loaded. Start the harness with a target list.' };
        }
        const lines = harness.targets.map((target) => `- ${target.type}: ${target.value}${target.program ? ` (${target.program})` : ''}`);
        return { reply: lines.join('\n'), data: { targets: harness.targets } };
      }

      case 'plan': {
        if (!argument) {
          return { reply: 'Usage: plan <objective>' };
        }
        const plan = await harness.plan(argument);
        state.lastPlan = plan;
        if (!plan.steps.length) {
          return {
            reply: [
              `The provider returned no usable in-scope step${plan.error ? ` (${plan.error})` : ''}.`,
              plan.blocked.length ? `${plan.blocked.length} step(s) were dropped as out of scope.` : '',
            ].filter(Boolean).join('\n'),
            data: { plan },
          };
        }
        const lines = plan.steps.map((step, index) => {
          const blocked = plan.blocked[index];
          return `${index + 1}. [${step.risk}] ${step.title} → ${step.target.value}`;
        });
        return {
          reply: [
            `Plan from ${plan.provider}${plan.model ? ` (${plan.model})` : ''}:`,
            ...lines,
            plan.blocked.length ? `${plan.blocked.length} step(s) were dropped as out of scope.` : '',
          ].filter(Boolean).join('\n'),
          data: { plan },
        };
      }

      case 'run': {
        if (!argument) {
          return { reply: 'Usage: run <objective>' };
        }
        startRun(argument);
        return {
          reply: `Engagement started: ${argument}\nUse "approve" or "deny" if an approval is requested, and "results" to see the outcome.`,
          data: { started: true },
        };
      }

      case 'results': {
        if (state.running) {
          return { reply: 'The engagement is still running.' };
        }
        if (state.lastError) {
          return { reply: `The engagement failed: ${state.lastError}` };
        }
        if (!state.lastMarkdown) {
          return { reply: 'There is no result yet. Run an engagement first.' };
        }
        const counts = state.lastReport.summary.counts;
        return {
          reply: [
            `Engagement finished. ${state.lastReport.summary.total} finding(s).`,
            `critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}, info ${counts.info}`,
            `${state.lastReport.summary.actionsRun} action(s) ran, ${state.lastReport.summary.actionsBlocked} were blocked.`,
          ].join('\n'),
          data: { summary: state.lastReport.summary, findings: state.findings },
        };
      }

      case 'findings': {
        if (!state.findings.length) {
          return { reply: 'No findings have been collected yet.' };
        }
        const lines = state.findings.map((finding) => (
          `- [${finding.severity}] ${finding.title} (${finding.target ? finding.target.value : 'n/a'})`
        ));
        return { reply: lines.join('\n'), data: { findings: state.findings } };
      }

      case 'report': {
        if (!state.lastMarkdown) {
          return { reply: 'There is no report yet. Run an engagement first.' };
        }
        const target = path.resolve(argument || options.reportPath || 'report.md');
        await fs.writeFile(target, state.lastMarkdown, 'utf8');
        return { reply: `Report written to ${target}.`, data: { path: target } };
      }

      case 'audit': {
        const verification = await harness.audit.verify();
        return {
          reply: verification.ok
            ? `Audit chain is intact across ${verification.entries} record(s).`
            : `Audit chain is BROKEN at record ${verification.brokenAt}: ${verification.reason}`,
          data: verification,
        };
      }

      case 'approve': {
        const approved = broker.approve();
        return {
          reply: approved ? 'Approved.' : 'There is no pending approval request.',
          data: { pending: broker.describe() },
        };
      }

      case 'deny': {
        const denied = broker.deny();
        return {
          reply: denied ? 'Denied.' : 'There is no pending approval request.',
          data: { pending: broker.describe() },
        };
      }

      case 'clear': {
        state.findings = [];
        state.lastMarkdown = null;
        state.lastReport = null;
        state.lastPlan = null;
        return { reply: 'Cleared.' };
      }

      case 'quit':
      case 'exit':
        return { reply: 'Goodbye.', data: { quit: true } };

      default:
        return { reply: `Unknown command "${name}". Type "help" for the list.` };
    }
  }

  return {
    broker,
    handle,
    startRun,
    state,
    helpText: HELP_TEXT,
  };
}

module.exports = {
  ApprovalBroker,
  HELP_TEXT,
  createCommandRouter,
  parseCommand,
};
