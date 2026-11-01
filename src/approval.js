'use strict';

/**
 * Approval controls.
 *
 * Every action the harness wants to take carries a risk tier. The policy turns
 * that tier into one of three decisions:
 *
 *   auto  - the action may run without a human
 *   ask   - a human must approve it
 *   deny  - the action may not run at all
 *
 * The gate fails closed. An action that needs approval and has nobody to ask
 * is not approved.
 */

const RISK_TIERS = Object.freeze(['safe', 'low', 'medium', 'high', 'critical']);
const DECISIONS = Object.freeze(['auto', 'ask', 'deny']);

const TIER_ORDER = Object.freeze({
  safe: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

/**
 * Normalises a risk label to a known tier. Unknown labels are treated as the
 * most conservative tier that is not `critical`, so a new action kind cannot
 * accidentally be auto-approved by a typo.
 *
 * @param {unknown} risk
 * @returns {string}
 */
function normalizeTier(risk) {
  const tier = String(risk == null ? '' : risk).trim().toLowerCase();
  if (RISK_TIERS.includes(tier)) {
    return tier;
  }
  return 'high';
}

/**
 * True when the rule's match clause applies to the action.
 *
 * An omitted clause matches everything. A clause value may be a string, an
 * array of strings, or `*`.
 *
 * @param {object} match
 * @param {object} action
 * @returns {boolean}
 */
function matchClause(match, action) {
  const clauses = [
    ['kind', action.kind],
    ['risk', action.risk],
    ['tool', action.tool],
    ['targetType', action.target && action.target.type],
  ];

  for (const [key, actual] of clauses) {
    if (!Object.prototype.hasOwnProperty.call(match, key)) {
      continue;
    }
    const expected = match[key];
    if (expected === '*') {
      continue;
    }
    const candidates = Array.isArray(expected) ? expected : [expected];
    const normalized = candidates.map((item) => String(item).toLowerCase());
    if (!normalized.includes(String(actual == null ? '' : actual).toLowerCase())) {
      return false;
    }
  }

  return true;
}

class ApprovalPolicy {
  /**
   * @param {object} [spec]
   */
  constructor(spec = {}) {
    if (!spec || typeof spec !== 'object') {
      throw new TypeError('a policy spec must be an object');
    }

    const defaultDecision = String(spec.default || 'ask').toLowerCase();
    if (!DECISIONS.includes(defaultDecision)) {
      throw new TypeError(`unknown default decision: ${spec.default}`);
    }
    this.defaultDecision = defaultDecision;

    this.tiers = {};
    for (const [tier, decision] of Object.entries(spec.tiers || {})) {
      const normalizedTier = normalizeTier(tier);
      const normalizedDecision = String(decision).toLowerCase();
      if (!DECISIONS.includes(normalizedDecision)) {
        throw new TypeError(`unknown decision for tier ${tier}: ${decision}`);
      }
      this.tiers[normalizedTier] = normalizedDecision;
    }

    this.rules = (Array.isArray(spec.rules) ? spec.rules : []).map((rule, index) => {
      if (!rule || typeof rule !== 'object') {
        throw new TypeError(`policy rule ${index} must be an object`);
      }
      const decision = String(rule.decision || '').toLowerCase();
      if (!DECISIONS.includes(decision)) {
        throw new TypeError(`policy rule ${index} has an unknown decision: ${rule.decision}`);
      }
      return {
        match: rule.match && typeof rule.match === 'object' ? rule.match : {},
        decision,
        reason: rule.reason ? String(rule.reason) : '',
        approver: rule.approver ? String(rule.approver) : '',
      };
    });
  }

  /**
   * Builds a policy from a JSON file.
   *
   * @param {string} filePath
   * @returns {ApprovalPolicy}
   */
  static fromFile(filePath) {
    const fs = require('node:fs');
    const path = require('node:path');
    const resolved = path.resolve(filePath);
    const raw = fs.readFileSync(resolved, 'utf8');
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error(`policy file ${resolved} is not valid JSON: ${error.message}`);
    }
    return new ApprovalPolicy(parsed);
  }

  /**
   * Decides how an action should be treated.
   *
   * Rules are evaluated in order and the first match wins, which lets a policy
   * express "everything is denied except these two kinds of action".
   *
   * @param {object} action
   * @returns {{decision: string, reason: string, tier: string, rule: object|null}}
   */
  evaluate(action) {
    const tier = normalizeTier(action && action.risk);

    for (const rule of this.rules) {
      if (matchClause(rule.match, action || {})) {
        return {
          decision: rule.decision,
          reason: rule.reason || `matched policy rule (${rule.match.kind || '*'})`,
          tier,
          rule,
        };
      }
    }

    if (Object.prototype.hasOwnProperty.call(this.tiers, tier)) {
      return {
        decision: this.tiers[tier],
        reason: `risk tier ${tier} is configured as ${this.tiers[tier]}`,
        tier,
        rule: null,
      };
    }

    return {
      decision: this.defaultDecision,
      reason: `no rule or tier matched, default decision is ${this.defaultDecision}`,
      tier,
      rule: null,
    };
  }
}

class ApprovalGate {
  /**
   * @param {ApprovalPolicy} policy
   * @param {{requestApproval?: Function}} [options]
   */
  constructor(policy, options = {}) {
    if (!policy || typeof policy.evaluate !== 'function') {
      throw new TypeError('an approval gate needs a policy');
    }
    this.policy = policy;
    this.requestApproval = typeof options.requestApproval === 'function'
      ? options.requestApproval
      : null;
  }

  /**
   * Asks for approval, if that is what the policy asks for.
   *
   * @param {object} action
   * @param {object} [context]
   * @returns {Promise<{approved: boolean, decision: string, reason: string, approver: string|null, tier: string}>}
   */
  async authorize(action, context = {}) {
    const evaluation = this.policy.evaluate(action);

    if (evaluation.decision === 'deny') {
      return {
        approved: false,
        decision: 'deny',
        reason: evaluation.reason,
        approver: null,
        tier: evaluation.tier,
      };
    }

    if (evaluation.decision === 'auto') {
      return {
        approved: true,
        decision: 'auto',
        reason: evaluation.reason,
        approver: evaluation.rule && evaluation.rule.approver ? evaluation.rule.approver : 'policy',
        tier: evaluation.tier,
      };
    }

    if (!this.requestApproval) {
      // Fail closed: an action that needs a human, with no human available, is
      // not approved.
      return {
        approved: false,
        decision: 'ask',
        reason: 'approval is required but no approver is available',
        approver: null,
        tier: evaluation.tier,
      };
    }

    const answer = await this.requestApproval(action, { ...context, evaluation });
    const approved = answer === true || (answer && answer.approved === true);
    const approver = (answer && answer.approver) || context.approver || 'interactive';

    return {
      approved,
      decision: 'ask',
      reason: approved
        ? `approved by ${approver}`
        : `not approved by ${approver}`,
      approver,
      tier: evaluation.tier,
    };
  }
}

module.exports = {
  ApprovalGate,
  ApprovalPolicy,
  DECISIONS,
  RISK_TIERS,
  TIER_ORDER,
  matchClause,
  normalizeTier,
};
