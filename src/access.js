'use strict';

/**
 * Access modes.
 *
 * The harness runs with one of three access levels, chosen by the operator:
 *
 *   ask  - every action needs an explicit human approval before it runs
 *   smart- the harness decides by risk: harmless read-only work runs on its
 *          own, anything that changes state or reaches outside the obvious
 *          read path is escalated
 *   full - nothing is escalated; everything inside the engagement scope runs
 *
 * A `deny` decision from the policy always wins, in every mode. The policy is
 * the operator's own list of tools and actions they do not want run, so it is
 * honoured even in `full` mode.
 */

const ACCESS_MODES = Object.freeze(['ask', 'smart', 'full']);

/**
 * Normalises a mode name. Unknown modes fall back to `smart`, because that is
 * the mode where the operator is still in control.
 *
 * @param {unknown} mode
 * @returns {string}
 */
function normalizeMode(mode) {
  const normalized = String(mode == null ? '' : mode).trim().toLowerCase();
  return ACCESS_MODES.includes(normalized) ? normalized : 'smart';
}

/**
 * Applies an access mode on top of a risk policy.
 */
class AccessController {
  /**
   * @param {{mode?: string, policy?: object, requestApproval?: Function}} [options]
   */
  constructor(options = {}) {
    this.mode = normalizeMode(options.mode);
    this.policy = options.policy;
    this.requestApproval = typeof options.requestApproval === 'function'
      ? options.requestApproval
      : null;
  }

  /**
   * The decision the access mode would reach on its own, before the policy
   * has a say.
   *
   * @param {string} tier
   * @returns {'auto'|'ask'}
   */
  decisionForTier(tier) {
    if (this.mode === 'full') {
      return 'auto';
    }
    if (this.mode === 'ask') {
      return 'ask';
    }
    // smart
    if (tier === 'safe') {
      return 'auto';
    }
    if (tier === 'low') {
      return 'auto';
    }
    return 'ask';
  }

  /**
   * Decides whether an action may run.
   *
   * @param {object} action
   * @param {object} [context]
   * @returns {Promise<{approved: boolean, decision: string, reason: string, approver: string|null, tier: string, mode: string}>}
   */
  async authorize(action, context = {}) {
    const tier = action && action.risk ? String(action.risk) : 'safe';
    const modeDecision = this.decisionForTier(tier);

    if (this.policy && typeof this.policy.evaluate === 'function') {
      const evaluation = this.policy.evaluate(action);
      if (evaluation.decision === 'deny') {
        return {
          approved: false,
          decision: 'deny',
          reason: evaluation.reason,
          approver: null,
          tier: evaluation.tier || tier,
          mode: this.mode,
        };
      }
      // A policy that explicitly escalates or clears a tier overrides the mode
      // default for that tier, but `full` mode never escalates on its own.
      if (this.mode !== 'full' && evaluation.decision !== 'auto' && evaluation.decision !== 'ask') {
        return {
          approved: false,
          decision: 'deny',
          reason: evaluation.reason,
          approver: null,
          tier: evaluation.tier || tier,
          mode: this.mode,
        };
      }
      if (this.mode === 'smart' && evaluation.decision === 'auto') {
        return {
          approved: true,
          decision: 'auto',
          reason: evaluation.reason,
          approver: evaluation.rule && evaluation.rule.approver ? evaluation.rule.approver : 'policy',
          tier: evaluation.tier || tier,
          mode: this.mode,
        };
      }
    }

    if (modeDecision === 'auto') {
      return {
        approved: true,
        decision: 'auto',
        reason: `access mode ${this.mode} allows a ${tier} action without approval`,
        approver: `mode:${this.mode}`,
        tier,
        mode: this.mode,
      };
    }

    if (!this.requestApproval) {
      return {
        approved: false,
        decision: 'ask',
        reason: 'approval is required but no approver is available',
        approver: null,
        tier,
        mode: this.mode,
      };
    }

    const answer = await this.requestApproval(action, { ...context, tier, mode: this.mode });
    const approved = answer === true || (answer && answer.approved === true);
    const approver = (answer && answer.approver) || context.approver || 'operator';

    return {
      approved,
      decision: 'ask',
      reason: approved ? `approved by ${approver}` : `not approved by ${approver}`,
      approver,
      tier,
      mode: this.mode,
    };
  }
}

module.exports = {
  ACCESS_MODES,
  AccessController,
  normalizeMode,
};
