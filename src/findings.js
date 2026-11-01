'use strict';

/**
 * Findings.
 *
 * A finding is the unit of output of an engagement: a title, a severity, the
 * target it was found on, the evidence that proves it, and the steps to
 * reproduce it. The evidence is stored as it was captured, so a report can be
 * checked later by someone who was not present.
 */

const crypto = require('node:crypto');

const SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);

const SEVERITY_SCORE = Object.freeze({
  critical: 9.8,
  high: 7.5,
  medium: 5.3,
  low: 3.1,
  info: 0,
});

const SEVERITY_RANK = Object.freeze({
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
});

/**
 * Normalises a severity label. Unknown labels become `info`, which keeps an
 * unrecognised value out of the top of the report.
 *
 * @param {unknown} severity
 * @returns {string}
 */
function normalizeSeverity(severity) {
  const normalized = String(severity == null ? '' : severity).trim().toLowerCase();
  return SEVERITIES.includes(normalized) ? normalized : 'info';
}

/**
 * Builds a stable identifier for a finding, so the same finding keeps the same
 * id across runs and across report formats.
 *
 * @param {object} finding
 * @returns {string}
 */
function findingId(finding) {
  const basis = [
    String(finding.title || '').trim().toLowerCase(),
    String(finding.target && finding.target.value ? finding.target.value : '').trim().toLowerCase(),
    String(finding.category || '').trim().toLowerCase(),
  ].join('|');
  return crypto.createHash('sha256').update(basis).digest('hex').slice(0, 12);
}

/**
 * Creates a finding, filling in the fields the report depends on.
 *
 * @param {object} input
 * @returns {object}
 */
function createFinding(input = {}) {
  const severity = normalizeSeverity(input.severity);
  const finding = {
    id: input.id || findingId(input),
    title: String(input.title || 'Untitled finding'),
    severity,
    score: Number.isFinite(input.score) ? input.score : SEVERITY_SCORE[severity],
    category: String(input.category || 'general'),
    target: input.target || null,
    description: String(input.description || ''),
    impact: String(input.impact || ''),
    remediation: String(input.remediation || ''),
    steps: Array.isArray(input.steps) ? input.steps.map(String) : [],
    evidence: input.evidence || null,
    references: Array.isArray(input.references) ? input.references.map(String) : [],
    tags: Array.isArray(input.tags) ? input.tags.map(String) : [],
    program: input.program ? String(input.program) : '',
    status: String(input.status || 'open'),
    discoveredAt: input.discoveredAt || new Date().toISOString(),
  };

  return finding;
}

/**
 * Sorts findings by severity, then by score, then by title.
 *
 * @param {object[]} findings
 * @returns {object[]}
 */
function sortFindings(findings) {
  return [...findings].sort((left, right) => {
    const rank = SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity];
    if (rank !== 0) {
      return rank;
    }
    if (right.score !== left.score) {
      return right.score - left.score;
    }
    return String(left.title).localeCompare(String(right.title));
  });
}

/**
 * Counts the findings per severity.
 *
 * @param {object[]} findings
 * @returns {object}
 */
function severityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    const severity = normalizeSeverity(finding.severity);
    counts[severity] += 1;
  }
  return counts;
}

/**
 * Merges a new finding into an existing list, keyed by id. A repeat finding
 * keeps the first sighting and records how often it was seen.
 *
 * @param {object[]} existing
 * @param {object} finding
 * @returns {object[]}
 */
function mergeFinding(existing, finding) {
  const index = existing.findIndex((item) => item.id === finding.id);
  if (index === -1) {
    return [...existing, finding];
  }
  const previous = existing[index];
  const merged = {
    ...previous,
    occurrences: (previous.occurrences || 1) + 1,
    lastSeenAt: finding.discoveredAt,
  };
  const copy = [...existing];
  copy[index] = merged;
  return copy;
}

module.exports = {
  SEVERITIES,
  SEVERITY_RANK,
  SEVERITY_SCORE,
  createFinding,
  findingId,
  mergeFinding,
  normalizeSeverity,
  severityCounts,
  sortFindings,
};
