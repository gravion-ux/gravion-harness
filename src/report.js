'use strict';

/**
 * Report generation.
 *
 * An engagement produces two artefacts from the same data: a Markdown report a
 * human reads, and a JSON report a program consumes. Both carry the evidence,
 * because a finding without evidence is an opinion.
 */

const { severityCounts, sortFindings } = require('./findings');

const SEVERITY_LABEL = Object.freeze({
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Informational',
});

/**
 * Formats a header block for the Markdown evidence section.
 *
 * @param {object} headers
 * @returns {string}
 */
function formatHeaders(headers) {
  if (!headers || typeof headers !== 'object' || Object.keys(headers).length === 0) {
    return '_No response headers captured._';
  }
  return Object.entries(headers)
    .map(([name, value]) => `- **${name}:** ${value}`)
    .join('\n');
}

/**
 * Renders the evidence of a single finding.
 *
 * @param {object} finding
 * @returns {string}
 */
function formatEvidence(finding) {
  const evidence = finding.evidence;
  if (!evidence) {
    return '_No evidence captured._';
  }

  const parts = [];

  if (evidence.request) {
    parts.push(`**Request**\n\n\`\`\`http\n${evidence.request.method || 'GET'} ${evidence.request.url || ''}\n\`\`\``);
  }

  if (evidence.response) {
    parts.push([
      '**Response**',
      '',
      '```http',
      `HTTP ${evidence.response.status ?? '—'}${evidence.response.statusText ? ` ${evidence.response.statusText}` : ''}`,
      formatHeaders(evidence.response.headers).split('\n').map((line) => line.replace(/^- /, '')).join('\n'),
      '```',
    ].join('\n'));
  }

  if (evidence.bodyExcerpt) {
    parts.push([
      '**Body excerpt**',
      '',
      '```text',
      evidence.bodyExcerpt.slice(0, 2000),
      '```',
    ].join('\n'));
  }

  if (evidence.command) {
    parts.push([
      '**Command**',
      '',
      '```bash',
      evidence.command,
      '```',
    ].join('\n'));
  }

  if (evidence.tls) {
    parts.push([
      '**TLS**',
      '',
      '```json',
      JSON.stringify(evidence.tls, null, 2),
      '```',
    ].join('\n'));
  }

  if (Array.isArray(evidence.redirects) && evidence.redirects.length) {
    parts.push([
      '**Redirect chain**',
      '',
      ...evidence.redirects.map((hop) => `- ${hop.url} → ${hop.status ?? '—'}${hop.location ? ` → ${hop.location}` : ''}`),
    ].join('\n'));
  }

  return parts.join('\n\n');
}

/**
 * Builds the report data structure.
 *
 * @param {object} input
 * @returns {object}
 */
function buildReport(input = {}) {
  const findings = sortFindings(input.findings || []);
  const counts = severityCounts(findings);

  return {
    generatedAt: new Date().toISOString(),
    engagement: {
      name: input.name || 'Gravion Harness engagement',
      objective: input.objective || '',
      program: input.program || '',
      operator: input.operator || '',
      accessMode: input.accessMode || 'smart',
      provider: input.provider || 'deterministic',
      startedAt: input.startedAt || null,
      finishedAt: input.finishedAt || null,
    },
    scope: {
      targets: input.targets || [],
      denied: input.denied || [],
      description: input.scopeDescription || '',
    },
    summary: {
      total: findings.length,
      counts,
      actionsRun: input.actionsRun || 0,
      actionsBlocked: input.actionsBlocked || 0,
      auditEntries: input.auditEntries || 0,
      auditVerified: input.auditVerified ?? null,
    },
    methodology: input.methodology || [],
    findings,
    notes: input.notes || [],
  };
}

/**
 * Renders the report as Markdown.
 *
 * @param {object} report
 * @returns {string}
 */
function renderMarkdown(report) {
  const lines = [];
  const engagement = report.engagement || {};
  const summary = report.summary || {};
  const counts = summary.counts || {};

  lines.push(`# ${engagement.name}`);
  lines.push('');
  if (engagement.objective) {
    lines.push(`**Objective:** ${engagement.objective}`);
    lines.push('');
  }
  lines.push(`**Generated:** ${report.generatedAt}`);
  lines.push(`**Access mode:** ${engagement.accessMode}`);
  lines.push(`**Model provider:** ${engagement.provider}`);
  if (engagement.program) {
    lines.push(`**Program:** ${engagement.program}`);
  }
  if (engagement.operator) {
    lines.push(`**Operator:** ${engagement.operator}`);
  }
  lines.push('');

  lines.push('## Executive summary');
  lines.push('');
  lines.push(`${summary.total} finding${summary.total === 1 ? '' : 's'} were recorded during this engagement. `
    + `${summary.actionsRun} action(s) ran and `
    + `${summary.actionsBlocked} were blocked before execution.`);
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('| --- | ---: |');
  for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
    lines.push(`| ${SEVERITY_LABEL[severity]} | ${counts[severity] || 0} |`);
  }
  lines.push('');

  const blocking = report.findings.filter((finding) => ['critical', 'high'].includes(finding.severity));
  if (blocking.length) {
    lines.push('### Needs attention first');
    lines.push('');
    for (const finding of blocking) {
      lines.push(`- **${finding.title}** — ${finding.target ? finding.target.value : 'n/a'} (${SEVERITY_LABEL[finding.severity]})`);
    }
    lines.push('');
  }

  lines.push('## Scope');
  lines.push('');
  if (report.scope && report.scope.description) {
    lines.push(report.scope.description);
    lines.push('');
  }
  const targets = (report.scope && report.scope.targets) || [];
  if (targets.length) {
    lines.push('| Target | Type | Program |');
    lines.push('| --- | --- | --- |');
    for (const target of targets) {
      lines.push(`| ${target.value} | ${target.type} | ${target.program || '—'} |`);
    }
    lines.push('');
  } else {
    lines.push('_No targets were recorded._');
    lines.push('');
  }

  const denied = (report.scope && report.scope.denied) || [];
  if (denied.length) {
    lines.push('### Blocked as out of scope');
    lines.push('');
    for (const item of denied) {
      lines.push(`- ${item.value} — ${item.reason}`);
    }
    lines.push('');
  }

  if (report.methodology && report.methodology.length) {
    lines.push('## Methodology');
    lines.push('');
    for (const item of report.methodology) {
      lines.push(`- ${item}`);
    }
    lines.push('');
  }

  lines.push('## Findings');
  lines.push('');
  if (!report.findings.length) {
    lines.push('_No findings were recorded._');
    lines.push('');
  } else {
    lines.push('| ID | Severity | Title | Target |');
    lines.push('| --- | --- | --- | --- |');
    for (const finding of report.findings) {
      lines.push(`| ${finding.id} | ${SEVERITY_LABEL[finding.severity]} | ${finding.title} | ${finding.target ? finding.target.value : '—'} |`);
    }
    lines.push('');
  }

  report.findings.forEach((finding, index) => {
    lines.push(`### ${index + 1}. ${finding.title}`);
    lines.push('');
    lines.push(`- **ID:** \`${finding.id}\``);
    lines.push(`- **Severity:** ${SEVERITY_LABEL[finding.severity]} (score ${finding.score})`);
    lines.push(`- **Category:** ${finding.category}`);
    if (finding.target) {
      lines.push(`- **Target:** ${finding.target.value}`);
    }
    if (finding.program) {
      lines.push(`- **Program:** ${finding.program}`);
    }
    lines.push(`- **Discovered:** ${finding.discoveredAt}`);
    lines.push('');

    if (finding.description) {
      lines.push('**Description**');
      lines.push('');
      lines.push(finding.description);
      lines.push('');
    }
    if (finding.impact) {
      lines.push('**Impact**');
      lines.push('');
      lines.push(finding.impact);
      lines.push('');
    }
    if (finding.steps && finding.steps.length) {
      lines.push('**Steps to reproduce**');
      lines.push('');
      finding.steps.forEach((step, stepIndex) => {
        lines.push(`${stepIndex + 1}. ${step}`);
      });
      lines.push('');
    }
    if (finding.evidence) {
      lines.push('**Evidence**');
      lines.push('');
      lines.push(formatEvidence(finding));
      lines.push('');
    }
    if (finding.remediation) {
      lines.push('**Remediation**');
      lines.push('');
      lines.push(finding.remediation);
      lines.push('');
    }
    if (finding.references && finding.references.length) {
      lines.push('**References**');
      lines.push('');
      for (const reference of finding.references) {
        lines.push(`- ${reference}`);
      }
      lines.push('');
    }
  });

  if (report.notes && report.notes.length) {
    lines.push('## Notes');
    lines.push('');
    for (const note of report.notes) {
      lines.push(`- ${note}`);
    }
    lines.push('');
  }

  lines.push('## Audit trail');
  lines.push('');
  lines.push(`The harness wrote ${summary.auditEntries} audit record${summary.auditEntries === 1 ? '' : 's'}. `
    + 'Each record is chained to the hash of the record before it, so an edit or a removal in the log is detectable.');
  if (summary.auditVerified === true) {
    lines.push('');
    lines.push('The chain was verified after the run and is intact.');
  } else if (summary.auditVerified === false) {
    lines.push('');
    lines.push('**The chain did not verify after the run. Treat this log as altered.**');
  }
  lines.push('');

  return lines.join('\n');
}

module.exports = {
  SEVERITY_LABEL,
  buildReport,
  formatEvidence,
  formatHeaders,
  renderMarkdown,
};
