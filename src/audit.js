'use strict';

/**
 * Tamper-evident audit log.
 *
 * Every decision the harness makes is written here: what was proposed, what
 * was in scope, what was approved, what ran and what it returned.
 *
 * Each record carries the hash of the previous record, so the log is a chain.
 * Removing, reordering or editing a record breaks the chain and is detected by
 * {@link AuditLog#verify}. This does not make the log impossible to forge by
 * someone who can rewrite the whole file, but it does make partial edits
 * detectable, which is what an audit trail is for.
 *
 * The log is append-only: records are only ever added.
 */

const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const { redactDeep } = require('./redact');

const GENESIS = 'GENESIS';

/**
 * Builds the canonical string that is hashed for a record. The key order is
 * fixed so the same record always produces the same digest.
 *
 * @param {object} record
 * @returns {string}
 */
function canonicalize(record) {
  const ordered = {
    seq: record.seq,
    ts: record.ts,
    actor: record.actor,
    event: record.event,
    action: record.action,
    target: record.target,
    decision: record.decision,
    approved: record.approved,
    approver: record.approver,
    reason: record.reason,
    outcome: record.outcome,
    meta: record.meta,
    prev: record.prev,
  };
  return JSON.stringify(ordered);
}

/**
 * Computes the chain hash of a record.
 *
 * @param {object} record
 * @returns {string}
 */
function hashRecord(record) {
  return crypto.createHash('sha256').update(canonicalize(record)).digest('hex');
}

class AuditLog {
  /**
   * @param {{path?: string, actor?: string, clock?: Function}} [options]
   */
  constructor(options = {}) {
    this.path = options.path ? path.resolve(options.path) : null;
    this.actor = options.actor ? String(options.actor) : 'harness';
    this.clock = typeof options.clock === 'function' ? options.clock : () => new Date();
    this.sequence = 0;
    this.lastHash = GENESIS;
  }

  /**
   * Appends a record to the log.
   *
   * @param {object} event
   * @returns {Promise<object>} the stored record
   */
  async append(event = {}) {
    this.sequence += 1;

    const now = this.clock();
    const record = {
      seq: this.sequence,
      ts: (now instanceof Date ? now : new Date()).toISOString(),
      actor: this.actor,
      event: String(event.event || 'action'),
      action: event.action ? redactDeep(event.action) : null,
      target: event.target ? redactDeep(event.target) : null,
      decision: event.decision ? String(event.decision) : null,
      approved: typeof event.approved === 'boolean' ? event.approved : null,
      approver: event.approver ? String(event.approver) : null,
      reason: event.reason ? String(event.reason) : null,
      outcome: event.outcome ? redactDeep(event.outcome) : null,
      meta: event.meta ? redactDeep(event.meta) : null,
      prev: this.lastHash,
    };

    record.hash = hashRecord(record);

    if (this.path) {
      await fs.mkdir(path.dirname(this.path), { recursive: true });
      await fs.appendFile(this.path, `${JSON.stringify(record)}\n`, 'utf8');
    }

    this.lastHash = record.hash;
    return record;
  }

  /**
   * Reads every record from the log file.
   *
   * @returns {Promise<object[]>}
   */
  async read() {
    if (!this.path) {
      return [];
    }
    let raw;
    try {
      raw = await fs.readFile(this.path, 'utf8');
    } catch (error) {
      if (error && error.code === 'ENOENT') {
        return [];
      }
      throw error;
    }

    const records = [];
    for (const line of raw.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) {
        continue;
      }
      try {
        records.push(JSON.parse(trimmed));
      } catch {
        records.push({ __unparsable: true, raw: trimmed });
      }
    }
    return records;
  }

  /**
   * Verifies the hash chain.
   *
   * @returns {Promise<{ok: boolean, entries: number, brokenAt: number|null, reason: string|null}>}
   */
  async verify() {
    const records = await this.read();

    let previous = GENESIS;
    for (let index = 0; index < records.length; index += 1) {
      const record = records[index];

      if (record.__unparsable) {
        return {
          ok: false,
          entries: records.length,
          brokenAt: index + 1,
          reason: 'record is not valid JSON',
        };
      }

      if (record.prev !== previous) {
        return {
          ok: false,
          entries: records.length,
          brokenAt: index + 1,
          reason: 'the previous-record hash does not match the record before it',
        };
      }

      const expected = hashRecord(record);
      if (record.hash !== expected) {
        return {
          ok: false,
          entries: records.length,
          brokenAt: index + 1,
          reason: 'the record hash does not match its contents',
        };
      }

      previous = record.hash;
    }

    return { ok: true, entries: records.length, brokenAt: null, reason: null };
  }
}

module.exports = {
  AuditLog,
  GENESIS,
  canonicalize,
  hashRecord,
};
