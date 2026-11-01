# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-10-29

First release.

### Added

- **Engagement scope** (`src/scope.js`) — allow/deny rules for URLs, hosts,
  IPv4 addresses, CIDR blocks and local paths, with scheme and port
  restrictions. Every proposed step is checked against it before it can run.
- **Access modes** (`src/access.js`) — `ask`, `smart` and `full`. A `deny`
  decision from the approval policy wins in every mode, including `full`.
- **Approval policy** (`src/approval.js`) — per-risk-tier decisions and rules
  matched against the action, loaded from JSON.
- **Audit chain** (`src/audit.js`) — hash-chained JSONL log covering the plan,
  every scope drop, every authorisation decision and every execution, with
  verification at the end of a run.
- **Sandbox** (`src/sandbox.js`) — allowlisted executables only, arguments as
  an array, the working directory forced inside the sandbox root, a filtered
  environment, a timeout and an output cap.
- **Engine** (`src/engine.js`) — plans, validates, assigns the risk tier,
  authorises, executes and collects findings. The engine, not the provider,
  assigns the risk tier; destructive command patterns escalate to `critical`.
- **Target lists** (`src/targets.js`) — plain-text and JSON target files, CIDR
  expansion, URL-to-host expansion and optional host discovery. The target
  list is the authorisation: the scope is derived from it.
- **Probes** (`src/probe.js`) — bounded HTTP requests with redirect validation
  and TLS inspection.
- **Checks** (`src/checkers.js`) — `security_headers`, `info_exposure`,
  `status` and `tls`, each attaching the raw response as evidence.
- **Findings** (`src/findings.js`) — stable identifiers, severity handling and
  merging of repeated findings.
- **Reports** (`src/report.js`) — a Markdown report for a human and a JSON
  report for a program, both carrying the evidence and the audit state.
- **Redaction** (`src/redact.js`) — pattern and key-based redaction of secrets
  before anything is written to a log or a report.
- **Providers** (`src/providers/`) — an offline deterministic planner, an
  OpenAI-compatible provider and an Anthropic provider.
- **Command router** (`src/commands.js`) — one command language shared by the
  terminal chat, the voice transcript and the web console, with a broker for
  pending approvals.
- **Terminal chat** (`src/chat.js`) and **local web console**
  (`src/server.js`, `web/index.html`) — chat and voice operation, bound to the
  loopback interface by default.
- **CLI** (`src/cli.js`) — `run`, `plan`, `chat`, `serve`, `targets`, `audit`,
  `providers` and `init`.
- **Tests** — 127 tests over scope, approval, access, audit, redaction,
  sandbox, targets, engine, providers, findings, reports, the command router
  and the web API.

[0.1.0]: https://github.com/gravion-ux/gravion-harness/releases/tag/v0.1.0
