# Gravion Harness

An AI-assisted security testing harness that runs **only** against targets you
are authorised to test.

Give it a target list, an objective and a provider (a local model, a hosted
API, or the built-in offline planner). It plans the work, checks every proposed
step against your engagement scope, assigns the risk tier itself, executes the
surviving steps in a sandbox, turns the raw responses into findings with
evidence, and writes a tamper-evident audit log of every decision.

It is operated by chat and by voice, in a terminal or in a local browser
console.

**Zero runtime dependencies.** Node built-ins only. Node >= 18.

---

## The idea

Most "AI pentest" tools hand the model a shell and hope. This one keeps the
decisions in the engine:

| Decision | Made by |
| --- | --- |
| What to test | The provider (a model) proposes |
| Where it may go | The engine, against your scope — never the model |
| How risky it is | The engine, from the step kind and method |
| Whether it runs now | The access mode and your approval policy |
| How it runs | The sandbox — allowlist, no shell, filtered environment |
| What is a finding | The built-in checks, with the raw response attached |
| What happened | The hash-chained audit log |

A model that proposes a step outside your scope gets that step dropped before
it can run. A model that calls a recursive delete gets it escalated to
`critical`. The model does not get a vote on either.

## Install

```bash
git clone https://github.com/gravion-ux/gravion-harness.git
cd gravion-harness
npm install     # no dependencies; this is a formality
```

Or run it straight from the clone:

```bash
node src/cli.js --help
```

## Quick start

```bash
# 1. Write starter files (scope.json, policy.json, targets.txt)
node src/cli.js init --directory ./engagement

# 2. Put your authorised targets in engagement/targets.txt
cat > engagement/targets.txt <<'EOF'
https://app.example.com/, program=example, note=main site
api.example.com
EOF

# 3. Run an engagement
node src/cli.js run \
  --targets engagement/targets.txt \
  --objective "review the authorised targets" \
  --mode smart \
  --report engagement/report.md
```

That writes `report.md`, `report.json` and `gravion-audit.jsonl`.

## The three access modes

| Mode | Behaviour |
| --- | --- |
| `ask` | Every action waits for an explicit approval from you. Nothing runs on its own. |
| `smart` | Read-only work (`safe`, `low`) runs on its own. Anything that changes state or leaves the obvious read path is escalated for approval. **Default.** |
| `full` | Nothing is escalated. Everything inside the engagement scope runs. |

A `deny` rule in your approval policy always wins, in every mode — including
`full`. `full` relaxes *escalation*, not your own deny list.

## Where it runs

```bash
# Interactive terminal chat
node src/cli.js chat --targets engagement/targets.txt --mode smart

# Local browser console with voice control
node src/cli.js serve --targets engagement/targets.txt --port 8730
```

The browser console binds to `127.0.0.1` by default: it is an operator
console, not a service. Voice input uses the browser's own speech recognition,
so the audio never leaves the machine.

Both surfaces speak the same small command language:

```
help                      show this list
status                    current mode, targets, findings and audit state
mode ask|smart|full       change the access mode
targets                   show the engagement targets
plan <objective>          ask the provider for a plan and show the steps
run <objective>           run the engagement and collect findings
results                   show the outcome of the last engagement
findings                  list the findings collected so far
report [file]             write the Markdown report (default: report.md)
audit                     verify the audit log chain
approve / deny            answer a pending approval request
clear                     forget the collected findings
quit                      leave the chat
```

## Providers

```bash
node src/cli.js providers
```

| Provider | Use |
| --- | --- |
| `deterministic` | Built-in offline planner. No network, no key, fully reproducible. |
| `openai` | Any OpenAI-compatible API (also `ollama`, `local-api`). |
| `anthropic` | The Anthropic Messages API. |

The offline planner is the default and the one used by the test suite. Point
the harness at a hosted model when you want it to reason about the target
rather than follow a fixed read-only recipe.

```bash
node src/cli.js run --targets engagement/targets.txt \
  --provider openai --objective "review the authorised targets"
```

Provider settings come from the environment (`OPENAI_API_KEY`,
`OPENAI_BASE_URL`, `OPENAI_MODEL`, `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`) or
from the config you pass in code. A provider key is never written to the audit
log or the report — see `src/redact.js`.

## Authorisation

The target list *is* the authorisation. The harness derives the scope from it,
so you do not have to write the scope and the list separately.

`targets.txt` accepts one target per line:

```
https://app.example.com/          a URL
api.example.com                   a host
10.0.0.0/24                       a CIDR block
203.0.113.7                       an address
/srv/lab                          a local path
example.com, program=hackerone, note=main site
```

A JSON array of objects is also accepted, with `value` (or `url` / `host` /
`ip` / `cidr`), `program` and `note`.

A separate `scope.json` takes precedence when you need finer control: allow and
deny rules by `url`, `host`, `ip`, `cidr` or `path`, with scheme and port
restrictions. See `docs/USAGE.md`.

## The audit log

Every plan, scope drop, authorisation decision and execution is written to a
hash-chained JSONL log. Each record carries the hash of the record before it,
so an edit or a deletion in the log is detectable:

```bash
node src/cli.js audit --audit gravion-audit.jsonl
```

The chain is verified at the end of every engagement, and the result is stated
in the report. A broken chain is reported as a broken chain — the harness does
not quietly continue.

## What the sandbox does and does not do

The sandbox is a **controllable execution boundary, not a jail**:

- Only an allowlisted executable may run. There is no pattern matching and no
  implicit `sh`, `cmd` or `powershell`.
- Arguments are passed as an array to `execFile`, never as a shell string, so
  shell metacharacters are literal text rather than syntax.
- The working directory is forced inside the sandbox root.
- The environment is built from a small allowlist, so a secret in your
  environment is not handed to the tool.
- Every run has a timeout and an output cap.

It does **not** provide an operating-system sandbox. A tool that is allowed to
run can still reach the network and the filesystem you can reach. Run the
harness inside a container or a VM if you need that.

## Findings and evidence

Built-in checks: `security_headers`, `info_exposure`, `status`, `tls`.

Every finding keeps the raw response it came from — request, status, headers,
body excerpt, redirect chain, timing — so the report shows the evidence rather
than only the conclusion. A finding without evidence is an opinion.

## Documentation

- [`docs/USAGE.md`](docs/USAGE.md) — target lists, scope files, policies,
  providers, command reference.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — how the pieces fit together
  and why.
- [`SECURITY.md`](SECURITY.md) — threat model, reporting a vulnerability.

## Development

```bash
npm test     # 127 tests, node:test, no runner needed
npm run check  # syntax check every source file
```

The suite covers scope matching, approval policy, access modes, the audit
chain, redaction, sandbox execution, target parsing, the engine, the command
router and the local web API.

## Licence

MIT — see [`LICENSE`](LICENSE).
