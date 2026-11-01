# Usage

## Command line

```
gravion-harness run    --targets <file> [--scope <file>] [--policy <file>]
                       [--objective <text>] [--mode ask|smart|full]
                       [--provider <name>] [--report <file>] [--audit <file>]
                       [--program <name>] [--operator <name>]
                       [--commands <a,b,c>]
gravion-harness plan   --targets <file> [--objective <text>] [--provider <name>]
gravion-harness chat   --targets <file> [--scope <file>] [--policy <file>] [--mode ...]
gravion-harness serve  --targets <file> [--port 8730] [--host 127.0.0.1]
gravion-harness targets <file>
gravion-harness audit  --audit <file>
gravion-harness providers
gravion-harness init   [--directory <dir>]
```

| Flag | Meaning |
| --- | --- |
| `--targets` | The target list. This is the authorisation. |
| `--scope` | A scope file, which takes precedence over the derived scope. |
| `--policy` | An approval policy file. |
| `--objective` | What the engagement is for. |
| `--mode` | `ask`, `smart` (default) or `full`. |
| `--provider` | `deterministic`, `openai` or `anthropic`. |
| `--report` | Where the Markdown report goes. Default `report.md`. |
| `--audit` | Where the audit log goes. Default `gravion-audit.jsonl`. |
| `--commands` | Comma-separated sandbox allowlist, e.g. `curl,nmap`. |
| `--program`, `--operator` | Recorded in the report and the audit log. |

`run` writes both `report.md` and `report.json` next to the report file.

## Target lists

One target per line. Blank lines and lines starting with `#` are ignored.

```
https://app.example.com/
api.example.com
10.0.0.0/24
203.0.113.7
/srv/lab
example.com, program=hackerone, note=main site
```

Each line may carry attributes after the value:

| Attribute | Meaning |
| --- | --- |
| `program` | The programme or engagement this target belongs to. |
| `note` | A free-text note. May contain spaces. |
| `type` | Force the type: `url`, `host`, `ip`, `cidr`, `path`. |
| `url`, `host`, `ip`, `cidr`, `target` | Give the value explicitly instead of inferring it. |

A segment with no key continues the previous value, so
`example.com, note=main site, staging` keeps both words in the note. A value
may be quoted to hold a comma: `example.com, note="main, staging"`.

A JSON file (`.json`) is also accepted. It may hold an array of objects or an
array of strings:

```json
[
  { "url": "https://app.example.com/", "program": "example" },
  "api.example.com"
]
```

### What the target list becomes

The list is the authorisation, and the scope is derived from it:

- A CIDR block expands into individual addresses (up to 256 by default).
- A URL also yields its host.
- Duplicates are removed; the original order is kept.

## Scope files

Use `--scope` when you need finer control than a target list gives you. A
`scope.json`:

```json
{
  "description": "Staging environment for the example programme.",
  "allowedSchemes": ["https"],
  "allowedPorts": [443, 8443],
  "allow": [
    { "type": "url", "value": "https://app.example.com/", "note": "main site" },
    { "type": "host", "value": "api.example.com" },
    { "type": "cidr", "value": "198.51.100.0/24" }
  ],
  "deny": [
    { "type": "host", "value": "payments.example.com" }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `type` | `url`, `host`, `ip`, `cidr` or `path`. |
| `value` | The rule. A `host` rule matches the host and its subdomains. |
| `note` | Free text, carried into the report. |
| `allowedSchemes` | Schemes a URL may use. Default `http` and `https`. |
| `allowedPorts` | Ports a URL may use. `null` means any port. |
| `deny` | Checked before `allow`. A deny always wins. |

Deny rules are checked first, so a host that appears in both lists is denied.

## Approval policies

A policy turns a risk tier into a decision. `policy.json`:

```json
{
  "default": "ask",
  "tiers": {
    "safe": "auto",
    "low": "auto",
    "medium": "ask",
    "high": "ask",
    "critical": "deny"
  },
  "rules": [
    { "match": { "kind": "command" }, "decision": "ask", "reason": "local commands need a human" },
    { "match": { "tool": "nmap" }, "decision": "auto", "reason": "nmap is on the approved list" },
    { "match": { "risk": "critical" }, "decision": "deny", "reason": "never destructive" }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `default` | The decision when nothing else matches. Default `ask`. |
| `tiers` | A decision per risk tier. |
| `rules` | Rules matched against the action. The first matching rule wins. |
| `rule.match` | `kind`, `risk`, `tool` and `targetType`. A value may be a string, an array of strings, or `*`. An omitted clause matches everything. |
| `rule.decision` | `auto`, `ask` or `deny`. |
| `rule.reason` | Recorded in the audit log. |
| `rule.approver` | Optional name recorded when the rule auto-approves. |

A `deny` decision wins in every access mode, including `full`.

## Risk tiers

The engine assigns the tier, not the provider.

| Tier | Assigned to |
| --- | --- |
| `safe` | Notes, DNS lookups, TLS inspection. |
| `low` | `GET`, `HEAD`, `OPTIONS` requests; known read-only tools. |
| `medium` | `POST`, `PUT`, `PATCH`; an unrecognised step kind. |
| `high` | `DELETE` and other destructive methods; a tool that is not on the read-only list. |
| `critical` | A command that looks destructive, whatever tool it uses. |

A command is matched against the destructive patterns using its tool *and* its
arguments together, so `rm -rf /srv`, `bash -c "curl … | sh"` and
`mkfs /dev/sda` are all `critical`.

## Providers

```bash
node src/cli.js providers
```

| Name | Notes |
| --- | --- |
| `deterministic` | The offline planner. No network, no key, reproducible. Also reachable as `offline` or `local`. |
| `openai` | Any OpenAI-compatible endpoint. Also `openai-compatible`, `ollama`, `local-api`. |
| `anthropic` | The Anthropic Messages API. Also `claude`. |

### Environment

| Variable | Used by |
| --- | --- |
| `GRAVION_HARNESS_PROVIDER` | The default provider when none is given. |
| `GRAVION_HARNESS_API_KEY` | The OpenAI-compatible API key. |
| `OPENAI_API_KEY` | The OpenAI-compatible API key (fallback). |
| `GRAVION_HARNESS_BASE_URL` | The API base URL. |
| `GRAVION_HARNESS_MODEL` | The model name. |
| `ANTHROPIC_API_KEY` | The Anthropic API key. |

Defaults: `https://api.openai.com/v1` with `gpt-4o-mini`;
`https://api.anthropic.com` with `claude-sonnet-4-20250514`.

A key is never written to the audit log or the report.

## Running it from code

```js
const { createHarness, buildReport } = require('gravion-harness');

const harness = createHarness({
  scope: {
    allow: [{ type: 'host', value: 'example.com' }],
  },
  accessMode: 'smart',
  providerConfig: 'deterministic',
  sandbox: { root: process.cwd(), allowedCommands: ['curl'] },
  audit: { path: 'audit.jsonl', actor: 'priya' },
  program: 'example',
  operator: 'priya',
});

const result = await harness.run('review the authorised targets');
console.log(result.markdown);
console.log(result.audit.ok); // the chain verified
```

A provider of your own can be passed straight through — anything with a
`propose(request)` method works:

```js
const harness = createHarness({
  provider: {
    type: 'my-provider',
    async propose(request) {
      return { steps: [], provider: 'my-provider', model: 'mine' };
    },
  },
});
```

## The web console

```bash
node src/cli.js serve --targets engagement/targets.txt --port 8730
```

| Route | Method | Purpose |
| --- | --- | --- |
| `/` | GET | The chat and voice UI. |
| `/api/status` | GET | Mode, provider, targets, findings, audit state. |
| `/api/chat` | POST | Run one command line. Body: `{ "message": "…" }`. |
| `/api/approval` | POST | Answer a pending approval. Body: `{ "decision": "approve" \| "deny" }`. |
| `/api/findings` | GET | The collected findings. |
| `/api/report` | GET | The Markdown report. |

The server binds to `127.0.0.1` by default. It has no authentication, so do
not bind it to a public interface.

## The audit log

JSONL, one record per line, hash-chained:

```bash
node src/cli.js audit --audit gravion-audit.jsonl
```

Event types: `plan`, `scope-block`, `authorize`, `execute`.

Each record carries `event`, `action`, `target`, `decision`, `reason`, `meta`,
`timestamp`, `actor`, `previous` and `hash`. `verify()` recomputes the chain;
a mismatch reports the record number where it broke.
