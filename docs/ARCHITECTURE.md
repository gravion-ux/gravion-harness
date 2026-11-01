# Architecture

## The shape of it

```
                    ┌──────────────┐
   operator ───────▶│  chat / web  │  command language
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │   commands   │  router + approval broker
                    └──────┬───────┘
                           │
   ┌───────────────────────▼───────────────────────┐
   │                    engine                      │
   │                                                │
   │   plan ──▶ scope ──▶ classify ──▶ authorise    │
   │     ▲                                  │        │
   │     │                                  ▼        │
   │  provider                          execute      │
   │  (model)                            │  │  │     │
   │                                     ▼  ▼  ▼     │
   │                                  sandbox probe  │
   │                                     │  │  │     │
   │                                     ▼  ▼  ▼     │
   │                                   checks        │
   │                                     │          │
   │                                     ▼          │
   │                              findings ──▶ report │
   │                                     │          │
   └─────────────────────────────────────┼──────────┘
                                           ▼
                                     audit chain
```

## The one idea

The model proposes. The engine disposes.

A provider returns a list of steps. The engine then, for every step:

1. **Checks the scope** (`scope.js`). A step whose target is not covered by an
   allow rule, or that hits a deny rule, is dropped and recorded as
   `scope-block`. It never reaches the executor, whatever the model said.
2. **Assigns the risk tier** (`engine.js`). The provider cannot set it. A step
   kind it does not recognise becomes `medium`; a destructive command becomes
   `critical`.
3. **Authorises the action** (`access.js`, `approval.js`). The access mode and
   the policy turn the tier into run / ask / deny. A `deny` wins in every mode.
4. **Runs it** (`sandbox.js` for commands, `probe.js` for HTTP and TLS).
5. **Turns the result into findings** (`checkers.js`), each carrying the raw
   response as evidence.
6. **Records the decision** (`audit.js`).

Each of those is a separate module with a narrow interface, so the provider can
be swapped without touching the safety machinery, and the safety machinery can
be tested without a model.

## The modules

| Module | Responsibility |
| --- | --- |
| `scope.js` | Matching a target against allow/deny rules. Pure functions. |
| `approval.js` | Risk tier → decision, plus rules matched against the action. |
| `access.js` | The three modes, layered over the policy. |
| `audit.js` | The hash-chained log and its verification. |
| `sandbox.js` | Allowlisted, shell-free command execution. |
| `probe.js` | Bounded HTTP requests and TLS inspection. |
| `targets.js` | Target list parsing, expansion and discovery. |
| `findings.js` | Finding identity, severity and merging. |
| `checkers.js` | The built-in checks. Plain functions over a context. |
| `report.js` | The Markdown and JSON reports. |
| `redact.js` | Secret redaction, by pattern and by key name. |
| `engine.js` | The harness: the flow above. |
| `commands.js` | The shared command language and the approval broker. |
| `chat.js`, `server.js` | The two surfaces that speak that language. |
| `cli.js` | Argument parsing and the command dispatch. |
| `providers/` | Turning an objective into steps. |

## Design decisions

**The provider never gets a vote.** Risk is assigned by the engine from the
step kind and method. A provider that labels a `DELETE` as read-only is
ignored.

**Destructive patterns are matched against tool *and* arguments.** The tool
alone rarely says what a command does. `rm` with `-rf` is destructive;
`rm --version` is not. Scanning only the arguments missed the case where the
destructive part *is* the tool.

**The sandbox allowlist distinguishes programs from paths.** A rule that names
a program (`node`) matches the base name of the command, with a Windows `.exe`
suffix ignored. A rule that names a path (`/usr/bin/nmap`) is bound to that
exact path — widening it to the base name would let any binary called `nmap`
anywhere on the machine run, which is not what the rule said.

**The approval gate fails closed.** An action that needs approval and has
nobody to ask is not approved. In `ask` mode with no approver attached, the
action is blocked rather than run.

**`full` relaxes escalation, not the deny list.** `full` means "don't ask me
about risk". It does not mean "ignore what I told you never to do".

**The audit chain is append-only and hash-linked.** Each record carries the
hash of the record before it, so removing or editing a record is detectable.
The chain is verified after each run and the result is stated in the report —
a broken chain is reported, not hidden.

**Evidence travels with the finding.** `checkers.js` attaches the request, the
status, the headers, a body excerpt, the redirect chain and the timing to
every finding it creates. A report that shows only conclusions is an opinion.

**The web console has no authentication.** It binds to `127.0.0.1` and is an
operator console. Adding auth would mean shipping a credential path to a tool
that holds the operator's API keys; the loopback binding is the simpler and
safer boundary. Do not bind it to a public interface.

**Zero runtime dependencies.** Node built-ins only. The value of this tool is
the safety machinery, and a dependency is a supply-chain risk in the thing
whose job is to run code. It also means the harness runs on any machine with
Node 18+, with no install step and no lockfile to rot.

## The flow of an engagement

```
harness.run(objective)
  │
  ├─ provider.propose({ objective, scope, targets, context })
  │     └─ steps[], blocked[]
  │
  ├─ for each step:
  │     ├─ classifyRisk(step)           → safe | low | medium | high | critical
  │     ├─ scope.explain(step.target)    → allowed | denied (+ reason)
  │     │     └─ denied ──▶ audit 'scope-block', skip
  │     ├─ access.authorize(step)        → auto | ask | deny
  │     │     └─ not approved ──▶ audit 'authorize', stop
  │     ├─ runStep(step)                 → sandbox | probe | dns | tls
  │     ├─ collectFindings(step, result) → checkers
  │     └─ audit 'execute'
  │
  ├─ audit.verify()
  └─ buildReport(...) + renderMarkdown(...)
```

## Testing

127 tests with `node:test`, no runner and no coverage tooling. The suite
covers each module's contract and the engine's decisions, including the
boundary cases that matter:

- A scope rule that matches a host but not a sibling.
- A deny rule that wins over an allow rule.
- A destructive command reached through an unusual tool (`bash -c "curl … | sh"`).
- A sandbox allowlist entry that is a path rather than a program.
- A working directory that tries to escape the root.
- A secret under a credential-shaped key at several nesting depths.
- A tampered audit record.
- An approval request answered from the command language.

Every defect that was found during development was reproduced as a failing
test first, then fixed. The suite was the specification, not a description of
the implementation.
