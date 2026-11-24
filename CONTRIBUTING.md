# Contributing to Gravion Harness

Thanks for helping! Gravion Harness is an AI-assisted security
testing harness that runs **only** against targets you are authorised
to test. It plans the work, checks every proposed step against the
engagement scope, assigns the risk tier itself, executes surviving
steps in a sandbox, and writes a tamper-evident audit log of every
decision.

The most valuable contributions are new checkers, scope/approval
hardening, and tests — especially tests that prove an out-of-scope
step is refused.

## Ground rules

- **Authorised targets only — hard rule.** The scope check is the
  product. Contributions must never weaken scope enforcement,
  approval gates or the sandbox to make a run "work".
- **Zero runtime dependencies — hard rule.** Node.js built-ins only.
- **Every decision stays auditable.** New execution paths must write
  to the audit log in the existing format; a step that cannot be
  logged must not run.

## Development setup

Requires Node.js 20 or newer. There is nothing to install:

```bash
git clone https://github.com/gravion-ux/gravion-harness.git
cd gravion-harness
npm test
```

## Running the tests

```bash
npm run check   # syntax-check every source file
npm test        # node --test — the full suite
```

CI runs both on Node 20 and 22.

## Code style

- Plain Node.js, no build step. If you add a source file under
  `src/`, add it to the `check` script in `package.json` — the
  syntax gate lists files explicitly.
- Tests use the built-in `node --test` runner and live in `test/`.
- Comments explain *why* a scope rule, risk tier or approval gate
  exists.

## Proposing a bigger change

Changes to the scope model, risk-tier assignment, sandboxing or the
audit format: **open an issue first**. Checkers, tests, fixes and
documentation can go straight to a pull request.

## Pull request workflow

1. Fork and branch from `main`: `feat/<short-name>`,
   `fix/<short-name>`, `checker/<name>`, `docs/<short-name>`.
2. Run `npm run check` and the full suite locally.
3. Open the PR against `main` with: what changed, why, how you
   tested it — and for anything touching execution, which scope and
   audit behaviour you verified.
4. CI must be green. One logical change per PR.
