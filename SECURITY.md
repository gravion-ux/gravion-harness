# Security Policy

## Reporting a vulnerability

If you find a vulnerability in the harness itself, please report it privately
rather than opening a public issue.

- Email: `priyanshukumarthakur937@gmail.com`
- GitHub: use the repository's **Security → Report a vulnerability** tab

Please include: what you found, how to reproduce it, which version or commit
you tested, and the impact you believe it has. You should get an
acknowledgement within a week.

## What the harness is for

The harness is a tool for testing systems you own or have explicit written
authorisation to test. It refuses to run a step outside the engagement scope
you supplied, and it records every decision in a hash-chained audit log.

**Only use it against targets you are authorised to test.** Testing a system
without authorisation is illegal in most jurisdictions and is not what this
tool is for.

## Threat model

The interesting threats are not "can a model run `rm -rf /`". They are:

| Threat | Mitigation |
| --- | --- |
| The model proposes a target outside the authorisation | Every step is checked against the scope before it runs. The step is dropped and recorded as `scope-block`. |
| The model proposes something destructive | The engine classifies the tool *and* its arguments; destructive patterns escalate to `critical` regardless of which tool is used. |
| A command sneaks in through the allowlist | Only allowlisted executables run. A rule that names a path is bound to that exact path; a rule that names a program matches its base name. |
| Shell metacharacters in an argument | Arguments are passed as an array to `execFile` with `shell: false`. Metacharacters are literal text. |
| The working directory escapes the sandbox root | The directory is resolved and checked, including through symlinks. |
| A secret in the environment leaks into a tool | The child environment is built from a small allowlist. |
| A secret leaks into the log or the report | Secrets are redacted by pattern and by key name before anything is written. |
| The audit log is edited afterwards | Every record carries the hash of the one before it. The chain is verified after each run and the result appears in the report. |
| The operator cannot see what was decided | Every plan, scope drop, authorisation and execution is recorded with its reason. |

### What the harness does *not* protect you from

- **It is not an operating-system sandbox.** An allowlisted tool can still
  reach the network and the filesystem you can reach. Run the harness in a
  container or a VM if that matters to you.
- **`full` mode does not ask.** It relaxes escalation inside your scope; it
  does not override your own deny rules.
- **The scope is only as good as the file you wrote.** The harness cannot tell
  an authorised target from an unauthorised one. That judgement is yours.
- **The model can still be wrong.** The engine bounds what the model can do.
  It does not make the model right.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Handling secrets in issues

Please do not include live API keys, real target URLs or personal data in a
public issue. Redact them first.
