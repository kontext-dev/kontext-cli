# Baseline Model

`coding-agent-v0.json` is the initial Markov-chain risk model shipped with Kontext Guard.

Scope:

- Claude Code and coding-agent workflows
- normal coding actions
- normal source-control flows such as `git` and `gh`
- redacted event sequences, not raw prompts or secrets

The model estimates sequence risk. Deterministic rules remain authoritative for obvious security risk such as credential access, direct provider API calls with observed credentials, and destructive infrastructure operations.

Future versions can be shipped as updated parameter files and promoted only after local evaluation improves.
