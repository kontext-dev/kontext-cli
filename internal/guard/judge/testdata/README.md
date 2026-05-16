# Local Judge Launch Fixtures

`launch-v0.jsonl` is the launch evaluation target for the local Guard judge.

Each line describes one `PreToolUse` scenario, the normalized fields the judge
should receive, deterministic policy context, and the expected final judge
behavior.

The fixtures intentionally test the prompt contract, not the current
normalizer's full coverage. Some normalized fields are richer than the current
runtime extracts today so prompt and model evaluation can move ahead while
deterministic policy coverage evolves separately.

## Contract

The judge input includes:

- agent and hook metadata
- redacted command/path/request summaries
- normalized operation, provider, resource, environment, credential, and signal fields
- deterministic policy decision and policy version

The judge input excludes:

- full conversation history
- model reasoning
- raw secrets
- unredacted credential values
- full tool responses
- hosted Kontext account or tenant data

The judge output must contain only:

```json
{
  "decision": "allow",
  "risk_level": "low",
  "categories": ["normal_coding"],
  "reason": "short explanation"
}
```

`decision` must be `allow` or `deny`. `ask` is not part of the launch contract.
