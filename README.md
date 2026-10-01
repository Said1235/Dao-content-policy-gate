# DAO Governance Content Policy Gate

GenLayer Intelligent Contract that checks a governance proposal (by URL) against a fixed list of content rules. Validators fetch the proposal independently and agree on which rules it violates and on the hash of the exact text they read. It handles no funds, tokens or votes.

## Files

- `contracts/content_policy_gate.py` – classic runner (`1jb45aa8…`)
- `contracts/content_policy_gate_v2.py` – new runner (`5jycge4q…`, Studio `v0.123.0-rc.x`)

Same logic. If Studio says "Could not load contract schema", use the other file.

## Use (Studio)

1. **Deploy** – no inputs needed.
2. `initialize_policy` (once, deployer only):
   - `policy_version`: `policy-v1`
   - `rules_json`: `["The proposal must not contain spam or advertising.","The proposal must not promote illegal activity.","The proposal must not harass or insult any person or group."]`
3. `request_audit(proposal_id, proposal_url, request_nonce)` – use a commit-pinned raw URL and a new nonce each time.
4. `derive_audit_id(requester, proposal_id, request_nonce)` → `get_audit(audit_id)`.
   `violated_rule_ids: []` means compliant.

Look audits up by `audit_id` and check `requester` and `proposal_url`; `proposal_id` is only a label.

## Test

```bash
pip install genlayer-test==0.29.2 genvm-linter==0.11.1rc2 cloudpickle pytest requests
genvm-lint check contracts/content_policy_gate.py
pytest tests/direct

# second file needs its own environment
pip install genlayer-test==0.30.0rc2 genvm-linter==0.11.1rc2 cloudpickle pytest requests
GATE_CONTRACT=contracts/content_policy_gate_v2.py pytest tests/direct
```

`tests/integration` needs a network with validators and has not been run on Studio:
`GATE_CONTRACT=contracts/content_policy_gate.py gltest tests/integration -v -s --network <network>`

## License

MIT
