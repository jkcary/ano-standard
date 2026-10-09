# ANO — Open engineering for long-running AI agents

[中文](README.zh-CN.md) · [Quickstart](docs/QUICKSTART.md) · [Contributing](CONTRIBUTING.md) · [Community tasks](docs/COMMUNITY_BACKLOG.md) · [Apache-2.0](LICENSE)

ANO (AI Native Organism) is a model-independent engineering specification and Python reference runtime for agents that must keep commitments across restarts, enforce permission boundaries and verify results before claiming completion.

**Status:** `0.5.0-alpha.4`, experimental reference implementation. The `0.4.0` reference release is the stable specification baseline. ANO is an open draft, not an established industry standard, production platform or independent security certification.

## What problem does it address?

A model can propose an action. A long-running system must also know what it owes, whether it may act, what actually happened and how to recover. ANO makes those responsibilities explicit:

- **Commitments:** persistent goals, deadlines and lifecycle state instead of relying on chat history.
- **Permissions:** deterministic authorization before actions, with bounded delegation and budgets.
- **Evidence:** distinguish tool success from verified task completion.
- **Recovery:** restore state and reject stale or duplicate work within documented backend limits.
- **Controlled updates:** evaluate candidate capabilities, approve changes and retain rollback evidence.

## Try it locally

Python 3.10+ and Git are required. No model API key is needed.

```sh
git clone https://github.com/jkcary/ano-standard.git
cd ano-standard
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
python -m pip install -e .
python tools/run_quickstart.py
```

On Windows PowerShell, use `.\.venv\Scripts\python.exe` instead of `python` for the last two commands; activation is unnecessary.

The demo abruptly exits a child process after saving a commitment, recovers it, suppresses a repeated trigger, rejects an unauthorized action and keeps the task blocked instead of falsely marking it complete. Successful output contains `"status": "passed"` and `"final_state": "blocked"`. This is intentional. It uses temporary local state and performs no external action.

See the [walkthrough and limits](docs/QUICKSTART.md). For the separate simulated action-and-verification demo and the full regression suite:

```sh
python tools/run_mvp_demo.py
python tools/run_conformance.py --profile ANO-S
```

## Where to start

| Area | Current role |
|---|---|
| Core state, commitments, permissions, evidence and recovery | Preferred starting point for review and bounded pilots |
| Framework adapters, examples and independent implementations | Community priorities; LangGraph/Temporal integrations are not shipped |
| Self-modification, external trust and federation | Experimental contracts and reference implementations with explicit limits |

Existing agent frameworks can supply planning and tool orchestration. ANO aims to provide explicit state and governance contracts around those actions. It does not require a particular model or redefine an agent transport protocol.

## Repository map

- `spec/`: Chinese normative specifications, including the 0.5 working draft.
- `schemas/`: JSON Schema catalogs for 0.3, 0.4 and 0.5.
- `state-machines/`: language-independent lifecycle definitions.
- `reference/python/ano_runtime/`: Python reference implementation.
- `examples/`: sample entities, not customer data.
- `tests/` and `tools/`: conformance suite, local demos and release audits.
- `reports/`: generated evidence snapshots; check source hashes and dates before relying on them.

The current Python package is intended for use from a source checkout with its schemas and examples present. It is not yet a standalone packaged SDK.

## Verification and limitations

The suite checks cumulative profiles `ANO-C`, `ANO-P`, `ANO-G`, `ANO-A` and `ANO-S`. Self-conformance demonstrates the reference contract; it is not a production guarantee or independent certification.

- SQLite coordination and separate local federation databases do not establish multi-host consensus or cross-region availability.
- PostgreSQL runtime, real cloud KMS/HSM, enterprise identity and federation network deployment remain unverified where declared in the implementation status.
- The basic JSONL quickstart does not demonstrate torn-write or power-loss recovery, nor exactly-once effects in external services.
- Model capability discovery and update approval do not demonstrate sustained autonomous learning or authorize unsupervised self-modification.
- Conditional test skips remain explicit. Historical reports are not evidence of a fresh run on your machine.

Read [current implementation status](V050_IMPLEMENTATION_STATUS.md), [technical boundaries](README.zh-CN.md#设计边界), and the [security policy](SECURITY.md).

## Build it with us

We are looking for real use cases, failure reproductions, framework integrations, English specification review and independent implementations. Start with the [eight community tasks](docs/COMMUNITY_BACKLOG.md), open an [issue](https://github.com/jkcary/ano-standard/issues), or submit a focused PR.

Changes to normative contracts go through a public RFC under [governance](GOVERNANCE.md). Chinese and English participation are welcome. Please read [CONTRIBUTING](CONTRIBUTING.md) and our [code of conduct](CODE_OF_CONDUCT.md).

Code, specifications, schemas and documentation are licensed under [Apache-2.0](LICENSE). Third-party dependencies retain their own licenses.
