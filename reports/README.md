# Evidence snapshots

Reports are generated outputs, not independent certificates. Validate the implementation version and source hash before interpreting a claim. Reports from earlier release stages remain historical evidence, not claims about the current source.

For the current 0.5 alpha source, regenerate the five profiles and four acceptance reports, then run the release audit:

```sh
python tools/run_conformance.py --profile ANO-C
python tools/run_conformance.py --profile ANO-P
python tools/run_conformance.py --profile ANO-G
python tools/run_conformance.py --profile ANO-A
python tools/run_conformance.py --profile ANO-S
python tools/run_v050_evolution_demo.py
python tools/run_v050_distributed_demo.py
python tools/run_v050_external_trust_demo.py
python tools/run_v050_federation_demo.py
python tools/audit_v050_alpha.py
```

These local demonstrations do not provision cloud services or prove cross-host federation. The stored cluster report is historical and is not a fresh cluster run. A conditionally skipped test must not be interpreted as passed verification of an unavailable capability.
