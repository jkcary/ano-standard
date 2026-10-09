from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT / "reference" / "python"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from ano_runtime import SchemaCatalog, __version__, new_id, utc_now  # noqa: E402
from run_conformance import implementation_source_hash  # noqa: E402


PROFILES = ("ANO-C", "ANO-P", "ANO-G", "ANO-A", "ANO-S")


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit the ANO 0.5 Alpha.4 release evidence")
    parser.add_argument("--output", default=str(ROOT / "reports" / "v050-alpha-audit.json"))
    args = parser.parse_args()
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.5.0")
    source_hash = implementation_source_hash()
    checks: list[dict[str, str]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "status": "passed" if passed else "failed", "detail": detail})

    schema_directory = ROOT / "schemas" / "v0.5.0"
    schema_catalog = json.loads((schema_directory / "catalog.json").read_text(encoding="utf-8"))
    schema_files = sorted(path.name for path in schema_directory.glob("*.schema.json"))
    catalog.check_all()
    check(
        "v050_schema_catalog", sorted(schema_catalog["schemas"]) == schema_files,
        f"declared={len(schema_catalog['schemas'])}; files={len(schema_files)}",
    )
    reports: dict[str, dict[str, Any]] = {}
    for profile in PROFILES:
        report = json.loads((ROOT / "reports" / f"conformance-report-{profile.lower()}.json").read_text(encoding="utf-8"))
        reports[profile] = report
        summary, claim = report["summary"], report["claim"]
        valid = (
            claim["profile"] == profile and claim["status"] == "conformant"
            and claim["implementation_version"] == __version__
            and claim["implementation_source_hash"] == source_hash
            and claim["test_suite_version"] == "0.5.0-alpha.4"
            and summary["failed"] == 0 and summary["suite_failed"] == 0
            and not summary["missing_required_tests"] and not summary["invalid_skips"]
        )
        check(
            f"compat_{profile.lower().replace('-', '_')}", valid,
            f"tests={summary['tests_run']}; required={summary['required_tests']}; failed={summary['failed']}",
        )
    acceptance = json.loads((ROOT / "reports" / "v050-evolution-acceptance.json").read_text(encoding="utf-8"))
    catalog.validate("evolution-acceptance-report", acceptance)
    check(
        "evolution_acceptance",
        acceptance["status"] == "passed" and acceptance["implementation_version"] == __version__
        and acceptance["implementation_source_hash"] == source_hash
        and all(item["status"] == "passed" for item in acceptance["checks"]),
        f"status={acceptance['status']}; checks={len(acceptance['checks'])}",
    )
    distributed = json.loads((ROOT / "reports" / "v050-distributed-acceptance.json").read_text(encoding="utf-8"))
    catalog.validate("distributed-acceptance-report", distributed)
    check(
        "distributed_acceptance",
        distributed["status"] == "passed" and distributed["implementation_version"] == __version__
        and distributed["implementation_source_hash"] == source_hash
        and not distributed["postgres_runtime_verified"]
        and all(item["status"] == "passed" for item in distributed["checks"]),
        f"status={distributed['status']}; checks={len(distributed['checks'])}; postgres_runtime=false",
    )
    external_trust = json.loads((ROOT / "reports" / "v050-external-trust-acceptance.json").read_text(encoding="utf-8"))
    catalog.validate("external-trust-acceptance-report", external_trust)
    check(
        "external_trust_acceptance",
        external_trust["status"] == "passed" and external_trust["implementation_version"] == __version__
        and external_trust["implementation_source_hash"] == source_hash
        and not external_trust["cloud_runtime_verified"]
        and all(item["status"] == "passed" for item in external_trust["checks"]),
        f"status={external_trust['status']}; checks={len(external_trust['checks'])}; cloud_runtime=false",
    )
    federation = json.loads((ROOT / "reports" / "v050-federation-acceptance.json").read_text(encoding="utf-8"))
    catalog.validate("federation-acceptance-report", federation)
    check(
        "federation_acceptance",
        federation["status"] == "passed" and federation["implementation_version"] == __version__
        and federation["implementation_source_hash"] == source_hash
        and not federation["network_runtime_verified"]
        and all(item["status"] == "passed" for item in federation["checks"]),
        f"status={federation['status']}; checks={len(federation['checks'])}; network_runtime=false",
    )
    roadmap = (ROOT / "V050_ROADMAP.md").read_text(encoding="utf-8")
    specification = (ROOT / "spec" / "ANO_Specification_v0.5_Working_Draft.md").read_text(encoding="utf-8")
    status_text = (ROOT / "V050_IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    check("roadmap", "Governed Self-Growing Cluster" in roadmap, "0.5 completion stages and non-claims are declared")
    check("working_specification", "INV-081" in specification, "Alpha.1 through Alpha.4 invariants are specified")
    check("implementation_status", "联邦增长层" in status_text, "implemented Alpha.4 boundary is declared")
    check("version", __version__ == "0.5.0-alpha.4", f"implementation={__version__}")
    ano_s_manifest = json.loads((ROOT / "tests" / "manifests" / "ANO-S.json").read_text(encoding="utf-8"))
    check(
        "v040_compatibility", "O-RC-001" in ano_s_manifest["required_tests"],
        "0.4 production-kernel requirements remain cumulative",
    )
    check(
        "model_independent_growth", "V-MOD-001" in ano_s_manifest["required_tests"] and "INV-055" in specification,
        "model advancement remains candidate-only under deterministic evolution gates",
    )
    ano_s = reports["ANO-S"]["summary"]
    audit = {
        "audit_id": new_id("vaa"), "schema_version": "0.5.0",
        "implementation_version": __version__, "implementation_source_hash": source_hash,
        "audited_at": utc_now(), "status": "passed" if all(item["status"] == "passed" for item in checks) else "failed",
        "checks": checks,
        "conformance": {key: ano_s[key] for key in (
            "tests_run", "passed", "skipped", "required_tests", "profile_passed", "failed",
        )},
        "inventory": {
            "v030_schemas": len(list((ROOT / "schemas" / "v0.3.0").glob("*.schema.json"))),
            "v040_schemas": len(list((ROOT / "schemas" / "v0.4.0").glob("*.schema.json"))),
            "v050_schemas": len(schema_files),
            "state_machines": len(list((ROOT / "state-machines" / "v0.3.0").glob("*.json"))),
            "evolution_checks": len(acceptance["checks"]),
            "distributed_checks": len(distributed["checks"]),
            "external_trust_checks": len(external_trust["checks"]), "profiles": len(PROFILES),
            "federation_checks": len(federation["checks"]),
        },
        "non_claims": [
            "not a PostgreSQL or multi-node consensus implementation",
            "reference KMS and identity emulators are not cloud KMS, HSM, enterprise OIDC or SPIRE deployment certification",
            "signed provenance policy is not an independent supply-chain security certification",
            "federation tests use separate local databases and do not certify real multi-host transport or consensus",
            "not cross-region recovery or long-duration capacity certification",
            "candidate generation does not authorize unsupervised production self-modification",
        ],
    }
    catalog.validate("alpha-release-audit", audit)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": audit["status"], "checks": len(checks), "output": str(output)}, sort_keys=True))
    return 0 if audit["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
