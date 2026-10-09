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
    parser = argparse.ArgumentParser(description="Audit the ANO 0.4.0 reference release evidence")
    parser.add_argument("--output", default=str(ROOT / "reports" / "v040-release-audit.json"))
    args = parser.parse_args()
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.4.0")
    source_hash = implementation_source_hash()
    checks: list[dict[str, str]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "status": "passed" if passed else "failed", "detail": detail})

    schema_directory = ROOT / "schemas" / "v0.4.0"
    schema_catalog = json.loads((schema_directory / "catalog.json").read_text(encoding="utf-8"))
    schema_files = sorted(path.name for path in schema_directory.glob("*.schema.json"))
    catalog.check_all()
    check(
        "v040_schema_catalog", sorted(schema_catalog["schemas"]) == schema_files,
        f"declared={len(schema_catalog['schemas'])}; files={len(schema_files)}",
    )

    reports: dict[str, dict[str, Any]] = {}
    for profile in PROFILES:
        report_path = ROOT / "reports" / f"conformance-report-{profile.lower()}.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        reports[profile] = report
        summary, claim = report["summary"], report["claim"]
        manifest = json.loads((ROOT / "tests" / "manifests" / f"{profile}.json").read_text(encoding="utf-8"))
        valid = (
            claim["profile"] == profile and claim["status"] == "conformant"
            and claim["implementation_version"] == __version__
            and claim["implementation_source_hash"] == source_hash
            and claim["test_suite_version"] == "0.4.0"
            and manifest["test_suite_version"] == "0.4.0"
            and summary["failed"] == 0 and summary["suite_failed"] == 0
            and not summary["missing_required_tests"] and not summary["invalid_skips"]
        )
        check(
            f"compat_{profile.lower().replace('-', '_')}", valid,
            f"tests={summary['tests_run']}; required={summary['required_tests']}; failed={summary['failed']}",
        )

    storage_report = json.loads((ROOT / "reports" / "v040-storage-acceptance.json").read_text(encoding="utf-8"))
    catalog.validate("storage-acceptance-report", storage_report)
    check(
        "storage_acceptance",
        storage_report["status"] == "passed" and storage_report["implementation_version"] == __version__
        and storage_report["implementation_source_hash"] == source_hash
        and all(item["status"] == "passed" for item in storage_report["checks"]),
        f"status={storage_report['status']}; checks={len(storage_report['checks'])}",
    )
    kernel_report = json.loads((ROOT / "reports" / "v040-production-kernel.json").read_text(encoding="utf-8"))
    catalog.validate("production-kernel-report", kernel_report)
    check(
        "production_kernel",
        kernel_report["status"] == "passed" and kernel_report["implementation_version"] == __version__
        and kernel_report["implementation_source_hash"] == source_hash
        and all(item["status"] == "passed" for item in kernel_report["checks"]),
        f"status={kernel_report['status']}; checks={len(kernel_report['checks'])}",
    )
    specification = (ROOT / "spec" / "ANO_Specification_v0.4_Working_Draft.md").read_text(encoding="utf-8")
    status_text = (ROOT / "V040_IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    check("release_specification", "`0.4.0` Reference Release" in specification, "v0.4 specification is release marked")
    check("implementation_status", "参考生产内核已完成" in status_text, "completion boundary is declared")
    check("stable_version", __version__ == "0.4.0", f"implementation={__version__}")
    check(
        "model_independent_growth", "INV-044" in specification and "Capability Graph" in specification,
        "model advancement is an input to governed growth, not a control-plane dependency",
    )
    ano_s = reports["ANO-S"]["summary"]
    audit = {
        "audit_id": new_id("rau"), "schema_version": "0.4.0", "implementation_version": __version__,
        "implementation_source_hash": source_hash, "audited_at": utc_now(),
        "status": "passed" if all(item["status"] == "passed" for item in checks) else "failed",
        "checks": checks,
        "conformance": {key: ano_s[key] for key in (
            "tests_run", "passed", "skipped", "required_tests", "profile_passed", "failed",
        )},
        "inventory": {
            "v030_schemas": len(list((ROOT / "schemas" / "v0.3.0").glob("*.schema.json"))),
            "v040_schemas": len(schema_files),
            "state_machines": len(list((ROOT / "state-machines" / "v0.3.0").glob("*.json"))),
            "storage_checks": len(storage_report["checks"]),
            "production_kernel_checks": len(kernel_report["checks"]), "profiles": len(PROFILES),
        },
        "non_claims": [
            "not a multi-node database or consensus implementation",
            "not cross-region high availability or a production RPO/RTO certification",
            "reference KMS and IdP are not HSM, cloud KMS, OIDC or SPIFFE deployment adapters",
            "not an independent security, privacy, legal or industry certification",
            "self-conformance does not authorize unsupervised production self-modification",
        ],
    }
    catalog.validate("release-audit", audit)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": audit["status"], "checks": len(checks), "output": str(output)}, sort_keys=True))
    return 0 if audit["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
