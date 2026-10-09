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
    parser = argparse.ArgumentParser(description="Audit the ANO MVP release artifacts and acceptance evidence")
    parser.add_argument("--output", default=str(ROOT / "reports" / "mvp-release-audit.json"))
    args = parser.parse_args()
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.3.0")
    checks: list[dict[str, str]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "status": "passed" if passed else "failed", "detail": detail})

    catalog.check_all()
    catalog_file = json.loads((ROOT / "schemas" / "v0.3.0" / "catalog.json").read_text(encoding="utf-8"))
    schema_files = sorted(path.name for path in (ROOT / "schemas" / "v0.3.0").glob("*.schema.json"))
    check("schema_catalog_complete", sorted(catalog_file["schemas"]) == schema_files, f"catalog={len(catalog_file['schemas'])}; files={len(schema_files)}")

    profile_reports: dict[str, dict[str, Any]] = {}
    current_source_hash = implementation_source_hash()
    for profile in PROFILES:
        path = ROOT / "reports" / f"conformance-report-{profile.lower()}.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        profile_reports[profile] = report
        summary = report["summary"]
        valid = (
            report["claim"]["implementation_version"] == __version__
            and report["claim"]["implementation_source_hash"] == current_source_hash
            and report["claim"]["profile"] == profile
            and summary["failed"] == 0 and summary["suite_failed"] == 0
            and not summary["missing_required_tests"] and not summary["invalid_skips"]
            and summary["profile_passed"] + summary["skipped"] == summary["required_tests"]
        )
        check(f"conformance_{profile.lower().replace('-', '_')}", valid, f"required={summary['required_tests']}; profile_passed={summary['profile_passed']}; skipped={summary['skipped']}")

    demo = json.loads((ROOT / "reports" / "mvp-demo-report.json").read_text(encoding="utf-8"))
    catalog.validate("mvp-demo-report", demo)
    check("mvp_demo_passed", demo["status"] == "passed" and demo["implementation_version"] == __version__, f"status={demo['status']}; version={demo['implementation_version']}")
    required_stages = {"governed_action", "reflection_candidate", "model_advancement", "source_transparency"}
    check("mvp_stage_coverage", {item["stage"] for item in demo["stages"]} == required_stages and all(item["status"] == "passed" for item in demo["stages"]), "four required executable stages are present and passed")
    check("negative_controls", all(item["status"] == "passed" for item in demo["negative_controls"]), f"controls={len(demo['negative_controls'])}")
    check("mvp_scope_declared", (ROOT / "MVP_RELEASE.md").exists(), "MVP_RELEASE.md exists")
    check("source_hash_bound", all(report["claim"]["implementation_source_hash"] == current_source_hash for report in profile_reports.values()), f"source_hash={current_source_hash}")

    ano_s = profile_reports["ANO-S"]["summary"]
    inventory = {
        "schemas_including_catalog": len(schema_files) + 1,
        "catalog_entries": len(catalog_file["schemas"]),
        "examples": len(list((ROOT / "examples" / "v0.3.0").glob("*.json"))),
        "state_machines": len(list((ROOT / "state-machines" / "v0.3.0").glob("*.json"))),
        "tests_run": ano_s["tests_run"], "required_tests": ano_s["required_tests"],
        "passed": ano_s["passed"], "skipped": ano_s["skipped"],
    }
    remaining = [
        {"item": "真实多租户数据库、跨地域高可用与容量工程", "classification": "productionization", "mvp_blocking": False},
        {"item": "KMS/HSM、组织身份和远程证明集成", "classification": "productionization", "mvp_blocking": False},
        {"item": "独立安全评估、渗透测试和行业合规认证", "classification": "independent_certification", "mvp_blocking": False},
        {"item": "第二语言实现及 0.4 跨实现迁移测试", "classification": "future_interoperability", "mvp_blocking": False},
    ]
    audit = {
        "audit_id": new_id("mra"), "schema_version": "0.3.0",
        "implementation_version": __version__, "audited_at": utc_now(),
        "status": "passed" if all(item["status"] == "passed" for item in checks) else "failed",
        "checks": checks, "inventory": inventory, "remaining_work": remaining,
    }
    catalog.validate("mvp-release-audit", audit)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": audit["status"], "checks": len(checks), "output": str(output)}, sort_keys=True))
    return 0 if audit["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
