from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import sys
import time
import traceback
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ano_runtime import SchemaCatalog, __version__, utc_now  # noqa: E402


def implementation_source_hash() -> str:
    """Bind a claim to the exact executable, schema, machine, manifest and test inputs."""
    paths: list[Path] = []
    for directory, pattern in (
        (ROOT / "reference" / "python", "*.py"), (ROOT / "tools", "*.py"),
        (ROOT / "schemas", "*.json"), (ROOT / "state-machines", "*.json"),
        (ROOT / "examples", "*.json"), (ROOT / "spec", "*.md"),
        (ROOT / "tests", "*.py"), (ROOT / "tests" / "manifests", "*.json"),
    ):
        paths.extend(directory.rglob(pattern))
    paths.append(ROOT / "pyproject.toml")
    digest = hashlib.sha256()
    for path in sorted(set(paths), key=lambda item: item.relative_to(ROOT).as_posix()):
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"sha256:{digest.hexdigest()}"


def conformance_id(test: unittest.TestCase) -> str:
    if not hasattr(test, "_testMethodName"):
        return "INFRA-SETUP"
    method = getattr(test, test._testMethodName)
    value = getattr(method, "conformance_id", None)
    if not value:
        raise RuntimeError(f"test has no conformance id: {test.id()}")
    return str(value)


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.records: dict[str, dict[str, Any]] = {}

    def _record(self, test: unittest.TestCase, status: str, detail: str | None = None) -> None:
        test_id = conformance_id(test)
        existing = self.records.get(test_id)
        if existing and existing["test_case"] != test.id():
            raise RuntimeError(f"duplicate conformance id: {test_id}")
        if existing and existing["status"] in {"failed", "error"} and status == "passed":
            return
        self.records[test_id] = {
            "test_id": test_id,
            "test_case": test.id(),
            "status": status,
            "detail": detail,
        }

    def addSuccess(self, test: unittest.TestCase) -> None:
        super().addSuccess(test)
        self._record(test, "passed")

    def addFailure(self, test: unittest.TestCase, err: Any) -> None:
        super().addFailure(test, err)
        self._record(test, "failed", "".join(traceback.format_exception(*err)))

    def addError(self, test: unittest.TestCase, err: Any) -> None:
        super().addError(test, err)
        self._record(test, "error", "".join(traceback.format_exception(*err)))

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:
        super().addSkip(test, reason)
        self._record(test, "skipped", reason)

    def addSubTest(self, test: unittest.TestCase, subtest: unittest.TestCase, err: Any) -> None:
        super().addSubTest(test, subtest, err)
        if err is not None:
            self._record(test, "failed", "".join(traceback.format_exception(*err)))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run an ANO cumulative conformance profile")
    parser.add_argument("--profile", choices=["ANO-C", "ANO-P", "ANO-G", "ANO-A", "ANO-S"], default="ANO-S")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with (ROOT / "tests" / "manifests" / f"{args.profile}.json").open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    required_tests = set(manifest["required_tests"])
    conditional_tests = set(manifest["conditional_tests"])

    started_at = utc_now()
    started = time.perf_counter()
    suite = unittest.defaultTestLoader.discover(
        str(ROOT / "tests"), pattern="test_*.py", top_level_dir=str(ROOT)
    )
    runner = unittest.TextTestRunner(
        verbosity=2,
        resultclass=RecordingResult,
        stream=sys.stdout,
    )
    result: RecordingResult = runner.run(suite)  # type: ignore[assignment]
    finished_at = utc_now()
    duration = round(time.perf_counter() - started, 6)

    ordered = [result.records[key] for key in sorted(result.records)]
    suite_passed = [item["test_id"] for item in ordered if item["status"] == "passed"]
    suite_failed = [item["test_id"] for item in ordered if item["status"] in {"failed", "error"}]
    suite_skipped = [item["test_id"] for item in ordered if item["status"] == "skipped"]
    passed = sorted(set(suite_passed) & required_tests)
    failed = sorted(set(suite_failed) & required_tests)
    skipped = sorted(set(suite_skipped) & required_tests)
    observed_tests = {item["test_id"] for item in ordered}
    missing_required = sorted(required_tests - observed_tests)
    invalid_skips = sorted(set(skipped) - conditional_tests)
    failed = sorted(set(failed) | set(missing_required) | set(invalid_skips))
    for test_id in missing_required:
        ordered.append(
            {
                "test_id": test_id,
                "test_case": None,
                "status": "not_run",
                "detail": "required test is missing from the suite",
            }
        )
    ordered.sort(key=lambda item: item["test_id"])
    conformant = not failed and required_tests <= (set(passed) | (set(skipped) & conditional_tests))

    claim = {
        "specification": "ANO",
        "specification_version": "0.3.0",
        "profile": manifest["profile"],
        "status": "conformant" if conformant else "partial",
        "implementation_name": "ANO Python Reference Runtime",
        "implementation_version": __version__,
        "implementation_source_hash": implementation_source_hash(),
        "test_suite_version": manifest["test_suite_version"],
        "passed_tests": passed,
        "failed_tests": failed,
        "declared_exceptions": skipped,
        "issued_at": finished_at,
    }
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.3.0")
    catalog.validate("conformance-claim", claim)

    report = {
        "report_schema": "urn:ano:report:conformance:0.5.0-alpha.4",
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": duration,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "summary": {
            "tests_run": result.testsRun,
            "passed": len(suite_passed),
            "failed": len(failed),
            "suite_failed": len(suite_failed),
            "skipped": len(suite_skipped),
            "profile_passed": len(passed),
            "required_tests": len(required_tests),
            "missing_required_tests": missing_required,
            "invalid_skips": invalid_skips,
        },
        "claim": claim,
        "results": ordered,
    }
    report_path = ROOT / "reports" / f"conformance-report-{args.profile.lower()}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = report_path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    temporary.replace(report_path)
    shutil.copyfile(report_path, ROOT / "reports" / "conformance-report.json")
    print(f"\nConformance report: {report_path}")
    return 0 if result.wasSuccessful() and conformant else 1


if __name__ == "__main__":
    raise SystemExit(main())
