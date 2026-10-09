from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ano_runtime import SchemaCatalog

from tests.support import STANDARD_ROOT, conformance


class MvpEndToEndConformanceTests(unittest.TestCase):
    @conformance("S-MVP-001")
    def test_one_command_mvp_demo_closes_governed_growth_and_transparency_loop(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            output = Path(directory_name) / "mvp-demo-report.json"
            completed = subprocess.run(
                [sys.executable, str(STANDARD_ROOT / "tools" / "run_mvp_demo.py"), "--output", str(output)],
                cwd=STANDARD_ROOT, capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr or completed.stdout)
            report = json.loads(output.read_text(encoding="utf-8"))
            SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0").validate("mvp-demo-report", report)
            self.assertEqual("passed", report["status"])
            self.assertEqual(
                {"governed_action", "reflection_candidate", "model_advancement", "source_transparency"},
                {item["stage"] for item in report["stages"]},
            )
            self.assertTrue(all(item["status"] == "passed" for item in report["negative_controls"]))


if __name__ == "__main__":
    unittest.main()
