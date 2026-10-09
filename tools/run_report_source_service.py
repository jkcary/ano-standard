from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT / "reference" / "python"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from ano_runtime import (  # noqa: E402
    ClusterValidationEvidenceVerifier, SchemaCatalog, create_cluster_report_source_envelope,
)


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run an ANO 0.4 signed read-only report source")
    parser.add_argument("--report", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--source-domain", required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--ready-file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.3.0")
    ClusterValidationEvidenceVerifier(catalog).verify(report)
    loaded = serialization.load_pem_private_key(Path(args.private_key).read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise TypeError("report source key must be Ed25519")
    envelope = create_cluster_report_source_envelope(
        report, loaded, key_id=args.key_id, source_id=args.source_id, source_domain=args.source_domain,
    )
    expected_path = "/v1/reports/" + quote(str(report["run_id"]), safe="")

    class Handler(BaseHTTPRequestHandler):
        server_version = "ANO-Report-Source/0.5.0-alpha.4"

        def log_message(self, format: str, *values: object) -> None:
            return

        def send_json(self, status: int, value: dict[str, Any]) -> None:
            body = json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self.send_json(200, {"status": "ready", "source_id": args.source_id})
            elif self.path == expected_path:
                self.send_json(200, {"report": report, "source_envelope": envelope})
            else:
                self.send_json(404, {"error": "not_found"})

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    ready = {
        "url": f"http://127.0.0.1:{server.server_address[1]}",
        "run_id": report["run_id"], "source_id": args.source_id,
    }
    if args.ready_file:
        atomic_json(Path(args.ready_file), ready)
    print(json.dumps(ready, sort_keys=True), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
