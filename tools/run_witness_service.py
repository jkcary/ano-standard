from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT / "reference" / "python"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from ano_runtime import ANOError, DurableWitnessIssuer, SchemaCatalog  # noqa: E402


MAX_BODY_BYTES = 2 * 1024 * 1024


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
    parser = argparse.ArgumentParser(description="Run the ANO 0.4 authenticated external witness service")
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--runner-domain", required=True)
    parser.add_argument("--witness-domain", required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--advertise-host")
    parser.add_argument("--tls-cert", help="PEM server certificate")
    parser.add_argument("--tls-key", help="PEM server private key")
    parser.add_argument("--client-ca", help="PEM CA used to require and verify client certificates")
    parser.add_argument("--ready-file")
    return parser.parse_args()


def is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main() -> int:
    args = parse_args()
    tls_values = (args.tls_cert, args.tls_key, args.client_ca)
    if any(tls_values) and not all(tls_values):
        raise ValueError("--tls-cert, --tls-key and --client-ca must be supplied together")
    tls_enabled = all(tls_values)
    if not tls_enabled and not is_loopback(args.bind):
        raise ValueError("plaintext witness service is restricted to loopback; non-loopback binding requires mTLS")
    loaded = serialization.load_pem_private_key(Path(args.private_key).read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise TypeError("witness service key must be Ed25519")
    token = Path(args.token_file).read_text(encoding="utf-8").strip()
    if len(token) < 24:
        raise ValueError("witness bearer token must contain at least 24 characters")
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.3.0")
    issuer = DurableWitnessIssuer(
        args.state, catalog, loaded, key_id=args.key_id,
        runner_domain=args.runner_domain, witness_domain=args.witness_domain,
    )

    class Handler(BaseHTTPRequestHandler):
        server_version = "ANO-Witness/0.5.0-alpha.4"

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
            if self.path != "/healthz":
                self.send_json(404, {"error": "not_found"})
                return
            self.send_json(200, {"status": "ready", **issuer.status()})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/witness":
                self.send_json(404, {"error": "not_found"})
                return
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied, "Bearer " + token):
                self.send_json(401, {"error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_BODY_BYTES:
                    raise ValueError("request body size is invalid")
                request = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(request, dict) or set(request) != {"report"} or not isinstance(request["report"], dict):
                    raise ValueError("request must contain exactly one report object")
                envelope = issuer.issue(request["report"])
                self.send_json(200, {"envelope": envelope})
            except ANOError as exc:
                status = 409 if exc.code in {"WITNESS_CONCURRENT_WRITE", "WITNESS_RUN_REBIND"} else 422
                self.send_json(status, {"error": exc.code, "message": exc.message})
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                self.send_json(400, {"error": "invalid_request", "message": str(exc)})

    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    if tls_enabled:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=args.tls_cert, keyfile=args.tls_key)
        context.load_verify_locations(cafile=args.client_ca)
        context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
    advertised = args.advertise_host or args.bind
    if ":" in advertised and not advertised.startswith("["):
        advertised = f"[{advertised}]"
    ready = {
        "url": f"{'https' if tls_enabled else 'http'}://{advertised}:{server.server_address[1]}",
        "key_id": args.key_id, "witness_domain": args.witness_domain,
        "transport": "mtls" if tls_enabled else "loopback-http",
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
