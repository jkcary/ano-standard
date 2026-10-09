from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT / "reference" / "python"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from ano_runtime import KubectlDeploymentProvider, SchemaCatalog, sha256_json, utc_now  # noqa: E402


SCENARIOS = [
    "cluster.deploy", "security.no_token", "security.read_only_root",
    "security.tmp_writable", "network.egress_denied", "fault.pod_recovery",
    "rollback.resources_removed",
]


def command(args: list[str], *, input_text: str | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=timeout, check=False)


def kubectl(context: str, namespace: str | None, *args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    values = ["kubectl", "--context", context]
    if namespace is not None:
        values.extend(["--namespace", namespace])
    values.extend(args)
    return command(values, timeout=timeout)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the ANO Alpha.8 isolated Kubernetes validation lab")
    parser.add_argument("--context", required=True, help="Explicit kubectl context")
    parser.add_argument("--image", required=True, help="Digest-pinned BusyBox-compatible image")
    parser.add_argument("--cluster-type", required=True)
    parser.add_argument("--cluster-runtime-version", required=True)
    parser.add_argument("--network-policy-provider", required=True)
    parser.add_argument("--network-policy-version", required=True)
    parser.add_argument("--network-policy-manifest-sha256", required=True)
    parser.add_argument("--report", default=str(ROOT / "reports" / "cluster-validation-report.json"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    suffix = uuid.uuid4().hex[:8]
    namespace = f"ano-alpha8-{suffix}"
    run_id = f"lab_{suffix}"
    started_at = utc_now()
    states: dict[str, dict[str, str]] = {
        item: {"scenario_id": item, "status": "skipped", "evidence": "not reached"} for item in SCENARIOS
    }
    cleanup = {"attempted": False, "verified": False}
    provider: KubectlDeploymentProvider | None = None
    receipt: dict[str, Any] | None = None
    failure: Exception | None = None

    try:
        created = kubectl(args.context, None, "create", "namespace", namespace)
        if created.returncode != 0:
            raise RuntimeError(created.stderr.strip() or "namespace creation failed")
        labeled = kubectl(args.context, None, "label", "namespace", namespace, f"ano.dev/lab-run={run_id}", "--overwrite")
        if labeled.returncode != 0:
            raise RuntimeError(labeled.stderr.strip() or "namespace labeling failed")

        digest = args.image.rsplit("@", 1)[-1]
        provider = KubectlDeploymentProvider(
            context=args.context, namespace=namespace, dry_run=False,
            command=["/bin/sh", "-c", "sleep 3600"],
        )
        request = {
            "deployment_id": f"can_alpha8_{suffix}", "artifact_ref": args.image,
            "artifact_hash": digest,
            "isolation_execution_hash": sha256_json({"run_id": run_id, "context": args.context, "namespace": namespace}),
        }
        receipt = provider.stage(request)
        name = receipt["external_ref"].rsplit("/", 1)[-1]
        rollout = kubectl(args.context, namespace, "rollout", "status", f"deployment/{name}", "--timeout=90s", timeout=100)
        if rollout.returncode != 0:
            raise RuntimeError(rollout.stderr.strip() or rollout.stdout.strip() or "candidate rollout failed")
        states["cluster.deploy"] = {"scenario_id": "cluster.deploy", "status": "passed", "evidence": rollout.stdout.strip()[-512:]}

        pod_result = kubectl(args.context, namespace, "get", "pods", "-l", f"app.kubernetes.io/name={name}", "-o", "jsonpath={.items[0].metadata.name}")
        pod = pod_result.stdout.strip()
        if pod_result.returncode != 0 or not pod:
            raise RuntimeError(pod_result.stderr.strip() or "candidate pod not found")

        no_token = kubectl(args.context, namespace, "exec", pod, "--", "/bin/sh", "-c", "test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token")
        states["security.no_token"] = {
            "scenario_id": "security.no_token", "status": "passed" if no_token.returncode == 0 else "failed",
            "evidence": "service account token absent" if no_token.returncode == 0 else (no_token.stderr.strip() or "token exists"),
        }

        root_write = kubectl(args.context, namespace, "exec", pod, "--", "/bin/sh", "-c", "touch /ano-root-write-probe")
        states["security.read_only_root"] = {
            "scenario_id": "security.read_only_root", "status": "passed" if root_write.returncode != 0 else "failed",
            "evidence": "root filesystem write denied" if root_write.returncode != 0 else "unexpected root filesystem write succeeded",
        }

        tmp_write = kubectl(args.context, namespace, "exec", pod, "--", "/bin/sh", "-c", "echo ano-ok >/tmp/probe && test \"$(cat /tmp/probe)\" = ano-ok")
        states["security.tmp_writable"] = {
            "scenario_id": "security.tmp_writable", "status": "passed" if tmp_write.returncode == 0 else "failed",
            "evidence": "bounded temporary volume writable" if tmp_write.returncode == 0 else (tmp_write.stderr.strip() or "temporary write failed"),
        }

        network = kubectl(args.context, namespace, "exec", pod, "--", "/bin/sh", "-c", "wget -T 5 -qO- http://example.com >/dev/null")
        states["network.egress_denied"] = {
            "scenario_id": "network.egress_denied", "status": "passed" if network.returncode != 0 else "failed",
            "evidence": "external HTTP request denied" if network.returncode != 0 else "unexpected external HTTP request succeeded",
        }

        deleted = kubectl(args.context, namespace, "delete", "pod", pod, "--wait=true", "--timeout=60s", timeout=70)
        replacement = ""
        if deleted.returncode == 0:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                candidate = kubectl(args.context, namespace, "get", "pods", "-l", f"app.kubernetes.io/name={name}", "-o", "jsonpath={.items[0].metadata.name}")
                replacement = candidate.stdout.strip()
                ready = kubectl(args.context, namespace, "get", "pod", replacement, "-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}") if replacement else None
                if replacement and replacement != pod and ready is not None and ready.stdout.strip() == "True":
                    break
                time.sleep(1)
        recovered = bool(replacement and replacement != pod)
        states["fault.pod_recovery"] = {
            "scenario_id": "fault.pod_recovery", "status": "passed" if recovered else "failed",
            "evidence": f"replacement pod: {replacement}" if recovered else "controller did not replace deleted pod",
        }

        provider.rollback(receipt)
        deployment_absent = kubectl(args.context, namespace, "get", "deployment", name)
        policy_absent = kubectl(args.context, namespace, "get", "networkpolicy", name + "-deny-all")
        removed = deployment_absent.returncode != 0 and policy_absent.returncode != 0
        states["rollback.resources_removed"] = {
            "scenario_id": "rollback.resources_removed", "status": "passed" if removed else "failed",
            "evidence": "deployment and network policy removed" if removed else "rollback left cluster resources",
        }
    except Exception as exc:
        failure = exc
    finally:
        cleanup["attempted"] = True
        deleted_namespace = kubectl(args.context, None, "delete", "namespace", namespace, "--wait=true", "--timeout=90s", timeout=100)
        absent = kubectl(args.context, None, "get", "namespace", namespace)
        cleanup["verified"] = deleted_namespace.returncode == 0 and absent.returncode != 0

    statuses = [item["status"] for item in states.values()]
    status = "passed" if all(item == "passed" for item in statuses) and cleanup["verified"] else "failed"
    if failure is not None:
        for item in states.values():
            if item["status"] == "skipped":
                item["evidence"] = f"blocked by: {failure}"
    version = kubectl(args.context, None, "version", "-o", "json")
    kubernetes_version = "unknown"
    if version.returncode == 0:
        kubernetes_version = json.loads(version.stdout)["serverVersion"]["gitVersion"]
    report = {
        "run_id": run_id, "schema_version": "0.3.0", "harness_version": "0.3.0-alpha.8",
        "context": args.context, "namespace": namespace, "image_ref": args.image,
        "environment": {
            "cluster_type": args.cluster_type,
            "cluster_runtime_version": args.cluster_runtime_version,
            "kubernetes_version": kubernetes_version,
            "network_policy_provider": args.network_policy_provider,
            "network_policy_version": args.network_policy_version,
            "network_policy_manifest_sha256": args.network_policy_manifest_sha256,
        },
        "started_at": started_at, "finished_at": utc_now(), "scenarios": list(states.values()),
        "cleanup": cleanup, "status": status,
    }
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.3.0")
    catalog.validate("cluster-validation-report", report)
    output = Path(args.report)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
