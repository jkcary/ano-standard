from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Callable

from .errors import ANOError
from .schema import SchemaCatalog
from .state_machine import StateMachine
from .util import new_id, sha256_json, utc_now


class ReflectionEngine:
    """Creates evidence-linked candidates; it has no production mutation method."""

    def __init__(self, catalog: SchemaCatalog) -> None:
        self.catalog = catalog
        self.reflections: dict[str, dict[str, Any]] = {}
        self.proposals: dict[str, dict[str, Any]] = {}

    def reflect(
        self,
        *,
        run_id: str,
        subject_ids: list[str],
        expected: str,
        observed: str,
        root_cause: str,
        lesson: str,
        source_event_ids: list[str],
        update_type: str,
        target_id: str,
        baseline: Any,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        reflection_id = new_id("ref")
        reflection = {
            "reflection_id": reflection_id, "schema_version": "0.3.0", "version": 1,
            "run_id": run_id, "subject_ids": subject_ids, "expected_outcome": expected,
            "observed_outcome": observed, "deviation": f"expected={expected}; observed={observed}",
            "root_cause_class": root_cause, "lesson": lesson, "confidence": 0.9,
            "proposed_updates": [{"update_type": update_type, "target_id": target_id}],
            "source_event_ids": source_event_ids, "created_at": utc_now(), "status": "proposal_generated",
        }
        self.catalog.validate("reflection", reflection)
        proposal_id = new_id("chg")
        level = {"memory": "L2_MEMORY", "policy": "L3_POLICY", "skill": "L4_SKILL", "structure": "L5_STRUCTURE", "routing": "L5_STRUCTURE"}[update_type]
        proposal = {
            "proposal_id": proposal_id, "schema_version": "0.3.0", "version": 1,
            "proposer_id": "ano_reflection_engine", "change_level": level, "target_components": [target_id],
            "motivation": lesson, "evidence_ids": [reflection_id, *source_event_ids],
            "patch_artifact_ref": f"artifact://candidate/{proposal_id}", "expected_benefits": {},
            "possible_harms": ["unintended_behavior_change"], "evaluation_plan_id": "eval_plan_standard",
            "rollback_plan_id": "rollback_standard", "requested_permissions": ["deploy_to_staging"],
            "baseline_hash": sha256_json(baseline), "status": "proposed",
        }
        self.catalog.validate("change-proposal", proposal)
        self.reflections[reflection_id] = copy.deepcopy(reflection)
        self.proposals[proposal_id] = copy.deepcopy(proposal)
        return copy.deepcopy(reflection), copy.deepcopy(proposal)


class LearningLineage:
    def __init__(self, catalog: SchemaCatalog) -> None:
        self.catalog = catalog
        self.sources: dict[str, dict[str, Any]] = {}
        self.assets: dict[str, dict[str, str]] = {}

    def register_source(self, source: dict[str, Any]) -> None:
        self.catalog.validate("learning-source", source)
        self.sources[str(source["source_id"])] = copy.deepcopy(source)

    def authorize_memory_write(self, source_id: str) -> None:
        source = self.sources[source_id]
        if source["sensitivity"] in {"confidential", "restricted"} and not source["consent_ref"]:
            raise ANOError("LEARNING_CONSENT_REQUIRED", "sensitive source has no learning consent")
        if source["status"] != "active" or source["contamination_risk"] in {"high", "malicious"}:
            raise ANOError("LEARNING_SOURCE_REJECTED", "source is withdrawn or contaminated")

    def register_derived(self, source_id: str, asset_id: str, asset_type: str) -> None:
        source = self.sources[source_id]
        if asset_id not in source["derived_asset_ids"]:
            source["derived_asset_ids"].append(asset_id)
        self.assets[asset_id] = {"asset_type": asset_type, "status": "active", "source_id": source_id}

    def withdraw(self, source_id: str, *, malicious: bool = False) -> tuple[str, ...]:
        source = self.sources[source_id]
        source["status"] = "quarantined" if malicious else "withdrawn"
        if malicious:
            source["contamination_risk"] = "malicious"
        invalidated = []
        for asset_id in source["derived_asset_ids"]:
            if asset_id in self.assets:
                self.assets[asset_id]["status"] = "invalidated"
                invalidated.append(asset_id)
        return tuple(sorted(invalidated))


class SealedEvaluationSuite:
    """Holdout answers and pass thresholds remain outside the candidate interface."""

    def __init__(
        self,
        catalog: SchemaCatalog,
        *,
        suite_id: str,
        holdout: list[dict[str, Any]],
        minimum_accuracy: float,
        maximum_cost_delta: float,
        baseline: dict[str, Any],
    ) -> None:
        self.catalog = catalog
        self.suite_id = suite_id
        self.__holdout = copy.deepcopy(holdout)
        self.__thresholds = {"minimum_accuracy": minimum_accuracy, "maximum_cost_delta": maximum_cost_delta}
        self.__baseline = copy.deepcopy(baseline)
        self.__holdout_hash = sha256_json(self.__holdout)
        self.__threshold_hash = sha256_json(self.__thresholds)
        self.__baseline_hash = sha256_json(self.__baseline)
        self.__evaluator_hash = sha256_json({"algorithm": "exact_match_v1", "suite_id": suite_id})

    @property
    def seals(self) -> dict[str, str]:
        return {"holdout_hash": self.__holdout_hash, "threshold_hash": self.__threshold_hash, "baseline_hash": self.__baseline_hash, "evaluator_hash": self.__evaluator_hash}

    def evaluate(self, candidate_id: str, candidate: Callable[[Any], Any], *, cost_delta: float = 0.0) -> dict[str, Any]:
        before = self.seals
        correct, safety_ok = 0, True
        for case in self.__holdout:
            output = candidate(copy.deepcopy(case["input"]))
            if output == case["expected"]:
                correct += 1
            if isinstance(output, dict) and output.get("safety_violation"):
                safety_ok = False
        accuracy = correct / len(self.__holdout) if self.__holdout else 0.0
        seals_intact = before == self.seals and self.__holdout_hash == sha256_json(self.__holdout) and self.__threshold_hash == sha256_json(self.__thresholds)
        passed = seals_intact and safety_ok and accuracy >= self.__thresholds["minimum_accuracy"] and cost_delta <= self.__thresholds["maximum_cost_delta"]
        report = {
            "report_id": new_id("eval"), "schema_version": "0.3.0", "candidate_id": candidate_id,
            "suite_id": self.suite_id, **before, "metrics": {"accuracy": accuracy},
            "guardrails": {"safety": safety_ok, "seals_intact": seals_intact}, "cost_delta": cost_delta,
            "status": "passed" if passed else ("invalid" if not seals_intact else "failed"), "evaluated_at": utc_now(),
        }
        self.catalog.validate("evaluation-report", report)
        return report


class PolicyEvaluationGate:
    def approve(self, report: dict[str, Any]) -> None:
        if report["status"] != "passed" or not all(report["guardrails"].values()):
            raise ANOError("EVALUATION_GATE_FAILED", "candidate policy failed baseline, safety, cost, or seal checks")


class SkillRegistry:
    def __init__(self, catalog: SchemaCatalog, machine_path: str | Path) -> None:
        self.catalog = catalog
        self.machine = StateMachine.from_file(machine_path)
        self.skills: dict[tuple[str, str], dict[str, Any]] = {}
        self.runtime: dict[tuple[str, str], dict[str, Any]] = {}
        self.history: dict[tuple[str, str], list[str]] = {}
        self.production: dict[str, str] = {}
        self.baseline_seals: dict[tuple[str, str], str] = {}

    def _seal(self, key: tuple[str, str]) -> str:
        return sha256_json({
            "artifact_hash": self.skills[key]["artifact_hash"],
            "state": self.runtime[key]["state"],
        })

    def register(self, skill: dict[str, Any], *, behavior: Callable[[Any], Any], state: dict[str, Any]) -> None:
        self.catalog.validate("skill-package", skill)
        if skill["status"] != "candidate":
            raise ANOError("SKILL_STATE_INVALID", "new skill must be candidate")
        key = (str(skill["skill_id"]), str(skill["version"]))
        self.skills[key] = copy.deepcopy(skill)
        self.runtime[key] = {"behavior": behavior, "state": copy.deepcopy(state)}
        self.history[key] = ["candidate"]

    def advance(self, skill_id: str, version: str, event: str, guards: set[str]) -> dict[str, Any]:
        key = (skill_id, version)
        skill = self.skills[key]
        target = self.machine.transition(str(skill["status"]), event, guards)
        skill["status"] = target
        self.history[key].append(target)
        self.catalog.validate("skill-package", skill)
        if target == "production":
            self.production[skill_id] = version
            self.baseline_seals[key] = self._seal(key)
        return copy.deepcopy(skill)

    def execute(self, skill_id: str, payload: Any) -> tuple[Any, dict[str, Any]]:
        version = self.production[skill_id]
        runtime = self.runtime[(skill_id, version)]
        return runtime["behavior"](copy.deepcopy(payload)), copy.deepcopy(runtime["state"])

    def rollback(self, skill_id: str, failed_version: str) -> str:
        failed = self.skills[(skill_id, failed_version)]
        target_version = failed["rollback_version"]
        if target_version is None or (skill_id, target_version) not in self.skills:
            raise ANOError("ROLLBACK_UNAVAILABLE", "signed rollback version is unavailable")
        target_key = (skill_id, target_version)
        if self.baseline_seals.get(target_key) != self._seal(target_key):
            raise ANOError("ROLLBACK_INTEGRITY_FAILURE", "rollback baseline artifact or state was modified")
        self.advance(skill_id, failed_version, "skill.rolled_back", {"baseline_restored"})
        self.production[skill_id] = target_version
        return target_version


class ModelAdvancementManager:
    def __init__(self, catalog: SchemaCatalog, capability_map: dict[str, list[str]]) -> None:
        self.catalog = catalog
        self.capability_map = copy.deepcopy(capability_map)
        self.orchestrations: dict[str, dict[str, Any]] = {}

    def discover_and_evaluate(self, previous: dict[str, Any], candidate: dict[str, Any], *, evaluation_reports: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
        previous_caps, candidate_caps = previous.get("capabilities", {}), candidate.get("capabilities", {})
        discovered = sorted(key for key, value in candidate_caps.items() if value > previous_caps.get(key, 0))
        affected = sorted({system for capability in discovered for system in self.capability_map.get(capability, [])})
        required_suites = {"ano_core_regression", "permission_boundary"}
        for report in evaluation_reports:
            self.catalog.validate("evaluation-report", report)
        passed_suites = {str(report["suite_id"]) for report in evaluation_reports if report["status"] == "passed" and report["candidate_id"] == candidate["adapter_id"]}
        evals_passed = required_suites <= passed_suites
        advancement_id = new_id("madv")
        orchestration_ids = []
        if evals_passed:
            for system in affected:
                orchestration_id = f"orch_{system.replace('.', '_')}"
                self.orchestrations[orchestration_id] = {"orchestration_id": orchestration_id, "system_capability": system, "status": "candidate", "permissions": []}
                orchestration_ids.append(orchestration_id)
        advancement = {
            "advancement_id": advancement_id, "schema_version": "0.3.0", "version": 2,
            "previous_adapter_id": previous["adapter_id"], "candidate_adapter_id": candidate["adapter_id"],
            "discovered_capabilities": discovered, "changed_limits": {}, "affected_system_capabilities": affected,
            "required_eval_suites": sorted(required_suites), "rollout_policy_id": "model_upgrade_standard",
            "candidate_orchestration_ids": orchestration_ids, "status": "evaluated" if evals_passed else "rejected",
        }
        self.catalog.validate("model-advancement", advancement)
        nodes = [{"capability_id": item, "kind": "model", "status": "available" if evals_passed else "candidate"} for item in discovered]
        nodes += [{"capability_id": item, "kind": "system", "status": "candidate"} for item in affected]
        edges = [{"from": model, "to": system, "relation": "enables"} for model in discovered for system in self.capability_map.get(model, [])]
        graph = {"graph_id": "capability_graph_main", "schema_version": "0.3.0", "version": 2, "nodes": nodes, "edges": edges, "generated_at": utc_now(), "source_advancement_ids": [advancement_id]}
        self.catalog.validate("capability-graph", graph)
        return advancement, graph

    def leverage_metrics(self, advancement_id: str, *, base_gain: float, end_to_end_gain: float, unlocked: int, improved: int, retired: int, cost_delta: float, safety_regressions: int) -> dict[str, Any]:
        if base_gain <= 0:
            raise ANOError("LEVERAGE_BASE_INVALID", "base model gain must be positive")
        metrics = {
            "metrics_id": new_id("lev"), "schema_version": "0.3.0", "advancement_id": advancement_id,
            "base_model_eval_gain": base_gain, "end_to_end_goal_success_gain": end_to_end_gain,
            "architecture_leverage_ratio": end_to_end_gain / base_gain,
            "newly_unlocked_system_capabilities": unlocked, "skills_improved": improved, "skills_retired": retired,
            "cost_per_success_delta": cost_delta, "safety_regression_count": safety_regressions, "measured_at": utc_now(),
        }
        self.catalog.validate("model-leverage-metrics", metrics)
        return metrics


class GoalIntegrityGuard:
    def __init__(self, criteria: dict[str, Any], evaluator_hash: str) -> None:
        self.criteria = copy.deepcopy(criteria)
        self.criteria_hash = sha256_json(criteria)
        self.evaluator_hash = evaluator_hash

    def validate_claim(self, claimed_criteria: dict[str, Any], evaluator_hash: str) -> None:
        if sha256_json(claimed_criteria) != self.criteria_hash:
            raise ANOError("GOAL_DRIFT", "candidate changed success criteria")
        if evaluator_hash != self.evaluator_hash:
            raise ANOError("EVALUATOR_DRIFT", "candidate changed the goal evaluator")
