import time
import urllib.parse
from typing import Optional, List, Dict, Any, Tuple

from app.models.schemas import GuardScanResult, DetectorResult
from app.guard.pii_redactor import PIIRedactor
from app.guard.rules_detector import RulesDetector
from app.guard.classifier import TrainedClassifierDetector
from app.guard.llm_judge import LLMJudgeDetector
from app.guard.baseline import BaselineHeuristicDetector
from app.guard.policy import ToolPolicy
from app.config import settings


class GuardPipeline:
    """
    Unified Guard Layer Coordinator.

    Spec flow:
        Input scan → PII redaction → Tool policy → Human approval

    The pipeline:
      1. URL-decodes the text to defeat percent-encoded evasion.
      2. Runs selected detectors against the decoded text.
      3. Redacts PII from the ORIGINAL (non-duplicated) text for safe downstream use.
      4. Returns a unified GuardScanResult.
    """

    def __init__(self) -> None:
        self.redactor = PIIRedactor()
        self.rules_detector = RulesDetector()
        self.classifier_detector = TrainedClassifierDetector()
        self.llm_judge = LLMJudgeDetector()
        self.baseline_detector = BaselineHeuristicDetector()
        self.tool_policy = ToolPolicy()

    # ------------------------------------------------------------------
    # Public: Input scan
    # ------------------------------------------------------------------

    def scan_input(
        self,
        text: str,
        guard_enabled: bool = True,
        active_detector: str = "all",
        # Allowed values: "all" | "rules" | "classifier" | "llm_judge" | "baseline"
    ) -> GuardScanResult:
        """
        Runs input through injection detection + PII sanitisation.

        When guard_enabled=False the pipeline is bypassed entirely (Guard OFF
        baseline), which lets the benchmark measure the raw attack success rate.
        """
        start_time = time.perf_counter()

        if not guard_enabled:
            return GuardScanResult(
                is_blocked=False,
                verdict="SAFE",
                active_detector="NONE (GUARD OFF)",
                detector_results=[],
                pii_redacted_text=text,
                redacted_entities=[],
                policy_action="ALLOW",
                total_guard_latency_ms=0.0,
            )

        # ── Bug fix #6: Use decoded text as scan target, NOT a concatenation ──
        decoded_text = urllib.parse.unquote_plus(text)
        scan_target = decoded_text  # single, clean string

        # ── Bug fix #13: Redact original text so PII in the original is hidden,
        #    but use the decoded scan_target for detector inputs
        redacted_text, redacted_entities = self.redactor.redact(text)

        # Run selected detectors against decoded target
        detector_results: List[DetectorResult] = []

        if active_detector in ("all", "rules"):
            detector_results.append(self.rules_detector.scan(scan_target))

        if active_detector in ("all", "classifier"):
            detector_results.append(
                self.classifier_detector.scan(
                    scan_target, threshold=settings.CLASSIFIER_THRESHOLD
                )
            )

        if active_detector in ("all", "llm_judge"):
            detector_results.append(self.llm_judge.scan(scan_target))

        # Baseline is standalone (spec: "shows how your work compares")
        if active_detector == "baseline":
            detector_results.append(self.baseline_detector.scan(scan_target))

        # Verdict: ANY detector flagging → block
        any_injection = any(d.is_injection for d in detector_results)
        verdict = "INJECTION_DETECTED" if any_injection else "SAFE"
        policy_action = "BLOCK" if any_injection else "ALLOW"

        total_latency_ms = (time.perf_counter() - start_time) * 1000.0

        return GuardScanResult(
            is_blocked=any_injection,
            verdict=verdict,
            active_detector=active_detector,
            detector_results=detector_results,
            pii_redacted_text=redacted_text,
            redacted_entities=redacted_entities,
            policy_action=policy_action,
            total_guard_latency_ms=round(total_latency_ms, 2),
        )

    # ------------------------------------------------------------------
    # Public: Tool policy check (called from tool_execution_node)
    # ------------------------------------------------------------------

    def validate_tool_intent(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> Tuple[bool, bool, str]:
        """
        Delegates to ToolPolicy.
        Returns (is_allowed, is_risky, reason).
        """
        return self.tool_policy.validate_tool_call(tool_name, arguments)


guard_pipeline = GuardPipeline()
