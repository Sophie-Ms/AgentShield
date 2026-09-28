import time
import re
from app.models.schemas import DetectorResult

class BaselineHeuristicDetector:
    """
    Standard Baseline Scanner (emulating traditional English-centric guard tools like LLM Guard).
    Checks for English prompt-injection signatures, role-delimiter attacks,
    and jailbreak keywords, demonstrating standard coverage vs. multilingual gaps.
    """

    ENGLISH_SIGNATURES = [
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
        re.compile(r"disregard\s+(all\s+)?prior\s+instructions?", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+in\s+developer\s+mode", re.IGNORECASE),
        re.compile(r"system\s*:\s*override", re.IGNORECASE),
        re.compile(r"<\|im_start\|>", re.IGNORECASE),
        re.compile(r"\[INST\]", re.IGNORECASE),
        re.compile(r"###\s*instruction", re.IGNORECASE),
        re.compile(r"new\s+system\s+directive", re.IGNORECASE),
        re.compile(r"drop\s+table\s+", re.IGNORECASE)
    ]

    def scan(self, text: str) -> DetectorResult:
        start_time = time.perf_counter()
        matches = []
        for pat in self.ENGLISH_SIGNATURES:
            m = pat.search(text)
            if m:
                matches.append(m.group(0))

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        is_injection = len(matches) > 0
        confidence = 0.90 if is_injection else 0.10

        return DetectorResult(
            detector_name="baseline_llm_guard",
            is_injection=is_injection,
            confidence=confidence,
            latency_ms=round(latency_ms, 3),
            matched_patterns=matches,
            explanation=f"Baseline heuristic matched {len(matches)} signature(s)" if is_injection else "No English signatures detected"
        )
