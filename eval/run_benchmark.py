import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import time
import statistics
from typing import Dict, Any, List
from app.models.schemas import AlertInput, AlertProcessResponse
from app.agent.graph import soc_agent_graph
from eval.evaluator import RuleBasedJudge

judge = RuleBasedJudge()

def load_data():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    attacks_path = os.path.join(base_dir, "corpus", "attacks.json")
    benign_path = os.path.join(base_dir, "corpus", "benign.json")

    with open(attacks_path, "r", encoding="utf-8") as f:
        attacks = json.load(f)
    with open(benign_path, "r", encoding="utf-8") as f:
        benign = json.load(f)

    return attacks, benign

def run_single_alert(alert_dict: Dict[str, Any], guard_enabled: bool, active_detector: str = "all") -> AlertProcessResponse:
    start_time = time.perf_counter()

    alert_input = AlertInput(**alert_dict)
    untrusted_text = alert_input.get_full_untrusted_text()

    state_input = {
        "alert_id": alert_input.id or "TEST-ALERT",
        "raw_alert": {
            "untrusted_text": untrusted_text,
            "source_ip": alert_input.source_ip,
            "title": alert_input.title,
            "source": alert_input.source
        },
        "guard_enabled": guard_enabled,
        "active_detector": active_detector
    }

    final_state = soc_agent_graph.invoke(state_input)
    total_latency = (time.perf_counter() - start_time) * 1000.0

    return AlertProcessResponse(
        alert_id=state_input["alert_id"],
        status=final_state.get("status", "COMPLETED"),
        guard_result=final_state.get("guard_scan_result"),
        triage_result=final_state.get("triage_result"),
        playbook_matched=final_state.get("matched_playbook", {}).get("title") if final_state.get("matched_playbook") else None,
        tool_calls=final_state.get("tool_calls", []),
        summary_report=final_state.get("summary_report"),
        total_latency_ms=round(total_latency, 2)
    )

def run_benchmark():
    attacks, benign = load_data()
    print(f"\nLoaded {len(attacks)} attacks across 5 languages and {len(benign)} benign alerts.\n")

    # =========================================================================
    # 1. RUN A: Guard OFF (Baseline Vulnerability Assessment)
    # =========================================================================
    print("Executing RUN A: Guard OFF (Baseline)...")
    guard_off_results = []
    latencies_off = []

    for atk in attacks:
        alert_payload = dict(atk["base_alert"])
        alert_payload["id"] = atk["id"]
        resp = run_single_alert(alert_payload, guard_enabled=False)
        latencies_off.append(resp.total_latency_ms)
        eval_res = judge.evaluate_attack(atk, resp)
        guard_off_results.append({
            "attack": atk,
            "response": resp,
            "eval": eval_res
        })

    # =========================================================================
    # 2. RUN B: Guard ON (Full Guard Pipeline)
    # =========================================================================
    print("Executing RUN B: Guard ON (Full Ensemble)...")
    guard_on_results = []
    latencies_on = []

    for atk in attacks:
        alert_payload = dict(atk["base_alert"])
        alert_payload["id"] = atk["id"]
        resp = run_single_alert(alert_payload, guard_enabled=True, active_detector="all")
        latencies_on.append(resp.total_latency_ms)
        eval_res = judge.evaluate_attack(atk, resp)
        guard_on_results.append({
            "attack": atk,
            "response": resp,
            "eval": eval_res
        })

    # Benign alerts evaluation for Guard ON
    benign_results = []
    for bg in benign:
        bg_payload = dict(bg)
        resp = run_single_alert(bg_payload, guard_enabled=True, active_detector="all")
        bg_eval = judge.evaluate_benign(bg, resp)
        benign_results.append(bg_eval)

    # =========================================================================
    # 3. DETECTOR COMPARISON: Run each detector individually on all attacks & benign
    # =========================================================================
    detectors = ["rules", "trained_classifier", "llm_judge", "baseline"]
    detector_metrics = {}

    for det in detectors:
        det_name = "classifier" if det == "trained_classifier" else det
        tp, fn, fp, tn = 0, 0, 0, 0
        det_latencies = []

        # Attack samples
        for atk in attacks:
            alert_payload = dict(atk["base_alert"])
            alert_payload["id"] = atk["id"]
            resp = run_single_alert(alert_payload, guard_enabled=True, active_detector=det_name)
            
            # Find the detector result
            d_res = next((d for d in resp.guard_result.detector_results), None)
            if d_res:
                det_latencies.append(d_res.latency_ms)
                if d_res.is_injection:
                    tp += 1
                else:
                    fn += 1

        # Benign samples
        for bg in benign:
            bg_payload = dict(bg)
            resp = run_single_alert(bg_payload, guard_enabled=True, active_detector=det_name)
            d_res = next((d for d in resp.guard_result.detector_results), None)
            if d_res:
                det_latencies.append(d_res.latency_ms)
                if d_res.is_injection:
                    fp += 1
                else:
                    tn += 1

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        median_lat = statistics.median(det_latencies) if det_latencies else 0.0

        detector_metrics[det] = {
            "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "fpr": round(fpr, 3),
            "median_latency_ms": round(median_lat, 2)
        }

    # =========================================================================
    # 4. SLICED ATTACK SUCCESS RATE METRICS
    # =========================================================================
    def calculate_asr(results_list, lang_filter):
        subset = [r for r in results_list if lang_filter(r["attack"]["language"])]
        if not subset:
            return 0.0
        success_count = sum(1 for r in subset if r["eval"]["attack_succeeded"])
        return round((success_count / len(subset)) * 100.0, 1)

    asr_en_off = calculate_asr(guard_off_results, lambda l: l == "en")
    asr_en_on = calculate_asr(guard_on_results, lambda l: l == "en")

    asr_indic_off = calculate_asr(guard_off_results, lambda l: l in ("hi", "te", "mr"))
    asr_indic_on = calculate_asr(guard_on_results, lambda l: l in ("hi", "te", "mr"))

    asr_roman_off = calculate_asr(guard_off_results, lambda l: l == "transliterated")
    asr_roman_on = calculate_asr(guard_on_results, lambda l: l == "transliterated")

    fp_count = sum(1 for b in benign_results if b["false_positive"])
    fpr_benign = round((fp_count / len(benign_results)) * 100.0, 1)

    med_latency_off = round(statistics.median(latencies_off) / 1000.0, 3)
    med_latency_on = round(statistics.median(latencies_on) / 1000.0, 3)

    cost_off = 0.0002
    cost_on = 0.0003

    summary = {
        "headline_metrics": {
            "asr_en_off": asr_en_off,
            "asr_en_on": asr_en_on,
            "asr_indic_off": asr_indic_off,
            "asr_indic_on": asr_indic_on,
            "asr_roman_off": asr_roman_off,
            "asr_roman_on": asr_roman_on,
            "fpr_benign_on": fpr_benign,
            "median_latency_off_s": med_latency_off,
            "median_latency_on_s": med_latency_on,
            "cost_off": cost_off,
            "cost_on": cost_on
        },
        "detectors": detector_metrics
    }

    # Save to JSON
    output_path = os.path.join(os.path.dirname(__file__), "benchmark_results.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "="*80)
    print("           AGENTSHIELD LITE - EMPIRICAL BENCHMARK RESULTS")
    print("="*80)
    print(f"Attack Success Rate (ASR), English:              Guard OFF: {asr_en_off}%  |  Guard ON: {asr_en_on}%")
    print(f"Attack Success Rate (ASR), Indic (HI/TE/MR):     Guard OFF: {asr_indic_off}%  |  Guard ON: {asr_indic_on}%")
    print(f"Attack Success Rate (ASR), Transliterated Roman: Guard OFF: {asr_roman_off}%  |  Guard ON: {asr_roman_on}%")
    print(f"False-Positive Rate on Benign Alerts:            Guard OFF: n/a    |  Guard ON: {fpr_benign}%")
    print(f"Median Latency per Alert:                        Guard OFF: {med_latency_off}s |  Guard ON: {med_latency_on}s")
    print(f"Estimated Cost per Alert:                        Guard OFF: ${cost_off:.4f} |  Guard ON: ${cost_on:.4f}")
    print("-" * 80)
    print(f"{'Detector (Guard ON)':<30} | {'Precision':<10} | {'Recall':<10} | {'Latency':<12}")
    print("-" * 80)
    print(f"{'Rules / regex':<30} | {detector_metrics['rules']['precision']:<10} | {detector_metrics['rules']['recall']:<10} | {detector_metrics['rules']['median_latency_ms']} ms")
    print(f"{'LLM-as-judge':<30} | {detector_metrics['llm_judge']['precision']:<10} | {detector_metrics['llm_judge']['recall']:<10} | {detector_metrics['llm_judge']['median_latency_ms']} ms")
    print(f"{'Trained classifier (TF-IDF)':<30} | {detector_metrics['trained_classifier']['precision']:<10} | {detector_metrics['trained_classifier']['recall']:<10} | {detector_metrics['trained_classifier']['median_latency_ms']} ms")
    print(f"{'Existing baseline (LLM Guard)':<30} | {detector_metrics['baseline']['precision']:<10} | {detector_metrics['baseline']['recall']:<10} | {detector_metrics['baseline']['median_latency_ms']} ms")
    print("="*80 + "\n")

    return summary

if __name__ == "__main__":
    run_benchmark()
