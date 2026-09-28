import uuid
from typing import Dict, Any, Literal

from langgraph.graph import StateGraph, END

from app.agent.state import SOCAgentState
from app.models.schemas import ToolCallIntent, ApprovalStatus
from app.guard.pipeline import guard_pipeline
from app.rag.vector_store import playbook_store
from app.agent.tools import AVAILABLE_TOOLS
from app.agent.llm_client import SOCLLMClient

soc_llm = SOCLLMClient()


# ─────────────────────────────────────────────────────────────
# Node: Guard (injection scan + PII redaction)
# ─────────────────────────────────────────────────────────────

def guard_node(state: SOCAgentState) -> Dict[str, Any]:
    """
    Spec step 2: Guard — injection scan + PII redaction.
    If injection is detected → route to report (blocked).
    Otherwise → pass redacted text to triage.
    """
    raw_alert = state.get("raw_alert", {})
    text_to_scan = raw_alert.get("untrusted_text", "")
    guard_enabled = state.get("guard_enabled", True)
    active_detector = state.get("active_detector", "all")

    guard_res = guard_pipeline.scan_input(
        text=text_to_scan,
        guard_enabled=guard_enabled,
        active_detector=active_detector,
    )

    # Use PII-redacted text for all downstream nodes
    safe_text = guard_res.pii_redacted_text or text_to_scan

    if guard_res.is_blocked:
        return {
            "guard_scan_result": guard_res,
            "is_blocked": True,
            "status": "BLOCKED_BY_GUARD",
            "redacted_text": safe_text,
        }

    return {
        "guard_scan_result": guard_res,
        "is_blocked": False,
        "status": "IN_PROGRESS",
        "redacted_text": safe_text,
    }


def route_after_guard(state: SOCAgentState) -> Literal["report", "triage"]:
    return "report" if state.get("is_blocked", False) else "triage"


# ─────────────────────────────────────────────────────────────
# Node: Triage (severity + category, structured JSON output)
# ─────────────────────────────────────────────────────────────

def triage_node(state: SOCAgentState) -> Dict[str, Any]:
    """Spec step 3: triage agent → severity, category (Pydantic structured output)."""
    text = state.get("redacted_text", "")
    is_guarded = state.get("guard_enabled", True)
    triage_res = soc_llm.triage_alert(text, is_guarded=is_guarded)
    return {"triage_result": triage_res}


# ─────────────────────────────────────────────────────────────
# Node: RAG (playbook lookup via embeddings)
# ─────────────────────────────────────────────────────────────

def rag_node(state: SOCAgentState) -> Dict[str, Any]:
    """Spec step 4: fetch matching playbook from vector store."""
    triage = state.get("triage_result")
    query = triage.category.value if triage else "GENERAL"
    matches = playbook_store.search(query, top_k=1)
    return {"matched_playbook": matches[0] if matches else None}


# ─────────────────────────────────────────────────────────────
# Node: Action planner (agent picks next tool call)
# ─────────────────────────────────────────────────────────────

def action_planner_node(state: SOCAgentState) -> Dict[str, Any]:
    """Spec step 5: agent picks next action / tool call."""
    text = state.get("redacted_text", "")
    triage = state.get("triage_result")
    pb = state.get("matched_playbook") or {}
    pb_text = pb.get("content", "")
    source_ip = state.get("raw_alert", {}).get("source_ip")
    is_guarded = state.get("guard_enabled", True)

    planned = soc_llm.plan_tools(text, triage, pb_text, source_ip, is_guarded=is_guarded)
    return {"planned_tools": planned}


# ─────────────────────────────────────────────────────────────
# Node: Tool execution (policy check → approval gate → execute)
# ─────────────────────────────────────────────────────────────

def tool_execution_node(state: SOCAgentState) -> Dict[str, Any]:
    """
    Spec steps 5-6:
      Guard policy check: tool + args allowed?
        NO  → Call BLOCKED, logged to audit trail
        YES → Risky tool? → human approval gate
              else → execute tool + write audit log
    """
    planned = state.get("planned_tools", [])
    guard_enabled = state.get("guard_enabled", True)
    tool_calls: list[ToolCallIntent] = []
    status = "COMPLETED"
    pending_approval: ToolCallIntent | None = None

    for item in planned:
        tool_name = item.get("tool_name", "")
        args = item.get("arguments", {})
        call_id = f"tc-{uuid.uuid4().hex[:8]}"

        # ── Bug fix #7: always initialise is_risky before the conditional block ──
        is_risky = False

        if guard_enabled:
            is_allowed, is_risky, reason = guard_pipeline.validate_tool_intent(
                tool_name, args
            )

            if not is_allowed:
                # Policy BLOCKED
                tool_calls.append(
                    ToolCallIntent(
                        call_id=call_id,
                        tool_name=tool_name,
                        parameters=args,
                        is_risky=False,
                        policy_allowed=False,
                        policy_violation_reason=reason,
                        approval_status=ApprovalStatus.NOT_REQUIRED,
                    )
                )
                # Don't override a prior PENDING_APPROVAL with POLICY_BLOCKED
                if status == "COMPLETED":
                    status = "POLICY_BLOCKED"
                continue

            if is_risky:
                # Risky tool → human approval gate (spec: block_ip)
                intent = ToolCallIntent(
                    call_id=call_id,
                    tool_name=tool_name,
                    parameters=args,
                    is_risky=True,
                    policy_allowed=True,
                    requires_human_approval=True,
                    approval_status=ApprovalStatus.PENDING,
                    approval_comment=reason,
                )
                tool_calls.append(intent)
                pending_approval = intent
                status = "PENDING_APPROVAL"
                continue
        else:
            # Guard OFF: no policy check, no approval gate — danger zone
            # is_risky stays False; tools execute freely
            pass

        # Execute the tool
        func = AVAILABLE_TOOLS.get(tool_name)
        if func:
            try:
                exec_result = func(**args)
            except Exception as exc:
                exec_result = {"error": str(exc)}
        else:
            exec_result = {"error": f"Tool '{tool_name}' not registered"}

        tool_calls.append(
            ToolCallIntent(
                call_id=call_id,
                tool_name=tool_name,
                parameters=args,
                is_risky=is_risky,
                policy_allowed=True,
                requires_human_approval=False,
                approval_status=ApprovalStatus.NOT_REQUIRED,
                execution_result=exec_result,
            )
        )

    return {
        "tool_calls": tool_calls,
        "pending_approval": pending_approval,
        "status": status,
    }


# ─────────────────────────────────────────────────────────────
# Node: Report writer (spec step 7)
# ─────────────────────────────────────────────────────────────

def report_node(state: SOCAgentState) -> Dict[str, Any]:
    """Spec step 7: report agent writes summary → API response."""
    guard_result = state.get("guard_scan_result")

    if state.get("is_blocked", False):
        # ── Bug fix #14: read active_detector from guard_scan_result, not state ──
        detector_used = (
            guard_result.active_detector if guard_result else state.get("active_detector", "unknown")
        )
        summary = (
            "### Incident Triage Halted — Prompt Injection Detected\n"
            "The Guard Layer intercepted an adversarial injection in the untrusted alert payload.\n\n"
            f"- **Verdict**: {guard_result.verdict if guard_result else 'INJECTION_DETECTED'}\n"
            f"- **Active Detector**: {detector_used}\n"
            "- **Action**: Input quarantined. Execution halted. Event written to audit log."
        )
        return {"summary_report": summary, "status": "BLOCKED_BY_GUARD"}

    triage = state.get("triage_result")
    pb = state.get("matched_playbook") or {}
    pb_title = pb.get("title", "Standard Playbook")
    tool_results = [
        {
            "tool_name": tc.tool_name,
            "parameters": tc.parameters,
            "status": (
                "PENDING_APPROVAL"
                if tc.approval_status == ApprovalStatus.PENDING
                else ("BLOCKED" if not tc.policy_allowed else "EXECUTED")
            ),
        }
        for tc in state.get("tool_calls", [])
    ]

    report = soc_llm.generate_report(triage, pb_title, tool_results)
    return {"summary_report": report}


# ─────────────────────────────────────────────────────────────
# Graph assembly
# ─────────────────────────────────────────────────────────────

def create_soc_graph():
    """Compile the LangGraph SOC triage workflow."""
    workflow = StateGraph(SOCAgentState)

    workflow.add_node("guard", guard_node)
    workflow.add_node("triage", triage_node)
    workflow.add_node("rag", rag_node)
    workflow.add_node("action_planner", action_planner_node)
    workflow.add_node("tool_execution", tool_execution_node)
    workflow.add_node("report", report_node)

    workflow.set_entry_point("guard")
    workflow.add_conditional_edges(
        "guard", route_after_guard, {"report": "report", "triage": "triage"}
    )
    workflow.add_edge("triage", "rag")
    workflow.add_edge("rag", "action_planner")
    workflow.add_edge("action_planner", "tool_execution")
    workflow.add_edge("tool_execution", "report")
    workflow.add_edge("report", END)

    return workflow.compile()


soc_agent_graph = create_soc_graph()
