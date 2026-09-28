import os
import sys
import time
import uuid
import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, Security, Request, status
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.future import select

from app.config import settings
from app.models.schemas import (
    AlertInput,
    AlertProcessResponse,
    ApprovalDecision,
    GuardScanResult,
    ApprovalStatus
)
from app.models.database import (
    init_db,
    get_db,
    AsyncSessionLocal,
    AlertRecord,
    AuditLogRecord,
    ApprovalGateRecord
)
from app.agent.graph import soc_agent_graph
from app.agent.tools import AVAILABLE_TOOLS

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(
    title="AgentShield Lite API",
    description="Multilingual Prompt-Injection Benchmark & Guard Layer for Tool-Using SOC Triage Agents",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API-Key Authentication
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: Optional[str] = Security(API_KEY_HEADER)):
    if not api_key:
        return True
    if api_key != settings.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key in X-API-Key header"
        )
    return True

@app.get("/health", tags=["Health"])
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "guard_enabled": settings.GUARD_ENABLED,
        "llm_provider": settings.LLM_PROVIDER
    }

@app.post("/alerts", response_model=AlertProcessResponse, tags=["Alerts"])
async def ingest_alert(
    alert_input: AlertInput,
    guard_enabled: bool = True,
    active_detector: str = "all",  # "all", "rules", "classifier", "llm_judge", "baseline"
    authorized: bool = Depends(verify_api_key)
):
    """
    Ingests a security alert, passes it through the Guard Layer (PII sanitization & injection scanning),
    runs the LangGraph SOC triage workflow, checks tool policies and approval gates, and returns the response.
    """
    start_time = time.perf_counter()
    alert_id = alert_input.id or f"ALT-{uuid.uuid4().hex[:8].upper()}"
    untrusted_text = alert_input.get_full_untrusted_text()

    # 1. Record alert in DB
    async with AsyncSessionLocal() as session:
        db_alert = AlertRecord(
            id=alert_id,
            title=alert_input.title,
            source=alert_input.source,
            description=alert_input.description,
            raw_log=alert_input.raw_log,
            source_ip=alert_input.source_ip,
            destination_ip=alert_input.destination_ip,
            username=alert_input.username,
            status="RECEIVED"
        )
        session.add(db_alert)
        
        audit_init = AuditLogRecord(
            alert_id=alert_id,
            event_type="ALERT_INGESTED",
            actor="INGESTION_GATEWAY",
            details_json=json.dumps({"title": alert_input.title, "source": alert_input.source})
        )
        session.add(audit_init)
        await session.commit()

    # 2. Run LangGraph Workflow
    state_input = {
        "alert_id": alert_id,
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

    final_status = final_state.get("status", "COMPLETED")
    guard_result = final_state.get("guard_scan_result")
    triage_result = final_state.get("triage_result")
    matched_pb = final_state.get("matched_playbook")
    tool_calls = final_state.get("tool_calls", [])
    summary_report = final_state.get("summary_report")

    # 3. Update DB with Audit Logs & Pending Approvals
    async with AsyncSessionLocal() as session:
        res = await session.execute(select(AlertRecord).where(AlertRecord.id == alert_id))
        record = res.scalars().first()
        if record:
            record.status = final_status
            if triage_result:
                record.severity = triage_result.severity.value
                record.category = triage_result.category.value
            record.summary_report = summary_report

        # Log Guard Verdict
        if guard_result:
            audit_guard = AuditLogRecord(
                alert_id=alert_id,
                event_type="GUARD_SCAN",
                actor="GUARD_LAYER",
                details_json=json.dumps({
                    "is_blocked": guard_result.is_blocked,
                    "verdict": guard_result.verdict,
                    "active_detector": active_detector,
                    "redacted_entities": guard_result.redacted_entities
                })
            )
            session.add(audit_guard)

        # Record Tool Calls & Approval Gates
        for tc in tool_calls:
            audit_tool = AuditLogRecord(
                alert_id=alert_id,
                event_type="TOOL_BLOCKED" if not tc.policy_allowed else ("APPROVAL_REQUESTED" if tc.requires_human_approval else "TOOL_EXECUTED"),
                actor="TOOL_POLICY",
                details_json=json.dumps({
                    "tool": tc.tool_name,
                    "params": tc.parameters,
                    "status": tc.approval_status.value
                })
            )
            session.add(audit_tool)

            if tc.requires_human_approval and tc.approval_status == ApprovalStatus.PENDING:
                gate_rec = ApprovalGateRecord(
                    id=tc.call_id,
                    alert_id=alert_id,
                    tool_name=tc.tool_name,
                    parameters_json=json.dumps(tc.parameters),
                    status="PENDING"
                )
                session.add(gate_rec)

        await session.commit()

    return AlertProcessResponse(
        alert_id=alert_id,
        status=final_status,
        guard_result=guard_result,
        triage_result=triage_result,
        playbook_matched=matched_pb.get("title") if matched_pb else None,
        tool_calls=tool_calls,
        summary_report=summary_report,
        total_latency_ms=round(total_latency, 2)
    )

@app.get("/alerts/{alert_id}", tags=["Alerts"])
async def get_alert_details(alert_id: str, authorized: bool = Depends(verify_api_key)):
    """Fetch status, triage results, and audit trails for a specific alert."""
    async with AsyncSessionLocal() as session:
        res = await session.execute(select(AlertRecord).where(AlertRecord.id == alert_id))
        record = res.scalars().first()
        if not record:
            raise HTTPException(status_code=404, detail="Alert not found")

        audit_res = await session.execute(
            select(AuditLogRecord).where(AuditLogRecord.alert_id == alert_id).order_by(AuditLogRecord.created_at)
        )
        logs = [
            {
                "id": log.id,
                "event_type": log.event_type,
                "actor": log.actor,
                "details": log.details,
                "timestamp": log.created_at.isoformat()
            }
            for log in audit_res.scalars().all()
        ]

        gates_res = await session.execute(
            select(ApprovalGateRecord).where(ApprovalGateRecord.alert_id == alert_id)
        )
        gates = [
            {
                "gate_id": g.id,
                "tool_name": g.tool_name,
                "parameters": json.loads(g.parameters_json),
                "status": g.status,
                "analyst_id": g.analyst_id,
                "analyst_comment": g.analyst_comment
            }
            for g in gates_res.scalars().all()
        ]

        return {
            "alert_id": record.id,
            "title": record.title,
            "source": record.source,
            "status": record.status,
            "severity": record.severity,
            "category": record.category,
            "summary_report": record.summary_report,
            "created_at": record.created_at.isoformat(),
            "audit_trail": logs,
            "approval_gates": gates
        }

@app.post("/alerts/{alert_id}/approval", tags=["Approval Gate"])
async def resolve_approval_gate(
    alert_id: str,
    decision: ApprovalDecision,
    authorized: bool = Depends(verify_api_key)
):
    """
    Human-in-the-loop approval gate endpoint.
    SOC analysts review and approve or reject high-risk actions (e.g. block_ip).
    """
    async with AsyncSessionLocal() as session:
        res = await session.execute(
            select(ApprovalGateRecord).where(
                ApprovalGateRecord.id == decision.tool_call_id,
                ApprovalGateRecord.alert_id == alert_id
            )
        )
        gate = res.scalars().first()
        if not gate:
            raise HTTPException(status_code=404, detail="Approval gate record not found")

        if gate.status != "PENDING":
            raise HTTPException(status_code=400, detail=f"Gate already resolved: {gate.status}")

        dec_upper = decision.decision.upper()
        if dec_upper not in ("APPROVE", "REJECT"):
            raise HTTPException(status_code=400, detail="Decision must be 'APPROVE' or 'REJECT'")

        gate.status = "APPROVED" if dec_upper == "APPROVE" else "REJECTED"
        gate.analyst_id = decision.analyst_id
        gate.analyst_comment = decision.reason
        gate.resolved_at = datetime.now(timezone.utc)

        execution_output = None
        if dec_upper == "APPROVE":
            tool_name = gate.tool_name
            params = json.loads(gate.parameters_json)
            func = AVAILABLE_TOOLS.get(tool_name)
            if func:
                execution_output = func(**params)

        # Audit log the analyst decision
        audit_rec = AuditLogRecord(
            alert_id=alert_id,
            event_type="APPROVAL_RESOLVED",
            actor=f"ANALYST:{decision.analyst_id}",
            details_json=json.dumps({
                "decision": dec_upper,
                "tool": gate.tool_name,
                "reason": decision.reason,
                "execution_result": execution_output
            })
        )
        session.add(audit_rec)
        await session.commit()

        return {
            "status": "SUCCESS",
            "decision": dec_upper,
            "tool_call_id": gate.id,
            "execution_result": execution_output
        }

@app.get("/audit", tags=["Audit Log"])
async def get_recent_audit_logs(limit: int = 50, authorized: bool = Depends(verify_api_key)):
    """Retrieve system audit logs."""
    async with AsyncSessionLocal() as session:
        res = await session.execute(
            select(AuditLogRecord).order_by(AuditLogRecord.id.desc()).limit(limit)
        )
        logs = [
            {
                "id": log.id,
                "alert_id": log.alert_id,
                "event_type": log.event_type,
                "actor": log.actor,
                "details": log.details,
                "timestamp": log.created_at.isoformat()
            }
            for log in res.scalars().all()
        ]
        return {"count": len(logs), "logs": logs}

@app.get("/benchmark/results", tags=["Benchmark"])
async def get_benchmark_results():
    """Returns empirical benchmark metrics comparing Guard OFF vs Guard ON."""
    benchmark_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "eval", "benchmark_results.json")
    if os.path.exists(benchmark_file):
        with open(benchmark_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"status": "Benchmark has not been run yet. Run: python eval/run_benchmark.py"}

@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
async def dashboard():
    """Interactive SOC Analyst Console & Benchmark Dashboard."""
    html_path = os.path.join(os.path.dirname(__file__), "web", "dashboard.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>AgentShield Lite API is Running. Visit <a href='/docs'>/docs</a> for Swagger UI.</h1>"
