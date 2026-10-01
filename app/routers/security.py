from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Literal, Optional

from app.core.catalog import COMPLIANCE_FRAMEWORKS
from app.core.supabase_client import get_supabase
from app.services.snapshot import build_snapshot

router = APIRouter(prefix="/security", tags=["security"])


@router.get("")
def all_security():
    snap = build_snapshot()
    return {"security": snap["security"], "warnings": snap["warnings"]}


@router.get("/{region_id}")
def region_security(region_id: str):
    snap = build_snapshot()
    report = snap["security"].get(region_id)
    if not report:
        raise HTTPException(404, detail=f"Región no configurada: {region_id}")
    return {"report": report}


class ComplianceBody(BaseModel):
    status: Literal["healthy", "review", "issue"]
    note: Optional[str] = None


@router.put("/compliance/{framework}")
def set_compliance(framework: str, body: ComplianceBody):
    if framework not in COMPLIANCE_FRAMEWORKS:
        raise HTTPException(400, detail="Framework no soportado")
    get_supabase().table("compliance_status").upsert(
        {"framework": framework, "status": body.status, "note": body.note}
    ).execute()
    return {"framework": framework, "status": body.status, "note": body.note}
