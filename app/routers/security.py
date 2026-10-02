from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Literal, Optional

from app.core.catalog import COMPLIANCE_FRAMEWORKS
from app.core.supabase_client import get_supabase
from app.services.snapshot import build_snapshot

router = APIRouter(prefix="/security", tags=["security"])


def _is_https(request: Request) -> bool:
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    return proto.split(",")[0].strip().lower() == "https"


@router.get("")
def all_security(request: Request):
    snap = build_snapshot(https=_is_https(request), with_security=True)
    return {"security": snap["security"], "warnings": snap["warnings"]}


@router.get("/{region_id}")
def region_security(region_id: str, request: Request):
    # Solo se calcula la región pedida (evita repetir consultas a Supabase por cada región)
    from app.core.config import get_settings
    from app.services import snapshot as snap_mod
    from app.services.security_checks import build_real_security

    if region_id not in get_settings().region_list:
        raise HTTPException(404, detail=f"Región no configurada: {region_id}")
    base = build_snapshot()["security"][region_id]
    real = build_real_security(region_id, snap_mod._list_compliance(), _is_https(request))
    report = {
        **base,
        "score": real["score"],
        "groups": real["groups"],
        "accessStats": real["accessStats"],
        "accessEvents": real["accessEvents"],
    }
    if real["complianceStatus"] != "unknown":
        report["summary"] = {**base["summary"], "compliance": real["complianceStatus"]}
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