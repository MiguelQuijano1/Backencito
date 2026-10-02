from datetime import datetime
from typing import List, Optional
from zoneinfo import ZoneInfo

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.core.regions_meta import region_label, region_meta
from app.core.supabase_client import get_supabase
from app.core.catalog import PRICING_OPTIONS

router = APIRouter(prefix="/proposals", tags=["proposals"])


class ProposalIn(BaseModel):
    name: str
    type: str
    description: str = ""
    regionId: str
    users: str
    availability: str
    migration: str
    selected: List[str] = Field(default_factory=list)


def _to_proposal(row: dict) -> dict:
    s = get_settings()
    created = row.get("created_at")
    if isinstance(created, str):
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
    else:
        dt = created or datetime.utcnow()
    try:
        local = dt.astimezone(ZoneInfo(s.app_timezone))
    except Exception:
        local = dt
    meta = region_meta(row["region_id"])
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "type": row["type"],
        "description": row.get("description") or "",
        "regionId": row["region_id"],
        "region": region_label(meta),
        "users": row["users"],
        "availability": row["availability"],
        "migration": row["migration"],
        "selected": row.get("selected") or [],
        "createdAt": local.strftime("%d/%m/%Y, %H:%M"),
        "createdAtIso": dt.isoformat(),
    }


@router.get("")
def list_proposals():
    data = (
        get_supabase()
        .table("proposals")
        .select("*")
        .order("created_at", desc=True)
        .execute()
        .data
        or []
    )
    return {"proposals": [_to_proposal(r) for r in data]}


@router.post("")
def create_proposal(body: ProposalIn):
    ins = {
        "name": body.name,
        "type": body.type,
        "description": body.description,
        "region_id": body.regionId,
        "users": body.users,
        "availability": body.availability,
        "migration": body.migration,
        "selected": body.selected,
    }
    res = get_supabase().table("proposals").insert(ins).execute()
    if not res.data:
        raise HTTPException(500, detail="No se pudo crear la propuesta")
    return _to_proposal(res.data[0])


# ── Limpiar / restaurar planificaciones (archivo) ──────────────────────────
# "Limpiar" mueve las planificaciones de una región a la tabla proposals_archive
# (no se borran). "Restaurar" las devuelve a proposals. Ambas operaciones son
# atómicas: las hace una función SQL (archive_proposals / restore_proposals).
# IMPORTANTE: estas rutas van ANTES de "/{proposal_id}" para que "archived" no se
# interprete como un id.


@router.get("/archived")
def archived_counts():
    """Cuántas planificaciones archivadas hay por región."""
    rows = get_supabase().table("proposals_archive").select("region_id").execute().data or []
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["region_id"]] = counts.get(r["region_id"], 0) + 1
    return {"counts": counts, "total": sum(counts.values())}


@router.post("/archive/{region_id}")
def archive_region(region_id: str):
    """Mueve todas las planificaciones de la región al archivo."""
    res = get_supabase().rpc("archive_proposals", {"p_region_id": region_id}).execute()
    return {"regionId": region_id, "moved": int(res.data or 0)}


@router.post("/restore/{region_id}")
def restore_region(region_id: str):
    """Devuelve a la lista activa las planificaciones archivadas de la región."""
    res = get_supabase().rpc("restore_proposals", {"p_region_id": region_id}).execute()
    return {"regionId": region_id, "restored": int(res.data or 0)}


@router.delete("/{proposal_id}")
def delete_proposal(proposal_id: int):
    res = get_supabase().table("proposals").delete().eq("id", proposal_id).execute()
    if not res.data:
        raise HTTPException(404, detail="Propuesta no encontrada")
    return None


def _proposal_to_cost_rows(selected: list[str]) -> list[dict]:
    price = {p["name"].upper(): p for p in PRICING_OPTIONS}
    # los ids de planificación (p. ej. "route53") no coinciden con el nombre de tarifa ("Route 53")
    id_to_name = {"ROUTE53": "ROUTE 53"}
    rows = []
    for i, name in enumerate(selected, start=1):
        name = id_to_name.get(name.upper(), name)
        p = price.get(name.upper()) or price.get(name)
        if not p:
            # buscar por coincidencia parcial
            for k, v in price.items():
                if k in name.upper() or name.upper() in k:
                    p = v
                    break
        if not p:
            continue
        monthly = round(p["rate"] * p["hours"], 2)
        rows.append(
            {
                "id": i,
                "service": p["name"],
                "quantity": 1,
                "hours": p["hours"],
                "rate": p["rate"],
                "monthly": monthly,
            }
        )
    return rows


@router.post("/{proposal_id}/apply-to-costs")
def apply_to_costs(proposal_id: int):
    res = get_supabase().table("proposals").select("*").eq("id", proposal_id).limit(1).execute()
    if not res.data:
        raise HTTPException(404, detail="Propuesta no encontrada")
    prop = res.data[0]
    rows = _proposal_to_cost_rows(prop.get("selected") or [])
    if not rows:
        raise HTTPException(400, detail="La propuesta no tiene servicios con tarifa definida")
    region_id = prop["region_id"]
    get_supabase().table("cost_overrides").upsert(
        {"region_id": region_id, "rows": rows}
    ).execute()
    return {"regionId": region_id, "source": "custom", "rows": rows}