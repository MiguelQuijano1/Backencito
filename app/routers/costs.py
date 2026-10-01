from typing import List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core.supabase_client import get_supabase
from app.services.snapshot import build_snapshot

router = APIRouter(prefix="/costs", tags=["costs"])


class CostRow(BaseModel):
    id: int
    service: str
    quantity: float
    hours: float
    rate: float
    monthly: float


class RowsBody(BaseModel):
    rows: List[CostRow] = Field(default_factory=list)


def _totals(rows: list) -> dict:
    monthly = round(sum(float(r["monthly"] if isinstance(r, dict) else r.monthly) for r in rows), 2)
    return {"monthly": monthly, "annual": round(monthly * 12)}


# IMPORTANTE: esta ruta va ANTES de "/{region_id}" para que "summary" no se
# interprete como un id de región.
@router.get("/summary")
def get_global_summary():
    """Vista general del servidor: costos de TODAS las regiones en una sola respuesta."""
    snap = build_snapshot()
    sb = get_supabase()

    overrides = {
        r["region_id"]: r["rows"]
        for r in (sb.table("cost_overrides").select("region_id,rows").execute().data or [])
    }

    proposals_by_region: dict[str, int] = {}
    proposals_total = 0
    for p in sb.table("proposals").select("region_id").execute().data or []:
        proposals_total += 1
        proposals_by_region[p["region_id"]] = proposals_by_region.get(p["region_id"], 0) + 1

    regions_out = []
    by_service: dict[str, dict] = {}

    for region in snap["regions"]:
        rid = region["id"]
        custom = overrides.get(rid)
        rows = (custom if custom is not None else region["costTable"]) or []
        base_source = "aws" if snap["costsAvailable"] else "planning"

        regions_out.append(
            {
                "regionId": rid,
                "name": region["name"],
                "location": region["location"],
                "source": "custom" if custom is not None else base_source,
                "rows": rows,
                "totals": _totals(rows),
                "proposals": proposals_by_region.get(rid, 0),
            }
        )

        for row in rows:
            acc = by_service.setdefault(
                row["service"],
                {"service": row["service"], "monthly": 0.0, "quantity": 0.0, "regions": set()},
            )
            acc["monthly"] += float(row["monthly"])
            acc["quantity"] += float(row["quantity"])
            acc["regions"].add(rid)

    services_out = sorted(
        (
            {
                "service": s["service"],
                "monthly": round(s["monthly"], 2),
                "quantity": s["quantity"],
                "regions": len(s["regions"]),
            }
            for s in by_service.values()
        ),
        key=lambda s: s["monthly"],
        reverse=True,
    )

    all_rows = [row for r in regions_out for row in r["rows"]]
    return {
        "regions": regions_out,
        "byService": services_out,
        "totals": _totals(all_rows),
        "proposalsCount": proposals_total,
        "costBasis": snap["costBasis"],
        "costsAvailable": snap["costsAvailable"],
    }


@router.get("/{region_id}")
def get_costs(region_id: str):
    snap = build_snapshot()
    region = next((r for r in snap["regions"] if r["id"] == region_id), None)
    if not region:
        raise HTTPException(404, detail=f"Región no configurada: {region_id}")
    ov = (
        get_supabase()
        .table("cost_overrides")
        .select("rows")
        .eq("region_id", region_id)
        .limit(1)
        .execute()
        .data
    )
    custom = ov[0]["rows"] if ov else None
    rows = custom if custom is not None else region["costTable"]
    base_source = "aws" if snap["costsAvailable"] else "planning"
    return {
        "regionId": region_id,
        "source": "custom" if custom is not None else base_source,
        "rows": rows,
        "totals": _totals(rows or []),
        "costBasis": snap["costBasis"],
        "costsAvailable": snap["costsAvailable"],
    }


@router.put("/{region_id}/rows")
def put_rows(region_id: str, body: RowsBody):
    snap = build_snapshot()
    if not any(r["id"] == region_id for r in snap["regions"]):
        raise HTTPException(404, detail=f"Región no configurada: {region_id}")
    rows = [r.model_dump() for r in body.rows]
    get_supabase().table("cost_overrides").upsert({"region_id": region_id, "rows": rows}).execute()
    return {"regionId": region_id, "source": "custom", "rows": rows, "totals": _totals(rows)}


@router.delete("/overrides")
def delete_all_overrides():
    # borra todos los escenarios personalizados
    data = get_supabase().table("cost_overrides").delete().neq("region_id", "").execute().data or []
    return {"deleted": len(data), "message": "Escenarios de costos eliminados."}


@router.delete("/{region_id}/rows")
def delete_rows(region_id: str):
    get_supabase().table("cost_overrides").delete().eq("region_id", region_id).execute()
    snap = build_snapshot()
    region = next((r for r in snap["regions"] if r["id"] == region_id), None)
    if not region:
        raise HTTPException(404, detail=f"Región no configurada: {region_id}")
    rows = region["costTable"]
    return {
        "regionId": region_id,
        "source": "planning",
        "rows": rows,
        "totals": _totals(rows or []),
    }