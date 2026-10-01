from fastapi import APIRouter
from app.services.snapshot import build_snapshot

router = APIRouter(prefix="/regions", tags=["regions"])


@router.get("")
def list_regions():
    snap = build_snapshot()
    return {
        "regions": snap["regions"],
        "meta": {
            **snap.get("meta", {}),
            "generatedAt": snap["generatedAt"],
            "accountId": snap["accountId"],
            "costBasis": snap["costBasis"],
            "costsAvailable": snap["costsAvailable"],
            "warnings": snap["warnings"],
        },
    }


@router.get("/{region_id}")
def get_region(region_id: str):
    snap = build_snapshot()
    for r in snap["regions"]:
        if r["id"] == region_id:
            return {"region": r, "meta": snap.get("meta", {})}
    return {"error": {"code": "not_found", "message": f"Región no configurada: {region_id}"}}
