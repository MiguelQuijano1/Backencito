from typing import Literal, Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.core.supabase_client import get_supabase

router = APIRouter(prefix="/audit", tags=["audit"])


class AccessIn(BaseModel):
    lat: float = Field(ge=-90, le=90)
    lon: float = Field(ge=-180, le=180)
    accuracy: float = Field(ge=0)
    source: Literal["gps"]
    district: Optional[str] = None
    address: Optional[str] = None
    area: Optional[str] = None


@router.post("/access")
def post_access(body: AccessIn, request: Request):
    row = {
        "user_email": None,
        "lat": body.lat,
        "lon": body.lon,
        "accuracy": body.accuracy,
        "source": body.source,
        "district": body.district,
        "address": body.address,
        "area": body.area,
        "ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
    }
    res = get_supabase().table("access_audit").insert(row).execute()
    if not res.data:
        return {"error": "insert failed"}
    d = res.data[0]
    return {"id": int(d["id"]), "createdAt": d.get("created_at")}


@router.get("/access")
def list_access(limit: int = 50):
    limit = max(1, min(limit, 200))
    data = (
        get_supabase()
        .table("access_audit")
        .select("*")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
        .data
        or []
    )
    entries = [
        {
            "id": int(r["id"]),
            "userEmail": r.get("user_email"),
            "lat": r["lat"],
            "lon": r["lon"],
            "accuracy": r.get("accuracy"),
            "source": r["source"],
            "district": r.get("district"),
            "address": r.get("address"),
            "area": r.get("area"),
            "ip": r.get("ip"),
            "userAgent": r.get("user_agent"),
            "createdAt": r.get("created_at"),
        }
        for r in data
    ]
    return {"entries": entries}
