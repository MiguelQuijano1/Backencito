"""Snapshot de regiones. Sin AWS: catálogo real de regiones + costos vacíos (no inventa recursos de cuenta)."""
from __future__ import annotations

from datetime import datetime, timezone
from math import asin, cos, radians, sin, sqrt

from app.core.catalog import COMPLIANCE_FRAMEWORKS, SERVICE_CATALOG
from app.core.config import get_settings
from app.core.regions_meta import REGION_CATALOG, region_meta
from app.core.supabase_client import get_supabase
from app.services.security_checks import build_real_security


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    dlat, dlon = radians(lat2 - lat1), radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    return 2 * r * asin(sqrt(a))


def recommend_region(lat: float, lon: float) -> dict:
    """Región AWS más cercana a la ubicación del usuario."""
    best_id = None
    best_d = float("inf")
    for rid, meta in REGION_CATALOG.items():
        d = _haversine_km(lat, lon, meta["lat"], meta["lon"])
        if d < best_d:
            best_d = d
            best_id = rid
    meta = region_meta(best_id or "sa-east-1")
    return {
        "regionId": meta["id"],
        "name": meta["name"],
        "location": meta["location"],
        "distanceKm": round(best_d, 1),
        "message": f"Por tu ubicación te recomendamos {meta['name']} ({meta['location']}) por menor latencia aproximada.",
    }


def _empty_service_metrics() -> dict:
    return {
        s["id"]: {"status": "available", "resources": 0, "usage": 0, "usageMeasured": False}
        for s in SERVICE_CATALOG
    }


def _list_compliance() -> list[dict]:
    try:
        rows = get_supabase().table("compliance_status").select("framework,status,note").execute().data or []
        mp = {r["framework"]: r for r in rows}
    except Exception:
        mp = {}
    return [
        {
            "name": name,
            "status": mp.get(name, {}).get("status") or "review",
            "note": mp.get(name, {}).get("note") or "Sin atestar",
            "source": "manual",
        }
        for name in COMPLIANCE_FRAMEWORKS
    ]


def build_snapshot(https: bool = False, with_security: bool = False) -> dict:
    settings = get_settings()
    compliance = _list_compliance()
    regions = []
    security: dict = {}
    cost_trends: dict = {}

    for rid in settings.region_list:
        meta = region_meta(rid)
        azs = []
        for i, site in enumerate(meta.get("az_sites") or []):
            letter = chr(ord("a") + i)
            azs.append(
                {
                    "id": f"{rid}{letter}",
                    "letter": letter,
                    "city": site.get("city", ""),
                    "lat": site.get("lat", meta["lat"]),
                    "lon": site.get("lon", meta["lon"]),
                }
            )
        metrics = _empty_service_metrics()
        summary = {
            "iam": "review",
            "mfa": "review",
            "dataProtection": "review",
            "accountProtection": "review",
            "compliance": "review",
        }
        region = {
            "id": meta["id"],
            "name": meta["name"],
            "location": meta["location"],
            "lat": meta["lat"],
            "lon": meta["lon"],
            "status": "operational",
            "securityScore": 0,
            "availability": 0,
            "security": summary,
            "costTable": [],  # costos reales vienen de planificaciones / overrides en BD
            "serviceMetrics": metrics,
            "services": [],
            "azs": azs,
            "costTrend": [],
        }
        regions.append(region)
        real = build_real_security(rid, compliance, https) if with_security else None
        if real and real["complianceStatus"] != "unknown":
            summary = {**summary, "compliance": real["complianceStatus"]}
        security[rid] = {
            "regionId": rid,
            "score": real["score"] if real else 0,
            "awsConnected": settings.aws_enabled,
            "summary": summary,
            "iamCards": [],
            "accountProtection": [],
            "dataProtection": [],
            "compliance": compliance,
            "groups": real["groups"] if real else [],
            "accessStats": real["accessStats"] if real else None,
            "accessEvents": real["accessEvents"] if real else [],
            "generatedAt": datetime.now(timezone.utc).isoformat(),
        }
        cost_trends[rid] = {"services": [], "rows": []}

    warnings = []
    if not settings.aws_enabled:
        warnings.append(
            "AWS_ENABLED=false: no hay inventario de cuenta. Costos del dashboard deben salir de planificaciones (Supabase)."
        )

    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "accountId": None,
        "regions": regions,
        "security": security,
        "costTrends": cost_trends,
        "costBasis": settings.cost_basis,
        "costsAvailable": False,
        "warnings": warnings,
        "meta": {
            "dataMode": "catalog_only" if not settings.aws_enabled else "aws",
            "awsEnabled": settings.aws_enabled,
        },
    }