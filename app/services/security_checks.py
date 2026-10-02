"""Seguridad calculada con datos REALES, sin necesidad de cuenta AWS.

Fuentes:
  - platform:  configuración real del propio backend (CORS, auth, HTTPS, BD)
  - access:    tabla access_audit (GPS + IP + user-agent de cada acceso)
  - planning:  tabla proposals (servicios elegidos en cada planificación de la región)
  - compliance: tabla compliance_status (atestación manual)

Todo lo que exige AWS (IAM, MFA, S3, CloudTrail...) NO se inventa: se informa como
"Sin medir" en el campo `aws`.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from math import asin, cos, radians, sin, sqrt

from app.core.config import get_settings
from app.core.supabase_client import get_supabase, ping_database

SCORE_VALUE = {"healthy": 1.0, "review": 0.5, "issue": 0.0}
IMPOSSIBLE_KMH = 900.0  # más rápido que un avión comercial
LOW_ACCURACY_M = 1000.0


def _km(lat1, lon1, lat2, lon2) -> float:
    dlat, dlon = radians(lat2 - lat1), radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    return 2 * 6371.0 * asin(sqrt(a))


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _check(id_, label, status, detail, source, weight=1.0, recommendation=None):
    return {
        "id": id_,
        "label": label,
        "status": status,  # healthy | review | issue | unknown
        "detail": detail,
        "source": source,
        "weight": weight,
        "recommendation": recommendation,
    }


# ── 1) Plataforma ───────────────────────────────────────────────────────────
def platform_checks(https: bool) -> list[dict]:
    s = get_settings()
    out = []

    try:
        ping_database()
        out.append(_check("db", "Base de datos accesible", "healthy", "Supabase responde.", "platform"))
    except Exception as e:  # noqa: BLE001
        out.append(_check("db", "Base de datos accesible", "issue", f"Supabase no responde: {e}", "platform", 2))

    if s.auth_enabled:
        out.append(_check("auth", "Autenticación del API", "healthy", "AUTH_ENABLED=true.", "platform", 3))
    else:
        out.append(
            _check(
                "auth",
                "Autenticación del API",
                "issue",
                "AUTH_ENABLED=false: cualquiera con la URL puede leer, borrar planificaciones o cambiar el cumplimiento.",
                "platform",
                3,
                "Activar autenticación (JWT) antes de publicar.",
            )
        )

    origins = s.cors_origin_list
    if not origins or "*" in origins:
        out.append(
            _check("cors", "CORS restringido", "issue", "Se aceptan peticiones desde cualquier origen.", "platform", 2,
                   "Definir CORS_ORIGINS con el dominio del front.")
        )
    else:
        out.append(_check("cors", "CORS restringido", "healthy", f"Orígenes permitidos: {', '.join(origins)}.", "platform", 2))

    if https:
        out.append(_check("https", "Conexión cifrada (HTTPS)", "healthy", "La petición llegó por HTTPS.", "platform"))
    else:
        out.append(
            _check("https", "Conexión cifrada (HTTPS)", "review", "La petición llegó por HTTP (normal solo en desarrollo local).",
                   "platform", 1, "Servir el API siempre por HTTPS en producción.")
        )

    # RATE_LIMIT_PER_MINUTE existe en la configuración pero ningún middleware lo aplica.
    out.append(
        _check("ratelimit", "Límite de peticiones", "review",
               f"Configurado en {s.rate_limit_per_minute}/min pero el API no lo aplica todavía.", "platform", 1,
               "Añadir un middleware de rate limiting (p. ej. slowapi).")
    )
    return out


# ── 2) Accesos (access_audit) ───────────────────────────────────────────────
def access_analysis(limit: int = 500) -> dict:
    """Devuelve {checks, stats, events}. events = hallazgos concretos para mostrar."""
    try:
        rows = (
            get_supabase().table("access_audit").select("*").order("created_at", desc=True).limit(limit).execute().data or []
        )
    except Exception as e:  # noqa: BLE001
        return {
            "checks": [_check("access", "Registro de accesos", "unknown", f"No se pudo leer access_audit: {e}", "access")],
            "stats": None,
            "events": [],
        }

    now = datetime.now(timezone.utc)
    rows = [r for r in rows if _parse(r.get("created_at"))]
    rows.sort(key=lambda r: _parse(r["created_at"]))  # cronológico ascendente

    stats = {
        "total": len(rows),
        "last24h": sum(1 for r in rows if _parse(r["created_at"]) >= now - timedelta(hours=24)),
        "last7d": sum(1 for r in rows if _parse(r["created_at"]) >= now - timedelta(days=7)),
        "uniqueIps": len({r.get("ip") for r in rows if r.get("ip")}),
        "uniqueDevices": len({r.get("user_agent") for r in rows if r.get("user_agent")}),
        "uniquePlaces": len({r.get("district") for r in rows if r.get("district")}),
        "lastAccess": rows[-1]["created_at"] if rows else None,
    }

    if not rows:
        return {
            "checks": [_check("access", "Registro de accesos", "unknown", "Aún no hay accesos registrados (abre Auditoría).", "access")],
            "stats": stats,
            "events": [],
        }

    events: list[dict] = []
    cutoff = now - timedelta(days=7)

    # Viaje imposible: dos accesos consecutivos con velocidad > IMPOSSIBLE_KMH
    for prev, cur in zip(rows, rows[1:]):
        t1, t2 = _parse(prev["created_at"]), _parse(cur["created_at"])
        if t2 < cutoff:
            continue
        hours = max((t2 - t1).total_seconds() / 3600, 1 / 60)
        km = _km(prev["lat"], prev["lon"], cur["lat"], cur["lon"])
        # Si alguno es por IP (±10 km) exigimos margen para no dar falsos positivos
        margin = 50 if "ip" in (prev.get("source"), cur.get("source")) else 5
        if km > margin and km / hours > IMPOSSIBLE_KMH:
            events.append({
                "type": "impossible_travel", "severity": "issue", "at": cur["created_at"],
                "title": "Viaje imposible",
                "detail": f"{round(km)} km en {hours:.1f} h entre {prev.get('district') or 'ubicación previa'} y {cur.get('district') or 'ubicación actual'}.",
                "ip": cur.get("ip"),
            })

    # IP / dispositivo nuevo en las últimas 24 h (no visto antes de esa ventana)
    recent_cut = now - timedelta(hours=24)
    old = [r for r in rows if _parse(r["created_at"]) < recent_cut]
    new = [r for r in rows if _parse(r["created_at"]) >= recent_cut]
    if old:
        known_ips = {r.get("ip") for r in old if r.get("ip")}
        known_ua = {r.get("user_agent") for r in old if r.get("user_agent")}
        seen: set[tuple[str, str]] = set()
        for r in new:
            if r.get("ip") and r["ip"] not in known_ips and ("ip", r["ip"]) not in seen:
                seen.add(("ip", r["ip"]))
                events.append({"type": "new_ip", "severity": "review", "at": r["created_at"], "title": "IP nueva",
                               "detail": f"Primer acceso desde {r['ip']} ({r.get('district') or 'ubicación desconocida'}).", "ip": r["ip"]})
            ua = r.get("user_agent")
            if ua and ua not in known_ua and ("ua", ua) not in seen:
                seen.add(("ua", ua))
                events.append({"type": "new_device", "severity": "review", "at": r["created_at"], "title": "Dispositivo nuevo",
                               "detail": f"Navegador/dispositivo no visto antes: {ua[:70]}", "ip": r.get("ip")})

    events.sort(key=lambda e: e["at"], reverse=True)

    # Resumen en checks
    travel = [e for e in events if e["type"] == "impossible_travel"]
    novel = [e for e in events if e["type"] in ("new_ip", "new_device")]
    anonymous = sum(1 for r in rows if not r.get("user_email"))
    imprecise = sum(1 for r in rows if (r.get("accuracy") or 0) >= LOW_ACCURACY_M or r.get("source") == "ip")

    checks = [
        _check("travel", "Viajes imposibles (7 días)",
               "issue" if travel else "healthy",
               f"{len(travel)} detectado(s)." if travel else "Ninguno: las ubicaciones son consistentes en el tiempo.",
               "access", 3, "Revisar si la cuenta fue compartida o comprometida." if travel else None),
        _check("novelty", "IP o dispositivo nuevo (24 h)",
               "review" if novel else "healthy",
               f"{len(novel)} acceso(s) desde IP/dispositivo no visto antes." if novel else "Todo proviene de IPs y dispositivos ya conocidos.",
               "access", 1.5),
        _check("identity", "Accesos identificados",
               "review" if anonymous else "healthy",
               f"{anonymous} de {len(rows)} accesos no tienen usuario asociado." if anonymous else "Todos los accesos tienen usuario.",
               "access", 1.5, "Asociar el correo del usuario al registrar cada acceso (requiere login)." if anonymous else None),
        _check("precision", "Precisión de ubicación",
               "review" if imprecise > len(rows) / 2 else "healthy",
               f"{imprecise} de {len(rows)} accesos tienen ubicación aproximada (IP o ±1 km o más).",
               "access", 0.5),
    ]
    return {"checks": checks, "stats": stats, "events": events[:20]}


# ── 3) Planificaciones (proposals) ──────────────────────────────────────────
def planning_checks(region_id: str) -> list[dict]:
    try:
        rows = get_supabase().table("proposals").select("id,name,selected").eq("region_id", region_id).execute().data or []
    except Exception as e:  # noqa: BLE001
        return [_check("plans", "Planificaciones", "unknown", f"No se pudo leer proposals: {e}", "planning")]
    if not rows:
        return [_check("plans", "Arquitecturas planificadas", "unknown",
                       "No hay planificaciones en esta región para evaluar.", "planning")]

    def sel(r):
        return {str(x).lower() for x in (r.get("selected") or [])}

    exposed = [r for r in rows if sel(r) & {"ec2", "rds", "s3"}]
    no_iam = [r["name"] for r in exposed if "iam" not in sel(r)]
    needs_net = [r for r in rows if sel(r) & {"ec2", "rds"}]
    no_vpc = [r["name"] for r in needs_net if "vpc" not in sel(r)]
    web = [r for r in rows if "ec2" in sel(r) and sel(r) & {"route53", "cloudfront"}]
    no_cdn = [r["name"] for r in web if "cloudfront" not in sel(r)]

    def level(missing, total):
        if not total:
            return "unknown"
        return "healthy" if not missing else ("issue" if len(missing) == total else "review")

    def txt(missing, total, ok_msg):
        if not total:
            return "Ninguna planificación incluye este tipo de recurso."
        return ok_msg if not missing else f"{len(missing)} de {total} sin cubrir: {', '.join(missing[:3])}{'…' if len(missing) > 3 else ''}."

    return [
        _check("plan-iam", "Control de acceso (IAM) en la arquitectura", level(no_iam, len(exposed)),
               txt(no_iam, len(exposed), "Toda arquitectura con cómputo/datos incluye IAM."), "planning", 2,
               "Añadir IAM a las planificaciones con EC2, RDS o S3." if no_iam else None),
        _check("plan-vpc", "Aislamiento de red (VPC)", level(no_vpc, len(needs_net)),
               txt(no_vpc, len(needs_net), "EC2/RDS siempre dentro de una VPC."), "planning", 2,
               "Colocar EC2 y RDS dentro de una VPC." if no_vpc else None),
        _check("plan-cdn", "Capa de entrada protegida (CloudFront)", level(no_cdn, len(web)),
               txt(no_cdn, len(web), "Los servicios web pasan por CloudFront."), "planning", 1,
               "CloudFront reduce exposición directa y permite WAF." if no_cdn else None),
    ]


# ── 4) Cumplimiento (manual) ────────────────────────────────────────────────
def compliance_checks(compliance: list[dict]) -> list[dict]:
    return [
        _check(f"comp-{c['name']}", c["name"], c["status"], c.get("note") or "Sin atestar", "compliance", 1)
        for c in compliance
    ]


# ── Agregado ────────────────────────────────────────────────────────────────
def _worst(checks: list[dict]) -> str:
    st = [c["status"] for c in checks if c["status"] != "unknown"]
    if not st:
        return "unknown"
    return "issue" if "issue" in st else ("review" if "review" in st else "healthy")


def _score(checks: list[dict]) -> int:
    measured = [c for c in checks if c["status"] in SCORE_VALUE]
    total = sum(c["weight"] for c in measured)
    if not total:
        return 0
    return round(sum(SCORE_VALUE[c["status"]] * c["weight"] for c in measured) / total * 100)


def build_real_security(region_id: str, compliance: list[dict], https: bool) -> dict:
    plat = platform_checks(https)
    acc = access_analysis()
    plan = planning_checks(region_id)
    comp = compliance_checks(compliance)

    groups = [
        {"id": "platform", "label": "Plataforma", "checks": plat},
        {"id": "access", "label": "Accesos", "checks": acc["checks"]},
        {"id": "planning", "label": "Planificaciones", "checks": plan},
        {"id": "compliance", "label": "Cumplimiento", "checks": comp},
    ]
    for g in groups:
        g["status"] = _worst(g["checks"])
    all_checks = [c for g in groups for c in g["checks"]]
    return {
        "groups": groups,
        "score": _score(all_checks),
        "accessStats": acc["stats"],
        "accessEvents": acc["events"],
        "complianceStatus": _worst(comp) if comp else "unknown",
    }