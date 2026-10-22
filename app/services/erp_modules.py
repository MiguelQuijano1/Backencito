"""Seguridad del ERP medida POR MÓDULO (Ventas, Compras, Inventario, Finanzas...).

Cada control tiene un origen distinto y se muestra como tal:
  - "measured": se comprueba en vivo contra el ERP (p. ej. que las rutas del módulo exijan sesión).
  - "declared": sale de lo que el código del ERP implementa; no se puede verificar desde fuera.
  - "gap":      lo que el ERP NO cubre y un servicio de AWS podría cubrir (con costo y efecto colateral).

Ningún servicio cubre el 100 %: cada uno tiene un factor `coverage` < 1, por eso el puntaje
"con AWS" nunca llega a 100. Los factores, pesos y supuestos de costo son editables aquí.
Tarifas: precios públicos de AWS (us-east-1), verificados el 14/10/2026.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

import httpx

from app.core.config import get_settings
from app.services.erp_security import TIMEOUT, erp_security_report

CACHE_SECONDS = 30
_cache: dict[str, object] = {"at": 0.0, "url": "", "data": None}
PRICES_VERIFIED = "14/10/2026"

# ── Servicios AWS que cubren brechas ───────────────────────────────────────
# monthly_usd = estimación con los supuestos indicados (tarifas públicas).
SERVICES: dict[str, dict] = {
    "waf": {
        "label": "AWS WAF (firewall de aplicación web)", "coverage": 0.6,
        "monthly_usd": round(5 + 5 * 1 + 0.6 * 5, 2),
        "assumption": "1 Web ACL ($5) + 5 reglas ($1 c/u) + 5 M de peticiones/mes ($0,60 por millón).",
        "side_effect": "Una regla demasiado estricta puede bloquear peticiones legítimas (falsos positivos); hay que afinarla y vigilarla.",
    },
    "threat": {
        "label": "Amazon GuardDuty (detección de amenazas)", "coverage": 0.5,
        "monthly_usd": round(1 * 4 + 5 * 1, 2),
        "assumption": "1 M de eventos de administración ($4 por millón) + 5 GB de logs de red ($1 por GB). 30 días de prueba gratis.",
        "side_effect": "Genera alertas que alguien debe revisar; sin responsable, el servicio se paga pero no protege.",
    },
    "backup": {
        "label": "AWS Backup (copias de seguridad)", "coverage": 0.8,
        "monthly_usd": round(20 * 0.05, 2),
        "assumption": "20 GB protegidos a $0,05 por GB-mes (varía según el servicio respaldado).",
        "side_effect": "Restaurar una copia puede sobrescribir datos más nuevos, y el costo crece con el tamaño de la base.",
    },
    "kms": {
        "label": "AWS KMS (cifrado con claves propias)", "coverage": 0.7,
        "monthly_usd": round(1 + 0.03 * ((200_000 - 20_000) / 10_000), 2),
        "assumption": "1 clave ($1/mes) + 200 mil operaciones/mes ($0,03 por 10 mil, tras 20 mil gratis).",
        "side_effect": "Cada lectura cifrada añade una llamada a KMS (algo de latencia); si se pierde o borra la clave, los datos no se recuperan.",
    },
    "secrets": {
        "label": "AWS Secrets Manager (gestión de secretos)", "coverage": 0.7,
        "monthly_usd": round(3 * 0.40 + 300_000 / 10_000 * 0.05, 2),
        "assumption": "3 secretos (JWT, service_role, base de datos) a $0,40 + 300 mil llamadas/mes ($0,05 por 10 mil).",
        "side_effect": "El ERP depende de AWS para arrancar: si falla la consulta del secreto, no inicia.",
    },
    "mfa": {
        "label": "MFA para usuarios del ERP (p. ej. Amazon Cognito)", "coverage": 0.8,
        "monthly_usd": None,
        "assumption": "Costo por usuario activo; no verificado. Cotizar en la AWS Pricing Calculator.",
        "side_effect": "Un paso más al iniciar sesión; hay que prever cómo recuperar el acceso si un usuario pierde su segundo factor.",
    },
}

GAP_TEXT = {
    "waf": "Delante del ERP no hay un firewall de aplicación: solo cuenta con el límite de peticiones del propio backend.",
    "threat": "No hay detección de comportamiento anómalo en la cuenta ni en la red; el ERP solo registra sus propias acciones.",
    "backup": "No se midió ninguna política propia de copias de seguridad ni pruebas de restauración.",
    "kms": "No se midió cifrado con claves administradas por el equipo; se depende del cifrado por defecto del proveedor.",
    "secrets": "Las claves (JWT, service_role) viven en variables de entorno de la plataforma, sin rotación automática.",
    "mfa": "El ERP guarda un indicador de MFA, pero el inicio de sesión no lo exige.",
}

# ── Módulos del ERP ────────────────────────────────────────────────────────
# criticality: qué tan grave es una falla en ese módulo (0-1). gaps: (servicio, peso).
# Los módulos y rutas espejan el catálogo de permisos del ERP (app/security/catalog.py) y su router (/api/v1).
MODULES = [
    {"id": "finanzas", "label": "Finanzas", "criticality": 1.0,
     "paths": ["/receivables", "/payables", "/cash", "/bank-accounts", "/bank-movements"],
     "gaps": [("waf", 2), ("threat", 2), ("backup", 3), ("kms", 3)]},
    {"id": "sistema", "label": "Administración del sistema", "criticality": 1.0,
     "paths": ["/users", "/roles", "/permissions", "/audit", "/settings"],
     "gaps": [("waf", 2), ("threat", 3), ("secrets", 3), ("kms", 2), ("backup", 2)]},
    {"id": "ventas", "label": "Ventas", "criticality": 0.8,
     "paths": ["/quotations", "/sales-orders", "/sales-invoices"],
     "gaps": [("waf", 2), ("threat", 2), ("backup", 2), ("kms", 1)]},
    {"id": "compras", "label": "Compras", "criticality": 0.8,
     "paths": ["/purchase-requests", "/purchase-orders", "/supplier-products"],
     "gaps": [("waf", 2), ("threat", 2), ("backup", 2), ("kms", 1)]},
    {"id": "inventario", "label": "Inventario y Kardex", "criticality": 0.6,
     "paths": ["/stock", "/goods-receipts", "/kardex", "/transfers", "/adjustments"],
     "gaps": [("waf", 2), ("threat", 2), ("backup", 2)]},
    {"id": "mantenimiento", "label": "Mantenimiento (datos maestros)", "criticality": 0.6,
     "paths": ["/customers", "/suppliers", "/products", "/categories", "/warehouses", "/drivers", "/vehicles"],
     "gaps": [("waf", 2), ("threat", 2), ("backup", 3)]},
    {"id": "documentos", "label": "Documentos y reportes", "criticality": 0.5,
     "paths": ["/documents", "/dashboard"],
     "gaps": [("waf", 2), ("threat", 2), ("kms", 2), ("backup", 1)]},
]

# Controles que el ERP implementa (según su código). Se muestran como "declarado".
DECLARED = [
    ("rbac", "Permisos por rol y acción", 3,
     "El ERP exige un permiso por módulo y acción en cada ruta (verificado por las pruebas de políticas de ruta del repositorio)."),
    ("audit", "Auditoría de acciones", 2,
     "Las acciones quedan registradas en la auditoría del ERP (servicio de auditoría en el backend)."),
    ("rate", "Límite de peticiones y bloqueo de cuenta", 1,
     "El backend limita las peticiones por IP (global y 10 inicios de sesión por minuto) y bloquea la cuenta tras varios intentos fallidos."),
]

SCORE_VALUE = {"healthy": 1.0, "review": 0.5, "issue": 0.0}


def _probe_auth(c: httpx.Client, api: str, paths: list[str]) -> tuple[int, int, list[str]]:
    protected = exposed = 0
    exposed_paths: list[str] = []
    for p in paths:
        try:
            r = c.get(f"{api}{p}")
        except httpx.HTTPError:
            continue
        if r.status_code in (401, 403):
            protected += 1
        elif 200 <= r.status_code < 300:
            exposed += 1
            exposed_paths.append(p)
    return protected, exposed, exposed_paths


def _transport_value(base: dict) -> float | None:
    for g in base.get("groups", []):
        if g["id"] == "transport":
            vals = [SCORE_VALUE[c["status"]] for c in g["checks"] if c["status"] in SCORE_VALUE]
            return sum(vals) / len(vals) if vals else None
    return None


def _control(id_, label, state, value, weight, detail, service=None) -> dict:
    return {"id": id_, "label": label, "state": state, "value": value, "weight": weight,
            "detail": detail, "service": service}


def _scores(controls: list[dict]) -> tuple[int, int]:
    """(actual, con AWS). Los controles sin medir (value None) no cuentan ni a favor ni en contra."""
    used = [c for c in controls if c["value"] is not None]
    total = sum(c["weight"] for c in used)
    if not total:
        return 0, 0
    actual = sum(c["weight"] * (0.0 if c["state"] == "gap" else c["value"]) for c in used)
    with_aws = sum(
        c["weight"] * (SERVICES[c["service"]]["coverage"] if c["state"] == "gap" else c["value"]) for c in used
    )
    return round(actual / total * 100), round(with_aws / total * 100)


def _measure(api: str, base: dict) -> dict:
    transport = _transport_value(base)
    modules = []
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False) as c:
        for m in MODULES:
            protected, exposed, exposed_paths = _probe_auth(c, api, m["paths"])
            n = protected + exposed
            controls = []
            if n:
                controls.append(_control(
                    "auth", "Rutas del módulo exigen sesión", "measured", protected / n, 3,
                    f"{protected} de {n} rutas probadas rechazan peticiones sin sesión."
                    + (f" Expuestas: {', '.join(exposed_paths)}." if exposed_paths else "")))
            else:
                controls.append(_control("auth", "Rutas del módulo exigen sesión", "measured", None, 3,
                                         "No se pudo medir: ninguna ruta de prueba dio una respuesta evaluable."))
            controls.append(_control(
                "transport", "Transporte seguro (HTTPS, cabeceras, CORS)", "measured", transport, 2,
                "Resultado global del ERP (es común a todos los módulos)." if transport is not None else "Sin medir."))
            for id_, label, w, detail in DECLARED:
                controls.append(_control(id_, label, "declared", 1.0, w, detail))
            for svc, w in m["gaps"]:
                controls.append(_control(f"gap-{svc}", SERVICES[svc]["label"], "gap", 0.0, w, GAP_TEXT[svc], svc))
            actual, with_aws = _scores(controls)
            modules.append({
                "id": m["id"], "label": m["label"], "criticality": m["criticality"],
                "score": actual, "scoreWithAws": with_aws,
                "priority": round((100 - actual) * m["criticality"], 1),
                "controls": controls,
            })

        # Eje aparte: identidad y acceso (IAM)
        try:
            r = c.get(f"{api}/users", headers={"Authorization": "Bearer token.falso.invalido"})
            fake_rejected = r.status_code in (401, 403)
        except httpx.HTTPError:
            fake_rejected = None
    iam_controls = [
        _control("iam-token", "Tokens falsos rechazados", "measured",
                 None if fake_rejected is None else (1.0 if fake_rejected else 0.0), 3,
                 "Un token inventado es rechazado." if fake_rejected else "Un token inventado fue aceptado o no se pudo medir."),
        _control("iam-rbac", "Roles y permisos granulares", "declared", 1.0, 3,
                 "Cada usuario tiene un rol con permisos por módulo y acción."),
        _control("iam-lock", "Bloqueo de cuenta por intentos fallidos", "declared", 1.0, 2,
                 "El ERP registra intentos fallidos y bloquea temporalmente la cuenta."),
        _control("iam-mfa", SERVICES["mfa"]["label"], "gap", 0.0, 3, GAP_TEXT["mfa"], "mfa"),
    ]
    iam_actual, iam_aws = _scores(iam_controls)

    modules.sort(key=lambda m: m["priority"], reverse=True)
    for i, m in enumerate(modules, 1):
        m["rank"] = i

    total_crit = sum(m["criticality"] for m in modules)
    overall = round(sum(m["score"] * m["criticality"] for m in modules) / total_crit)
    overall_aws = round(sum(m["scoreWithAws"] * m["criticality"] for m in modules) / total_crit)

    used = {c["service"] for m in modules for c in m["controls"] if c["state"] == "gap"} | {"mfa"}
    services = []
    for sid in ["waf", "threat", "backup", "kms", "secrets", "mfa"]:
        if sid not in used:
            continue
        s = SERVICES[sid]
        covers = [m["label"] for m in modules if any(c.get("service") == sid for c in m["controls"])]
        if sid == "mfa":
            covers = ["Identidad y acceso (IAM)"] + covers
        services.append({"id": sid, "label": s["label"], "monthlyUsd": s["monthly_usd"],
                         "assumption": s["assumption"], "coverage": s["coverage"],
                         "sideEffect": s["side_effect"], "covers": covers})
    plan_cost = round(sum(s["monthlyUsd"] for s in services if s["monthlyUsd"] is not None), 2)
    top = modules[0]
    return {
        "configured": True, "reachable": True, "erpUrl": api,
        "checkedAt": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "score": overall, "scoreWithAws": overall_aws,
            "mostNeeded": {"id": top["id"], "label": top["label"], "score": top["score"]},
            "planCostUsd": plan_cost, "planCostPending": any(s["monthlyUsd"] is None for s in services),
        },
        "iam": {"score": iam_actual, "scoreWithAws": iam_aws, "controls": iam_controls},
        "modules": modules,
        "services": services,
        "notes": [
            f"Costos: estimaciones con las tarifas públicas de AWS (us-east-1, verificadas el {PRICES_VERIFIED}) y los supuestos indicados en cada servicio. Confirmar en la AWS Pricing Calculator.",
            "Ningún servicio cubre el 100 %: cada uno mitiga solo una parte del riesgo (factor de cobertura), por eso el puntaje «con AWS» nunca llega a 100.",
            "Hoy el ERP corre fuera de AWS (backend en Koyeb, base en Supabase). KMS, Backup o Secrets Manager aplican a recursos alojados en AWS: el puntaje «con AWS» es la cobertura que se lograría integrando esos servicios.",
            "Medido = comprobado en vivo contra el ERP. Declarado = implementado según el código del ERP, no verificable desde fuera. Los pesos, la criticidad y los factores de cobertura son criterios del equipo.",
        ],
    }


def erp_modules_report(refresh: bool = False) -> dict:
    api = (get_settings().erp_api_url or "").strip().rstrip("/")
    if not api:
        return {"configured": False, "reachable": False, "erpUrl": "", "checkedAt": None}
    now = time.time()
    if not refresh and _cache["data"] is not None and _cache["url"] == api and now - float(_cache["at"]) < CACHE_SECONDS:
        return _cache["data"]  # type: ignore[return-value]
    base = erp_security_report(refresh=refresh)
    if not base.get("reachable"):
        data = {"configured": True, "reachable": False, "erpUrl": api, "checkedAt": base.get("checkedAt")}
    else:
        data = _measure(api, base)
    _cache.update(at=now, url=api, data=data)
    return data