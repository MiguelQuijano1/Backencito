"""Mide la seguridad del ERP EnterpriseCloud (El-Real-Backend) desde fuera, como lo haría un auditor.

Todas las pruebas son de SOLO LECTURA y no necesitan credenciales del ERP:
  - no se intenta iniciar sesión (así no se bloquea ninguna cuenta ni se ensucia la auditoría del ERP),
  - no se envían datos ni se modifica nada.

Lo que no se puede medir de forma segura (p. ej. el límite de peticiones) se informa como "unknown"
(sin medir); no se inventa un resultado.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from app.core.config import get_settings

TIMEOUT = 6.0
CACHE_SECONDS = 30
EVIL_ORIGIN = "https://origen-no-autorizado.example"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

# Rutas de listado del ERP que NUNCA deben responder sin sesión.
PROTECTED_PATHS = [
    "/users", "/roles", "/permissions", "/audit", "/settings", "/customers", "/suppliers", "/products",
    "/categories", "/warehouses", "/drivers", "/vehicles", "/quotations", "/sales-orders", "/sales-invoices",
    "/purchase-requests", "/purchase-orders", "/supplier-products", "/goods-receipts", "/stock", "/kardex",
    "/transfers", "/adjustments", "/receivables", "/payables", "/cash", "/bank-accounts", "/bank-movements",
    "/documents", "/dashboard",
]
REQUIRED_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": None,
    "referrer-policy": None,
    "cache-control": None,
}
SCORE_VALUE = {"healthy": 1.0, "review": 0.5, "issue": 0.0}

_cache: dict[str, object] = {"at": 0.0, "url": "", "data": None}


def _check(id_, label, status, detail, weight=1.0, recommendation=None) -> dict:
    return {
        "id": id_, "label": label, "status": status, "detail": detail,
        "source": "erp", "weight": weight, "recommendation": recommendation,
    }


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


def _is_local(host: str | None) -> bool:
    return (host or "").lower() in LOCAL_HOSTS


# ── Pruebas ────────────────────────────────────────────────────────────────
def _availability(c: httpx.Client, api: str) -> tuple[list[dict], bool]:
    try:
        r = c.get(f"{api}/health")
    except httpx.HTTPError as e:
        return [_check("erp-reach", "El ERP responde", "unknown",
                       f"No se pudo conectar con {api}: {type(e).__name__}. ¿Está encendido el backend del ERP?", 2)], False
    if r.status_code == 200:
        return [_check("erp-health", "Disponibilidad del ERP y su base de datos", "healthy",
                       "El endpoint /health responde y la base de datos está conectada.", 2)], True
    return [_check("erp-health", "Disponibilidad del ERP y su base de datos", "issue",
                   f"/health respondió {r.status_code}: la base de datos del ERP no está disponible.", 2,
                   "Revisar SUPABASE_URL y la service_role del ERP.")], True


def _https(api: str) -> dict:
    u = urlparse(api)
    if u.scheme == "https":
        return _check("erp-https", "Conexión cifrada (HTTPS)", "healthy", "El ERP se sirve por HTTPS.", 2)
    if _is_local(u.hostname):
        return _check("erp-https", "Conexión cifrada (HTTPS)", "review",
                      "El ERP se mide por HTTP en localhost (normal solo en desarrollo).", 2,
                      "En producción servir el ERP detrás de HTTPS (Nginx u otro proxy).")
    return _check("erp-https", "Conexión cifrada (HTTPS)", "issue",
                  "El ERP se sirve por HTTP en un servidor remoto: usuarios y contraseñas viajan sin cifrar.", 3,
                  "Poner HTTPS delante del ERP antes de publicarlo.")


def _auth_required(c: httpx.Client, api: str) -> list[dict]:
    exposed, protected, errors = [], 0, 0
    for path in PROTECTED_PATHS:
        try:
            r = c.get(f"{api}{path}")
        except httpx.HTTPError:
            errors += 1
            continue
        if r.status_code in (401, 403):
            protected += 1
        elif 200 <= r.status_code < 300:
            exposed.append(path)
        # 404/405/5xx: ruta no aplicable; no cuenta ni a favor ni en contra.
    out = []
    if exposed:
        out.append(_check("erp-auth", "Rutas protegidas por sesión", "issue",
                          f"{len(exposed)} ruta(s) responden SIN iniciar sesión: {', '.join(exposed[:4])}.", 3,
                          "Todas las rutas deben exigir un token JWT (política por defecto: denegar)."))
    elif protected:
        out.append(_check("erp-auth", "Rutas protegidas por sesión", "healthy",
                          f"{protected} de {protected + len(exposed)} rutas probadas rechazan peticiones sin sesión (401/403).", 3))
    else:
        out.append(_check("erp-auth", "Rutas protegidas por sesión", "unknown",
                          "No se pudo comprobar: ninguna ruta de prueba devolvió una respuesta evaluable.", 3))

    try:
        r = c.get(f"{api}/users", headers={"Authorization": "Bearer token.falso.invalido"})
        if r.status_code in (401, 403):
            out.append(_check("erp-badtoken", "Rechazo de tokens falsos", "healthy",
                              "Un token inventado es rechazado con " + str(r.status_code) + ".", 2))
        elif 200 <= r.status_code < 300:
            out.append(_check("erp-badtoken", "Rechazo de tokens falsos", "issue",
                              "Un token inventado fue aceptado.", 3, "Validar la firma y la sesión del JWT en cada petición."))
        else:
            out.append(_check("erp-badtoken", "Rechazo de tokens falsos", "unknown", f"Respuesta no evaluable ({r.status_code}).", 2))
    except httpx.HTTPError:
        out.append(_check("erp-badtoken", "Rechazo de tokens falsos", "unknown", "Sin respuesta del ERP.", 2))
    return out


def _headers(c: httpx.Client, api: str) -> dict:
    try:
        r = c.get(f"{api}/health")
    except httpx.HTTPError:
        return _check("erp-headers", "Cabeceras de seguridad HTTP", "unknown", "Sin respuesta del ERP.", 1.5)
    h = {k.lower(): v for k, v in r.headers.items()}
    missing = []
    for name, expected in REQUIRED_HEADERS.items():
        value = h.get(name)
        if not value or (expected and expected not in value.lower()):
            missing.append(name)
    hsts_note = ""
    if urlparse(api).scheme == "https":
        if "strict-transport-security" not in h:
            missing.append("strict-transport-security")
    else:
        hsts_note = " HSTS no se evalúa porque la prueba es por HTTP."
    if not missing:
        return _check("erp-headers", "Cabeceras de seguridad HTTP", "healthy",
                      "Presentes: X-Content-Type-Options, X-Frame-Options, Referrer-Policy y Cache-Control." + hsts_note, 1.5)
    return _check("erp-headers", "Cabeceras de seguridad HTTP", "review" if len(missing) <= 2 else "issue",
                  f"Faltan: {', '.join(missing)}." + hsts_note, 1.5,
                  "Añadirlas en el middleware del ERP o en el proxy.")


def _cors(c: httpx.Client, api: str) -> dict:
    leaks = []
    try:
        r = c.get(f"{api}/health", headers={"Origin": EVIL_ORIGIN})
        acao = r.headers.get("access-control-allow-origin")
        if acao in ("*", EVIL_ORIGIN):
            leaks.append(f"GET permitió el origen {acao}")
        r = c.options(f"{api}/users", headers={
            "Origin": EVIL_ORIGIN, "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        })
        acao = r.headers.get("access-control-allow-origin")
        if acao in ("*", EVIL_ORIGIN):
            leaks.append(f"el preflight permitió el origen {acao}")
    except httpx.HTTPError:
        return _check("erp-cors", "CORS restringido", "unknown", "Sin respuesta del ERP.", 2)
    if leaks:
        return _check("erp-cors", "CORS restringido", "issue", "Un sitio ajeno podría llamar al ERP desde el navegador: " + "; ".join(leaks) + ".", 2,
                      "Definir CORS_ORIGINS solo con el dominio del frontend.")
    return _check("erp-cors", "CORS restringido", "healthy", "Un origen no autorizado es rechazado (GET y preflight).", 2)


def _docs(c: httpx.Client, host: str, api: str) -> dict:
    open_paths = []
    for path in ("/docs", "/openapi.json"):
        try:
            if c.get(f"{host}{path}").status_code == 200:
                open_paths.append(path)
        except httpx.HTTPError:
            pass
    if not open_paths:
        return _check("erp-docs", "Documentación de la API oculta", "healthy", "/docs y /openapi.json no están expuestos.", 1.5)
    if _is_local(urlparse(api).hostname):
        return _check("erp-docs", "Documentación de la API oculta", "review",
                      f"{', '.join(open_paths)} visibles (normal en desarrollo).", 1.5,
                      "En producción usar ENVIRONMENT=production: el ERP los desactiva.")
    return _check("erp-docs", "Documentación de la API oculta", "issue",
                  f"{', '.join(open_paths)} visibles en un servidor remoto: revelan toda la superficie de la API.", 2,
                  "Poner ENVIRONMENT=production en el ERP.")


def _error_leak(c: httpx.Client, api: str) -> dict:
    try:
        r = c.get(f"{api}/ruta-que-no-existe-{int(time.time())}")
    except httpx.HTTPError:
        return _check("erp-errors", "Errores sin detalles internos", "unknown", "Sin respuesta del ERP.", 1)
    body = r.text[:4000]
    if "Traceback" in body or 'File "' in body:
        return _check("erp-errors", "Errores sin detalles internos", "issue",
                      "Una ruta inexistente devolvió una traza de Python.", 2, "Registrar el error en el servidor y devolver un mensaje genérico.")
    return _check("erp-errors", "Errores sin detalles internos", "healthy", "Los errores no revelan trazas ni rutas internas.", 1)


# ── Agregado ───────────────────────────────────────────────────────────────
def _measure(api: str) -> dict:
    u = urlparse(api)
    host = f"{u.scheme}://{u.netloc}"
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False) as c:
        avail, reachable = _availability(c, api)
        groups = [{"id": "availability", "label": "Disponibilidad", "checks": avail}]
        if reachable:
            groups += [
                {"id": "auth", "label": "Autenticación y acceso", "checks": _auth_required(c, api)},
                {"id": "transport", "label": "Transporte y navegador",
                 "checks": [_https(api), _headers(c, api), _cors(c, api)]},
                {"id": "exposure", "label": "Exposición de información",
                 "checks": [_docs(c, host, api), _error_leak(c, api)]},
                {"id": "unmeasured", "label": "Sin medir", "checks": [
                    _check("erp-ratelimit", "Límite de peticiones y bloqueo de cuenta", "unknown",
                           "No se prueba de forma activa para no bloquear inicios de sesión reales; revisar en el código del ERP.", 1)]},
            ]
    for g in groups:
        g["status"] = _worst(g["checks"])
    all_checks = [ck for g in groups for ck in g["checks"]]
    return {
        "configured": True,
        "reachable": reachable,
        "erpUrl": api,
        "checkedAt": datetime.now(timezone.utc).isoformat(),
        "score": _score(all_checks),
        "status": _worst(all_checks),
        "groups": groups,
    }


def erp_security_report(refresh: bool = False) -> dict:
    api = (get_settings().erp_api_url or "").strip().rstrip("/")
    if not api:
        return {"configured": False, "reachable": False, "erpUrl": "", "checkedAt": None, "score": 0, "status": "unknown", "groups": []}
    now = time.time()
    if not refresh and _cache["data"] is not None and _cache["url"] == api and now - float(_cache["at"]) < CACHE_SECONDS:
        return _cache["data"]  # type: ignore[return-value]
    data = _measure(api)
    _cache.update(at=now, url=api, data=data)
    return data