from __future__ import annotations

import asyncio
import ipaddress
import time

import httpx

from app.core.config import get_settings

_lock = asyncio.Lock()
_last_call = 0.0


async def _throttle() -> None:
    """Nominatim: máx. ~1 req/s."""
    global _last_call
    async with _lock:
        now = time.monotonic()
        wait = 1.1 - (now - _last_call)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_call = time.monotonic()


def parse_place(addr: dict) -> dict:
    street = addr.get("road") or addr.get("pedestrian")
    address = None
    if street:
        parts = [street]
        if addr.get("house_number"):
            parts.append(addr["house_number"])
        address = " ".join(parts)
    district = (
        addr.get("city_district")
        or addr.get("municipality")
        or addr.get("city")
        or addr.get("town")
        or addr.get("village")
        or addr.get("suburb")
        or addr.get("county")
        or addr.get("neighbourhood")
    )
    area_parts = []
    for k in ("state_district", "county", "state"):
        v = addr.get(k)
        if v and v != district and v not in area_parts:
            area_parts.append(v)
    return {
        "district": district,
        "address": address,
        "area": ", ".join(area_parts) if area_parts else None,
    }


async def reverse_geocode(lat: float, lon: float) -> dict:
    s = get_settings()
    await _throttle()
    url = f"{s.nominatim_base_url.rstrip('/')}/reverse"
    params = {"format": "jsonv2", "lat": lat, "lon": lon, "addressdetails": 1, "zoom": 18}
    headers = {"User-Agent": s.nominatim_user_agent, "Accept-Language": "es"}
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.get(url, params=params, headers=headers)
        r.raise_for_status()
        data = r.json()
    return parse_place(data.get("address") or {})


# ── Ubicación aproximada por IP (respaldo cuando el GPS no está disponible) ──
# Proveedores gratuitos, sin API key y con HTTPS. Se prueba el primero y, si falla
# (límite diario, caída), el segundo. La consulta se hace desde el backend, así el
# navegador del aula no necesita permisos ni acceso a terceros.
#   1) ipwho.is  → https://ipwhois.io/docs   (1 000 consultas/día)
#   2) ipapi.co  → https://ipapi.co/api/     (≈1 000 consultas/día)

_IP_CACHE_TTL = 3600.0  # segundos: la misma IP no se vuelve a consultar durante 1 h
_ip_cache: dict[str, tuple[float, dict]] = {}


def public_ip(raw: str | None) -> str | None:
    """Devuelve la IP solo si es válida y pública (descarta localhost y redes privadas)."""
    if not raw:
        return None
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


async def _lookup_ipwhois(client: httpx.AsyncClient, ip: str | None) -> dict:
    r = await client.get(f"https://ipwho.is/{ip or ''}", params={"lang": "es"})
    r.raise_for_status()
    d = r.json()
    if not d.get("success", False) or d.get("latitude") is None or d.get("longitude") is None:
        raise RuntimeError(d.get("message") or "ipwho.is no devolvió ubicación")
    return {
        "ip": d.get("ip"),
        "lat": float(d["latitude"]),
        "lon": float(d["longitude"]),
        "city": d.get("city"),
        "region": d.get("region"),
        "country": d.get("country"),
        "provider": "ipwho.is",
    }


async def _lookup_ipapi(client: httpx.AsyncClient, ip: str | None) -> dict:
    url = f"https://ipapi.co/{ip}/json/" if ip else "https://ipapi.co/json/"
    r = await client.get(url, headers={"Accept-Language": "es"})
    r.raise_for_status()
    d = r.json()
    if d.get("error") or d.get("latitude") is None or d.get("longitude") is None:
        raise RuntimeError(d.get("reason") or "ipapi.co no devolvió ubicación")
    return {
        "ip": d.get("ip"),
        "lat": float(d["latitude"]),
        "lon": float(d["longitude"]),
        "city": d.get("city"),
        "region": d.get("region"),
        "country": d.get("country_name"),
        "provider": "ipapi.co",
    }


async def locate_ip(ip: str | None) -> dict:
    """Ubicación aproximada (nivel ciudad) de una IP pública.

    Si `ip` es None (p. ej. desarrollo en localhost) el proveedor usa la IP desde la que
    sale el propio backend, que en local es la de tu red.
    """
    key = ip or "self"
    hit = _ip_cache.get(key)
    if hit and time.monotonic() - hit[0] < _IP_CACHE_TTL:
        return hit[1]

    last_error: Exception | None = None
    async with httpx.AsyncClient(timeout=10.0) as client:
        for lookup in (_lookup_ipwhois, _lookup_ipapi):
            try:
                result = await lookup(client, ip)
            except Exception as e:  # noqa: BLE001 - se prueba el siguiente proveedor
                last_error = e
                continue
            _ip_cache[key] = (time.monotonic(), result)
            return result
    raise RuntimeError(str(last_error) if last_error else "sin proveedores disponibles")