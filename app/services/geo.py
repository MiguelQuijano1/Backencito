from __future__ import annotations

import asyncio
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
