from fastapi import APIRouter, HTTPException, Query, Request

from app.services.geo import locate_ip, public_ip, reverse_geocode
from app.services.snapshot import recommend_region

router = APIRouter(prefix="/geo", tags=["geo"])

# La ubicación por IP es de nivel ciudad: se informa un radio de incertidumbre amplio.
IP_ACCURACY_M = 10_000


def _client_ip(request: Request) -> str | None:
    """IP pública del visitante (detrás de Railway/proxy llega en X-Forwarded-For)."""
    candidates: list[str] = []
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        candidates += [p.strip() for p in forwarded.split(",")]
    real = request.headers.get("x-real-ip")
    if real:
        candidates.append(real)
    if request.client:
        candidates.append(request.client.host)
    for c in candidates:
        ip = public_ip(c)
        if ip:
            return ip
    return None


@router.get("/reverse")
async def reverse(lat: float = Query(...), lon: float = Query(...)):
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise HTTPException(400, detail="Coordenadas inválidas")
    try:
        place = await reverse_geocode(lat, lon)
    except Exception as e:
        raise HTTPException(502, detail=f"Geocoder error: {e}") from e
    return place


@router.get("/ip")
async def ip_location(request: Request):
    """Ubicación aproximada (ciudad) a partir de la IP; respaldo cuando no hay GPS."""
    try:
        loc = await locate_ip(_client_ip(request))
    except Exception as e:
        raise HTTPException(502, detail=f"No se pudo estimar la ubicación por IP: {e}") from e
    return {**loc, "accuracy": IP_ACCURACY_M, "source": "ip"}


@router.get("/recommend-region")
def recommend(lat: float = Query(...), lon: float = Query(...)):
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise HTTPException(400, detail="Coordenadas inválidas")
    return recommend_region(lat, lon)