from fastapi import APIRouter, HTTPException, Query

from app.services.geo import reverse_geocode
from app.services.snapshot import recommend_region

router = APIRouter(prefix="/geo", tags=["geo"])


@router.get("/reverse")
async def reverse(lat: float = Query(...), lon: float = Query(...)):
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise HTTPException(400, detail="Coordenadas inválidas")
    try:
        place = await reverse_geocode(lat, lon)
    except Exception as e:
        raise HTTPException(502, detail=f"Geocoder error: {e}") from e
    return place


@router.get("/recommend-region")
def recommend(lat: float = Query(...), lon: float = Query(...)):
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise HTTPException(400, detail="Coordenadas inválidas")
    return recommend_region(lat, lon)
