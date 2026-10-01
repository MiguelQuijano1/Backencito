from fastapi import APIRouter
from app.core.catalog import PRICING_OPTIONS, SERVICE_CATALOG, SERVICE_CATEGORIES

router = APIRouter(prefix="/catalog", tags=["catalog"])


@router.get("/services")
def services():
    return {"services": SERVICE_CATALOG, "categories": SERVICE_CATEGORIES}


@router.get("/pricing")
def pricing():
    return {"options": PRICING_OPTIONS}
