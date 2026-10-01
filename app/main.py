from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.routers import audit, catalog, costs, geo, health, proposals, regions, security

settings = get_settings()

app = FastAPI(
    title="Backencito",
    description="Backend CloudOps Dashboard (FastAPI + Supabase)",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API = "/api"
app.include_router(health.router, prefix=API)
app.include_router(catalog.router, prefix=API)
app.include_router(regions.router, prefix=API)
app.include_router(security.router, prefix=API)
app.include_router(proposals.router, prefix=API)
app.include_router(costs.router, prefix=API)
app.include_router(audit.router, prefix=API)
app.include_router(geo.router, prefix=API)


@app.get("/")
def root():
    return {"name": "Backencito", "docs": "/docs", "health": "/api/health"}
