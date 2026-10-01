from fastapi import APIRouter
from app.core.config import get_settings
from app.core.supabase_client import ping_database

router = APIRouter(tags=["health"])


@router.get("/health")
def health():
    database = "ok"
    database_error = None
    try:
        ping_database()
    except Exception as e:
        database = "error"
        database_error = str(e)
    s = get_settings()
    return {
        "status": "ok" if database == "ok" else "degraded",
        "database": database,
        "databaseError": database_error,
        "awsEnabled": s.aws_enabled,
        "authEnabled": s.auth_enabled,
        "dbDriver": "supabase-py",
        "runtime": "fastapi",
    }
