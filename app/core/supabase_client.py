from functools import lru_cache
from supabase import create_client, Client
from app.core.config import get_settings


@lru_cache
def get_supabase() -> Client:
    s = get_settings()
    return create_client(s.supabase_url, s.supabase_service_role_key)


def ping_database() -> None:
    client = get_supabase()
    res = client.table("schema_migrations").select("name").limit(1).execute()
    # si la tabla no existe, supabase lanza; si existe, ok
    _ = res.data
