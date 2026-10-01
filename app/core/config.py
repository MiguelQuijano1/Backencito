from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    node_env: str = "development"
    port: int = 4000
    cors_origins: str = "http://localhost:5173"
    app_timezone: str = "America/Lima"
    rate_limit_per_minute: int = 120

    supabase_url: str
    supabase_anon_key: str = ""
    supabase_service_role_key: str

    aws_enabled: bool = False
    aws_region: str = "us-east-1"
    aws_regions: str = "us-east-1,us-west-2,sa-east-1,eu-west-1,eu-central-1,ap-southeast-1"
    enable_cost_explorer: bool = False
    cost_basis: str = "month_to_date"

    auth_enabled: bool = False
    jwt_secret: str = ""
    jwt_expires_in: str = "8h"
    admin_email: str = ""
    admin_password_hash: str = ""

    nominatim_base_url: str = "https://nominatim.openstreetmap.org"
    nominatim_user_agent: str = "Backencito/1.0 (proyecto-escolar)"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def region_list(self) -> list[str]:
        return [r.strip() for r in self.aws_regions.split(",") if r.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
