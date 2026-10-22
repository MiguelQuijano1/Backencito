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

    # URL base del API del ERP EnterpriseCloud que CloudOps vigila (vacío = no configurado)
    erp_api_url: str = ""

    # ── Análisis de proyectos con Gemini (pestaña "Análisis de proyecto" en Seguridad) ──
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.5-flash"
    # Si el modelo principal da 429 (cuota) o 404, se prueban estos en orden (separados por coma).
    gemini_fallback_models: str = "gemini-3.5-flash-lite,gemini-2.5-flash-lite"
    gemini_timeout_seconds: int = 120
    gemini_max_output_tokens: int = 12288
    # Si analizas exactamente los mismos archivos otra vez, se reutiliza el resultado (0 = desactivado) y no gasta cuota.
    analysis_cache_minutes: int = 60
    # Límites pensados para el plan gratuito: ~300 KB de código ≈ 75-100 mil tokens por petición.
    analysis_max_files: int = 150
    analysis_max_file_kb: int = 100
    analysis_max_total_kb: int = 300
    analysis_max_zip_mb: int = 50
    analysis_max_zip_entries: int = 20000

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