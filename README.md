# Backencito (FastAPI / Python)

Backend de **CloudOps Dashboard** en Python. Equivalente al de TypeScript/Express.

- **BD:** Supabase Data API (`SUPABASE_URL` + `SERVICE_ROLE_KEY`) — sin pooler Postgres
- **AWS:** desactivado por defecto (`AWS_ENABLED=false`)
- **Stack:** FastAPI · Uvicorn · supabase-py · Pydantic · httpx

## Arranque

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env   # Windows: copy | Linux: cp
# Edita .env con tus keys de Supabase

uvicorn app.main:app --reload --port 4000
```

API: `http://localhost:4000`  
Docs: `http://localhost:4000/docs`  
Health: `http://localhost:4000/api/health`

## Endpoints (mismo contrato que el front espera)

| Método | Ruta | Uso |
|--------|------|-----|
| GET | `/api/health` | Estado + DB |
| GET | `/api/regions` | Snapshot regiones |
| GET | `/api/security` / `/api/security/{region_id}` | Seguridad |
| GET/PUT/DELETE | `/api/costs/...` | Costos / escenarios |
| GET | `/api/catalog/services` | Catálogo |
| GET | `/api/catalog/pricing` | Tarifas |
| GET/POST/DELETE | `/api/proposals` | Planificaciones |
| POST/GET | `/api/audit/access` | Auditoría GPS |
| GET | `/api/geo/reverse` | Distrito/dirección |
| GET | `/api/geo/recommend-region` | Región sugerida por lat/lon |

Frontend: `VITE_API_URL=http://localhost:4000/api`
