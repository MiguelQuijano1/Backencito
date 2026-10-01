-- ═══════════════════════════════════════════════════════════════════
--  CloudOPS · Esquema que necesita Backencito (FastAPI + supabase-py)
--
--  Derivado de lo que el código realmente lee/escribe:
--    schema_migrations  → app/core/supabase_client.py (ping de /api/health)
--    proposals          → app/routers/proposals.py
--    cost_overrides     → app/routers/costs.py  (upsert por region_id)
--    compliance_status  → app/routers/security.py (upsert por framework)
--    access_audit       → app/routers/audit.py
--
--  IDEMPOTENTE: se puede ejecutar varias veces sin romper datos existentes.
--  No borra ni modifica filas. Ejecútalo en Supabase → SQL Editor.
-- ═══════════════════════════════════════════════════════════════════

-- ── 1) Tablas (solo se crean si no existen) ─────────────────────────

create table if not exists public.schema_migrations (
  name       text primary key,
  applied_at timestamptz not null default now()
);

create table if not exists public.proposals (
  id           bigint generated always as identity primary key,
  name         text        not null,
  type         text        not null,
  description  text        not null default '',
  region_id    text        not null,
  users        text        not null,
  availability text        not null,
  migration    text        not null,
  selected     text[]      not null default '{}',
  created_at   timestamptz not null default now()
);

create table if not exists public.cost_overrides (
  region_id  text primary key,
  rows       jsonb       not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);

create table if not exists public.compliance_status (
  framework  text primary key,
  status     text not null check (status in ('healthy', 'review', 'issue')),
  note       text,
  updated_at timestamptz not null default now()
);

create table if not exists public.access_audit (
  id         bigint generated always as identity primary key,
  user_email text,
  lat        double precision not null,
  lon        double precision not null,
  accuracy   double precision,
  source     text not null,
  district   text,
  address    text,
  area       text,
  ip         text,
  user_agent text,
  created_at timestamptz not null default now()
);

-- ── 2) Si las tablas ya existían, asegura las columnas que usa el código ──

alter table public.proposals add column if not exists description text not null default '';
alter table public.proposals add column if not exists selected    text[] not null default '{}';
alter table public.proposals add column if not exists created_at  timestamptz not null default now();

alter table public.access_audit add column if not exists district text;
alter table public.access_audit add column if not exists address  text;
alter table public.access_audit add column if not exists area     text;

-- ── 3) El upsert de supabase-py necesita PK/UNIQUE en la columna clave ──
--      (si ya tienen PK, estos bloques no hacen nada)

do $$
begin
  if not exists (
    select 1 from pg_index i
    join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any(i.indkey)
    where i.indrelid = 'public.cost_overrides'::regclass
      and i.indisunique and i.indnatts = 1 and a.attname = 'region_id'
  ) then
    create unique index cost_overrides_region_id_uidx on public.cost_overrides (region_id);
  end if;

  if not exists (
    select 1 from pg_index i
    join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any(i.indkey)
    where i.indrelid = 'public.compliance_status'::regclass
      and i.indisunique and i.indnatts = 1 and a.attname = 'framework'
  ) then
    create unique index compliance_status_framework_uidx on public.compliance_status (framework);
  end if;
end $$;

-- ── 4) Índices para las consultas del Dashboard ─────────────────────

create index if not exists proposals_region_created_idx on public.proposals (region_id, created_at desc);
create index if not exists access_audit_created_idx     on public.access_audit (created_at desc);

-- ── 5) Seguridad: RLS activado SIN políticas ────────────────────────
--  El backend usa la SERVICE_ROLE key (bypassa RLS) y el front NUNCA habla
--  directo con Supabase (todo va por /api). Con RLS y sin políticas, la
--  anon key queda sin acceso a nada — importante en access_audit (GPS + IP).

alter table public.schema_migrations enable row level security;
alter table public.proposals         enable row level security;
alter table public.cost_overrides    enable row level security;
alter table public.compliance_status enable row level security;
alter table public.access_audit      enable row level security;

-- ── 6) Marca de migración (la usa /api/health) ──────────────────────

insert into public.schema_migrations (name) values ('2026_10_cloudops_base')
on conflict (name) do nothing;


-- ═══════════════════════════════════════════════════════════════════
--  VERIFICACIÓN (opcional): ejecuta estas consultas aparte para revisar
-- ═══════════════════════════════════════════════════════════════════
-- Columnas y tipos reales:
--   select table_name, column_name, data_type, is_nullable
--   from information_schema.columns
--   where table_schema = 'public'
--     and table_name in ('schema_migrations','proposals','cost_overrides','compliance_status','access_audit')
--   order by table_name, ordinal_position;
--
-- RLS por tabla (rowsecurity debe ser true en las 5):
--   select tablename, rowsecurity from pg_tables where schemaname = 'public';
--
-- Cuántas planificaciones hay y su rango de fechas (alimenta la tendencia):
--   select region_id, count(*), min(created_at), max(created_at)
--   from public.proposals group by region_id order by region_id;