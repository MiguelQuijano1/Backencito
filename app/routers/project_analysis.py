import threading

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.core.config import get_settings
from app.services.project_analyzer import TESTS_RISK_THRESHOLD, analyze_project, extract_zip

router = APIRouter(prefix="/project-analysis", tags=["project-analysis"])

# Un análisis a la vez: protege la cuota gratuita de Gemini.
_busy = threading.Lock()


@router.get("/status")
def project_analysis_status():
    """Indica si Gemini está configurado y cuáles son los límites de subida."""
    s = get_settings()
    return {
        "configured": bool(s.gemini_api_key),
        "model": s.gemini_model,
        "maxFiles": s.analysis_max_files,
        "maxFileKb": s.analysis_max_file_kb,
        "maxTotalKb": s.analysis_max_total_kb,
        "maxZipMb": s.analysis_max_zip_mb,
        "testsRiskThreshold": TESTS_RISK_THRESHOLD,
    }


@router.post("")
def project_analysis(files: list[UploadFile] = File(...), paths: list[str] = Form(default=[])):
    """Recibe un .zip del proyecto (o archivos sueltos) por multipart y devuelve el análisis hecho con Gemini."""
    s = get_settings()
    if len(files) > s.analysis_max_files * 5:
        raise HTTPException(400, detail="Demasiados archivos. Sube solo el código del proyecto (sin node_modules ni .git).")

    # Si el navegador envió las rutas relativas por separado, se usan; si no, el nombre del archivo.
    use_paths = len(paths) == len(files)
    items: list[tuple[str, bytes]] = []
    pre_skipped: dict[str, int] = {}
    file_limit = s.analysis_max_file_kb * 1024 + 1
    zip_limit = s.analysis_max_zip_mb * 1024 * 1024
    for i, f in enumerate(files):
        name = paths[i] if use_paths else (f.filename or "")
        head = f.file.read(4)
        f.file.seek(0)
        if name.lower().endswith(".zip") or head == b"PK\x03\x04":
            data = f.file.read(zip_limit + 1)
            if len(data) > zip_limit:
                raise HTTPException(413, detail=f"El zip supera {s.analysis_max_zip_mb} MB. Quita node_modules, .git y carpetas de compilación antes de comprimirlo.")
            extracted, skipped = extract_zip(data)
            items.extend(extracted)
            for reason, n in skipped.items():
                pre_skipped[reason] = pre_skipped.get(reason, 0) + n
        else:
            items.append((name, f.file.read(file_limit)))

    if not _busy.acquire(blocking=False):
        raise HTTPException(429, detail="Ya hay un análisis en curso. Espera a que termine e inténtalo de nuevo.")
    try:
        return analyze_project(items, pre_skipped)
    finally:
        _busy.release()