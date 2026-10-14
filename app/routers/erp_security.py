from fastapi import APIRouter

from app.services.erp_modules import erp_modules_report
from app.services.erp_security import erp_security_report

router = APIRouter(prefix="/erp-security", tags=["erp-security"])


@router.get("")
def erp_security(refresh: bool = False):
    """Seguridad del ERP EnterpriseCloud medida desde fuera (solo lectura, sin credenciales)."""
    return erp_security_report(refresh=refresh)


@router.get("/modules")
def erp_security_modules(refresh: bool = False):
    """Seguridad por módulo del ERP: puntaje actual, brechas, servicios AWS, costo y ranking."""
    return erp_modules_report(refresh=refresh)