from fastapi import APIRouter

from app.services.erp_security import erp_security_report

router = APIRouter(prefix="/erp-security", tags=["erp-security"])


@router.get("")
def erp_security(refresh: bool = False):
    """Seguridad del ERP EnterpriseCloud medida desde fuera (solo lectura, sin credenciales)."""
    return erp_security_report(refresh=refresh)