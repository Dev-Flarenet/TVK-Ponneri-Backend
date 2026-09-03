from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import logging

from services.sms_service import send_status_update_sms, send_otp_sms

logger = logging.getLogger("sms_router")
router = APIRouter(prefix="/sms", tags=["WhatsApp & SMS Notifications"])

class StatusUpdateSmsRequest(BaseModel):
    mobile_number: str
    complaint_no: str
    status: str
    remarks: Optional[str] = ""

class OtpSmsRequest(BaseModel):
    mobile_number: str
    otp: str

@router.post("/send-status-update")
async def handle_send_status_update(req: StatusUpdateSmsRequest):
    """Trigger WhatsApp status notification to citizen."""
    try:
        success = await send_status_update_sms(
            mobile_number=req.mobile_number,
            complaint_no=req.complaint_no,
            status=req.status,
            remarks=req.remarks or ""
        )
        return {"status": "success" if success else "failed", "delivered": success}
    except Exception as e:
        logger.error(f"handle_send_status_update error: {e}")
        return {"status": "error", "message": str(e)}

@router.post("/send-otp")
async def handle_send_otp(req: OtpSmsRequest):
    """Trigger direct WhatsApp OTP dispatch."""
    try:
        success = await send_otp_sms(mobile_number=req.mobile_number, otp=req.otp)
        return {"status": "success" if success else "failed", "delivered": success}
    except Exception as e:
        logger.error(f"handle_send_otp error: {e}")
        return {"status": "error", "message": str(e)}
