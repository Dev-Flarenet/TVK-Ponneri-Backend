from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import random
import traceback

from services.aadhaar_verify import (
    init_aadhaar_session,
    verify_aadhaar,
    send_aadhaar_otp,
    verify_aadhaar_otp,
    get_session_data,
    update_session_data,
)
from services.sms_service import send_otp_sms

router = APIRouter(prefix="/aadhaar", tags=["Aadhaar Verification"])

class VerifyRequest(BaseModel):
    session_id: str
    aadhaar_number: str
    captcha: str

class SendMobileOtpRequest(BaseModel):
    session_id: str
    mobile: str

class VerifyMobileOtpRequest(BaseModel):
    session_id: str
    otp: str

class VerifyOtpRequest(BaseModel):
    session_id: str
    aadhaar_number: str
    otp: str

@router.get("/init")
async def init_session():
    """Fetch a fresh UIDAI captcha and session ID."""
    try:
        return await init_aadhaar_session()
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/verify")
async def verify(req: VerifyRequest):
    """Verify Aadhaar number + Captcha against official UIDAI Tathya."""
    try:
        return await verify_aadhaar(
            session_id=req.session_id,
            aadhaar_number=req.aadhaar_number,
            captcha_text=req.captcha,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/send-mobile-otp")
async def send_mobile_otp(req: SendMobileOtpRequest):
    """Generate 6-digit OTP and deliver to citizen phone."""
    session = await get_session_data(req.session_id)
    if not session:
        raise HTTPException(status_code=400, detail="Invalid or expired session.")

    otp = str(random.randint(100000, 999999))
    await update_session_data(req.session_id, {"mobile_otp": otp})

    success = await send_otp_sms(req.mobile, otp)
    if success:
        return {"status": "success", "message": "OTP sent successfully via WhatsApp."}
    else:
        raise HTTPException(
            status_code=502,
            detail="Failed to deliver OTP to the provided mobile number. Please check WhatsApp connectivity and try again.",
        )

@router.post("/verify-mobile-otp")
async def verify_mobile_otp(req: VerifyMobileOtpRequest):
    """Verify citizen mobile OTP."""
    session = await get_session_data(req.session_id)
    if not session:
        raise HTTPException(status_code=400, detail="Invalid or expired session.")

    expected = session.get("mobile_otp")
    if not expected:
        raise HTTPException(status_code=400, detail="OTP was not requested or session expired.")

    if req.otp == expected:
        return {"status": "success", "message": "Mobile number verified."}
    return {"status": "error", "message": "Invalid OTP."}

@router.post("/send-otp")
async def send_otp(req: VerifyRequest):
    """Trigger official UIDAI Aadhaar OTP."""
    try:
        return await send_aadhaar_otp(
            session_id=req.session_id,
            aadhaar_number=req.aadhaar_number,
            captcha_text=req.captcha,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/verify-otp")
async def verify_otp(req: VerifyOtpRequest):
    """Verify official UIDAI Aadhaar OTP."""
    try:
        return await verify_aadhaar_otp(
            session_id=req.session_id,
            aadhaar_number=req.aadhaar_number,
            otp=req.otp,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
