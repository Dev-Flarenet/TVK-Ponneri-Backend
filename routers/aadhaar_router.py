from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
import random
import traceback
import logging

from services.aadhaar_verify import (
    init_aadhaar_session,
    verify_aadhaar,
    send_aadhaar_otp,
    verify_aadhaar_otp,
    get_session_data,
    update_session_data,
)
from services.uidai_oauth_service import (
    get_captcha,
    generate_otp as oauth_generate_otp,
    login_and_get_profile,
)
from services.sms_service import send_otp_sms

logger = logging.getLogger("aadhaar_router")
router = APIRouter(prefix="/aadhaar", tags=["Aadhaar Verification & OAuth"])


# --- Pydantic Request Models ---

class GenerateOtpRequest(BaseModel):
    sessionId: str
    uid: str
    captcha: str
    captchaTxnId: str

class LoginRequest(BaseModel):
    sessionId: str
    uid: str
    otp: str

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


# =======================================================================
# 1. UIDAI Tathya OAuth 2.0 PKCE Endpoints
# =======================================================================

@router.get("/captcha")
async def fetch_oauth_captcha(sessionId: Optional[str] = Query(None)):
    """
    Fetch a fresh UIDAI captcha and initialize/renew an OAuth session with PKCE binding.
    """
    try:
        res = await get_captcha(sessionId)
        return res
    except Exception as e:
        logger.error(f"Error fetching OAuth captcha: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate-otp")
async def generate_aadhaar_oauth_otp(req: GenerateOtpRequest):
    """
    Validate Aadhaar number using Verhoeff algorithm and dispatch official OTP via UIDAI Tathya.
    """
    try:
        res = await oauth_generate_otp(
            session_id=req.sessionId,
            uid=req.uid,
            captcha=req.captcha,
            captcha_txn_id=req.captchaTxnId,
        )
        if not res.get("success"):
            raise HTTPException(status_code=400, detail=res.get("message", "Failed to generate OTP"))
        return res
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating Aadhaar OAuth OTP: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/login")
async def login_oauth(req: LoginRequest):
    """
    Verify 6-digit Aadhaar OTP, capture authorization code, perform PKCE token exchange,
    and return complete enriched demographic profile.
    """
    try:
        res = await login_and_get_profile(
            session_id=req.sessionId,
            uid=req.uid,
            otp=req.otp,
        )
        if not res.get("success"):
            raise HTTPException(status_code=400, detail=res.get("message", "Invalid OTP or authentication failed"))
        return res
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during Aadhaar OAuth login: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =======================================================================
# 2. Legacy / WhatsApp Flow Support (Maintained for Backward Compatibility)
# =======================================================================

@router.get("/init")
async def init_session():
    """Fetch a fresh UIDAI captcha and session ID."""
    try:
        # First attempt OAuth PKCE captcha for seamless interoperability
        try:
            oauth_res = await get_captcha()
            if oauth_res.get("success"):
                return {
                    "session_id": oauth_res.get("sessionId"),
                    "captcha_base64": oauth_res.get("captchaImage"),
                    "captcha_txn_id": oauth_res.get("captchaTxnId"),
                }
        except Exception:
            pass
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
    """Generate 6-digit OTP and deliver to citizen phone via FlarenetWA."""
    session = await get_session_data(req.session_id)
    if not session:
        # Fallback create session if needed
        session = {}

    otp = str(random.randint(100000, 999999))
    await update_session_data(req.session_id, {"mobile_otp": otp})

    success = await send_otp_sms(req.mobile, otp)
    if success:
        return {"status": "success", "message": "OTP sent successfully via Flarenet WhatsApp."}
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
