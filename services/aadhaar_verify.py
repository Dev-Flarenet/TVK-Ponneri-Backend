import httpx
import uuid
import time
import base64
import asyncio
from typing import Dict, Any, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aadhaar_verifier")

UIDAI_ORIGIN = "https://myaadhaar.uidai.gov.in"
TATHYA_BASE = "https://tathya.uidai.gov.in"

CAPTCHA_URL = f"{TATHYA_BASE}/audioCaptchaService/api/captcha/v3/generation"
VERIFY_URL = f"{TATHYA_BASE}/uidVerifyRetrieveService/api/verifyUID"
SEND_OTP_URL = f"{TATHYA_BASE}/uidLoginService/api/login/sendOtp"
VERIFY_OTP_URL = f"{TATHYA_BASE}/uidLoginService/api/login"

_COMMON_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/127.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en_IN",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Origin": UIDAI_ORIGIN,
    "Referer": f"{UIDAI_ORIGIN}/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
    "appid": "MYAADHAAR",
}

# Pure in-memory session cache (Fast, reliable, zero-config)
active_sessions: Dict[str, Dict[str, Any]] = {}
SESSION_TIMEOUT = 300  # 5 minutes

async def save_session_data(session_id: str, data: Dict[str, Any]):
    active_sessions[session_id] = {**active_sessions.get(session_id, {}), **data}

async def get_session_data(session_id: str) -> Optional[Dict[str, Any]]:
    return active_sessions.get(session_id)

async def update_session_data(session_id: str, updates: Dict[str, Any]):
    session = active_sessions.get(session_id, {})
    session.update(updates)
    active_sessions[session_id] = session

def _to_data_uri(data: Any, field_name: str) -> str:
    if isinstance(data, bytes):
        return f"data:image/jpeg;base64,{base64.b64encode(data).decode()}"
    s = str(data)
    if s.startswith("data:"):
        return s
    return f"data:image/jpeg;base64,{s}"

async def init_aadhaar_session() -> dict:
    session_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())

    captcha_body = {
        "captchaLength": "6",
        "captchaType": "2",
        "audioCaptchaRequired": True,
    }

    logger.info(f"[{session_id}] POST {CAPTCHA_URL} x-request-id={request_id}")
    async with httpx.AsyncClient(timeout=25.0, headers=_COMMON_HEADERS) as client:
        resp = await client.post(
            CAPTCHA_URL,
            json=captcha_body,
            headers={
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "x-request-id": request_id,
            },
        )

        if resp.status_code != 200:
            raise Exception(f"UIDAI captcha API returned HTTP {resp.status_code}. Body: {resp.text[:300]}")

        data = resp.json()
        img_raw = data.get("imageBase64")
        if not img_raw:
            raise ValueError(f"Captcha JSON does not contain 'imageBase64'. Keys returned: {list(data.keys())}")

        captcha_b64 = _to_data_uri(img_raw, "imageBase64")
        txn_id = data.get("transactionId", "")

        cookie_header = resp.headers.get("set-cookie") or ""
        if not cookie_header and client.cookies:
            cookie_header = "; ".join([f"{k}={v}" for k, v in client.cookies.items()])

        await save_session_data(session_id, {
            "cookie_data": cookie_header,
            "captcha_txn_id": str(txn_id),
            "timestamp": time.time(),
        })

        asyncio.create_task(_expire_session(session_id))

        return {
            "session_id": session_id,
            "captcha_base64": captcha_b64,
        }

async def verify_aadhaar(session_id: str, aadhaar_number: str, captcha_text: str) -> dict:
    session = await get_session_data(session_id)
    if not session:
        return {
            "status": "error",
            "message": "Session not found or expired. Please refresh the captcha.",
        }

    captcha_txn_id: str = session.get("captcha_txn_id", "")
    cookie_data: str = session.get("cookie_data", "")

    try:
        request_id = str(uuid.uuid4())
        verify_body = {
            "uid": aadhaar_number,
            "captchaTxnId": captcha_txn_id,
            "captcha": captcha_text,
            "transactionId": request_id,
            "captchaLogic": "V3",
        }

        headers = {
            **_COMMON_HEADERS,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "x-request-id": request_id,
        }
        if cookie_data:
            headers["Cookie"] = cookie_data

        logger.info(f"[{session_id}] POST {VERIFY_URL} x-request-id={request_id}")
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.post(VERIFY_URL, json=verify_body, headers=headers)

            logger.info(f"[{session_id}] verify response: HTTP {resp.status_code} | body[:120]: {resp.text[:120]}")

            if resp.status_code == 403:
                return {"status": "error", "message": "UIDAI blocked the request (HTTP 403)."}

            if resp.status_code != 200:
                return {"status": "error", "message": f"Verification API returned HTTP {resp.status_code}.", "raw": resp.text[:300]}

            raw_text = resp.text
            data = resp.json() if "json" in resp.headers.get("content-type", "") else {}
            combined = (raw_text + str(data)).lower()

            if data.get("errorCode") or "errorcode" in combined:
                error_msg = data.get("errorDetails", {}).get("messageEnglish", "") or "Aadhaar verification failed."
                if "captcha" in combined:
                    return {"status": "error", "message": "Invalid Captcha entered.", "raw": data or raw_text[:400]}
                return {"status": "error", "message": error_msg, "raw": data or raw_text[:400]}

            if (
                data.get("status") in ("1", 1, "Success", "success")
                or data.get("verified") is True
                or "exists" in combined
                or aadhaar_number[-4:] in raw_text
            ):
                masked_mobile = data.get("maskedMobileNumber", "")
                return {
                    "status": "success",
                    "message": "Aadhaar Number Verified Successfully.",
                    "masked_mobile": masked_mobile,
                    "raw": data or raw_text[:400],
                }

            if "captcha" in combined and ("invalid" in combined or "wrong" in combined or "incorrect" in combined):
                return {"status": "error", "message": "Invalid Captcha entered.", "raw": data or raw_text[:400]}

            if "invalid" in combined or data.get("status") in ("0", 0, "Failure", "failure"):
                return {"status": "error", "message": "Invalid Aadhaar Number.", "raw": data or raw_text[:400]}

            return {"status": "completed", "message": "Verification submitted.", "raw": data or raw_text[:400]}

    except httpx.TimeoutException:
        return {"status": "error", "message": "Verification request timed out. Please try again."}
    except Exception as e:
        logger.error(f"[{session_id}] verify error: {e}")
        return {"status": "error", "message": str(e)}

async def send_aadhaar_otp(session_id: str, aadhaar_number: str, captcha_text: str) -> dict:
    session = await get_session_data(session_id)
    if not session:
        return {"status": "error", "message": "Session not found or expired. Please refresh the captcha."}

    captcha_txn_id: str = session.get("captcha_txn_id", "")
    cookie_data: str = session.get("cookie_data", "")

    try:
        request_id = str(uuid.uuid4())
        send_otp_body = {
            "uidNumber": aadhaar_number,
            "captchaTxnId": captcha_txn_id,
            "captchaValue": captcha_text,
            "transactionId": f"MYAADHAAR:{uuid.uuid4()}",
        }

        headers = {
            **_COMMON_HEADERS,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "x-request-id": request_id,
        }
        if cookie_data:
            headers["Cookie"] = cookie_data

        logger.info(f"[{session_id}] POST {SEND_OTP_URL} x-request-id={request_id}")
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.post(SEND_OTP_URL, json=send_otp_body, headers=headers)

            if resp.status_code != 200:
                return {"status": "error", "message": f"Send OTP API returned HTTP {resp.status_code}.", "raw": resp.text[:300]}

            data = resp.json() if "json" in resp.headers.get("content-type", "") else {}
            if data.get("status") == "Success" or data.get("status") == 1:
                otp_txn_id = data.get("txnId")
                await update_session_data(session_id, {"otp_txn_id": otp_txn_id})
                return {
                    "status": "success",
                    "message": data.get("message", "OTP sent successfully."),
                    "txnId": otp_txn_id,
                }

            combined = str(data).lower()
            if "captcha" in combined:
                return {"status": "error", "message": "Invalid Captcha entered.", "raw": data}

            error_msg = data.get("message", "Failed to send OTP.")
            return {"status": "error", "message": error_msg, "raw": data}

    except Exception as e:
        logger.error(f"[{session_id}] send_otp error: {e}")
        return {"status": "error", "message": str(e)}

async def verify_aadhaar_otp(session_id: str, aadhaar_number: str, otp: str) -> dict:
    session = await get_session_data(session_id)
    if not session:
        return {"status": "error", "message": "Session not found or expired."}

    otp_txn_id: str = session.get("otp_txn_id")
    cookie_data: str = session.get("cookie_data", "")

    if not otp_txn_id:
        return {"status": "error", "message": "OTP was not requested or session expired."}

    try:
        request_id = str(uuid.uuid4())
        verify_body = {
            "uid": aadhaar_number,
            "otp": otp,
            "txnId": otp_txn_id,
        }

        headers = {
            **_COMMON_HEADERS,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "x-request-id": request_id,
        }
        if cookie_data:
            headers["Cookie"] = cookie_data

        logger.info(f"[{session_id}] POST {VERIFY_OTP_URL} x-request-id={request_id}")
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.post(VERIFY_OTP_URL, json=verify_body, headers=headers)

            if resp.status_code != 200:
                return {"status": "error", "message": f"Verify OTP API returned HTTP {resp.status_code}.", "raw": resp.text[:300]}

            data = resp.json() if "json" in resp.headers.get("content-type", "") else {}
            if data.get("status") == "Success" or data.get("status") == 1:
                return {
                    "status": "success",
                    "message": "OTP verified successfully.",
                    "token": data.get("token"),
                }

            error_msg = data.get("message", "OTP Verification Failed.")
            return {"status": "error", "message": error_msg, "raw": data}

    except Exception as e:
        logger.error(f"[{session_id}] verify_otp error: {e}")
        return {"status": "error", "message": str(e)}

async def _expire_session(session_id: str):
    await asyncio.sleep(SESSION_TIMEOUT)
    active_sessions.pop(session_id, None)
