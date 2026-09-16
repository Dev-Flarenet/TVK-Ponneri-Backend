import httpx
import uuid
import time
import base64
import hashlib
import secrets
import asyncio
import logging
import json
from datetime import datetime, date
from typing import Dict, Any, Optional, Tuple

from services.verhoeff import is_valid_aadhaar

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("uidai_oauth_service")

# Official UIDAI Tathya Endpoints
UIDAI_ORIGIN = "https://myaadhaar.uidai.gov.in"
TATHYA_BASE = "https://tathya.uidai.gov.in"
LOCAL_OAUTH_PROXY = "http://127.0.0.1:8080"

COMMON_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/133.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en_IN",
    "Origin": UIDAI_ORIGIN,
    "Referer": f"{UIDAI_ORIGIN}/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
    "appID": "MYAADHAAR",
}

# In-memory session store
oauth_sessions: Dict[str, Dict[str, Any]] = {}
SESSION_TIMEOUT_SECONDS = 600  # 10 minutes


def generate_pkce_pair() -> Tuple[str, str]:
    """
    Generate RFC 7636 PKCE code_verifier and UIDAI custom S256 code_challenge.
    UIDAI Computes: Base64(lowercase_hex(SHA256(verifier))) -> 88 chars ending in ==.
    """
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
    code_verifier = "".join(secrets.choice(alphabet) for _ in range(128))
    sha_hex = hashlib.sha256(code_verifier.encode("ascii")).hexdigest()
    code_challenge = base64.b64encode(sha_hex.encode("ascii")).decode("ascii")
    return code_verifier, code_challenge


def calculate_age(dob_str: Optional[str]) -> Optional[int]:
    """Calculate age from date of birth string (e.g. 2007-10-10 or 10/10/2007)."""
    if not dob_str:
        return None
    try:
        clean = dob_str.strip()
        dob_date = None
        for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%Y/%m/%d"):
            try:
                dob_date = datetime.strptime(clean, fmt).date()
                break
            except ValueError:
                continue

        if not dob_date:
            # Fallback for 4-digit birth year only
            if len(clean) == 4 and clean.isdigit():
                return date.today().year - int(clean)
            return None

        today = date.today()
        return today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))
    except Exception:
        return None


def format_deduplicated_address(demo: Dict[str, Any], is_local: bool = False) -> str:
    """
    UIDAI returns address parts partitioned across administrative divisions.
    Apply consecutive token deduplication so strings like 'Ponneri, Ponneri' don't repeat.
    """
    keys = (
        ["local_careof", "local_building", "local_street", "local_landmark", "local_locality",
         "local_poName", "local_vtcName", "local_subDistrictName", "local_districtName", "local_stateName"]
        if is_local else
        ["careof", "building", "street", "landmark", "locality",
         "poName", "vtcName", "subDistrictName", "districtName", "stateName"]
    )
    tokens = []
    for k in keys:
        v = demo.get(k)
        if v and isinstance(v, str):
            s = v.strip()
            if s and (not tokens or tokens[-1] != s):
                tokens.append(s)

    addr = ", ".join(tokens)
    pincode = str(demo.get("pincode") or "").strip()
    if pincode and not addr.endswith(pincode):
        addr = f"{addr} - {pincode}"
    return addr


_proxy_status_cache = {"active": False, "checked_at": 0.0}


async def _check_local_proxy() -> bool:
    """Check if the standalone Aadhar-Oauth server is active on port 8080 (cached for 15s)."""
    now = time.time()
    if now - _proxy_status_cache["checked_at"] < 15.0:
        return _proxy_status_cache["active"]

    try:
        async with httpx.AsyncClient(timeout=0.8) as client:
            res = await client.get(f"{LOCAL_OAUTH_PROXY}/api/sessions")
            is_active = res.status_code == 200
            _proxy_status_cache["active"] = is_active
            _proxy_status_cache["checked_at"] = now
            return is_active
    except Exception:
        _proxy_status_cache["active"] = False
        _proxy_status_cache["checked_at"] = now
        return False


async def get_captcha(session_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Stage 1: Initialize PKCE, Authorize session with UIDAI, and return Captcha image.
    """
    # Check local proxy first
    if await _check_local_proxy():
        try:
            url = f"{LOCAL_OAUTH_PROXY}/api/captcha"
            if session_id:
                url += f"?sessionId={session_id}"
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(url)
                if res.status_code == 200:
                    data = res.json()
                    # Cache in local memory as well
                    sid = data.get("sessionId")
                    oauth_sessions[sid] = {
                        "proxied": True,
                        "session_id": sid,
                        "captcha_txn_id": data.get("captchaTxnId"),
                        "created_at": time.time(),
                    }
                    return data
        except Exception as e:
            logger.warning(f"Local proxy captcha failed, falling back to native Tathya: {e}")

    # Native Tathya Execution
    sid = session_id or str(uuid.uuid4())
    code_verifier, code_challenge = generate_pkce_pair()
    telemetry_id = str(uuid.uuid4())

    auth_url = (
        f"{TATHYA_BASE}/access/oauth/authorize"
        f"?grant_type=authorization_code"
        f"&response_type=code"
        f"&client_id=myAadhaar"
        f"&scope=READ"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
        f"&telemetry_session_id={telemetry_id}"
    )

    async with httpx.AsyncClient(timeout=25.0, headers=COMMON_HEADERS, follow_redirects=False) as client:
        auth_resp = await client.get(auth_url)
        session_cookie = auth_resp.cookies.get("SESSION") or ""

        # Fetch Captcha
        captcha_url = f"{TATHYA_BASE}/access/generateCaptcha"
        captcha_headers = {
            **COMMON_HEADERS,
            "Referer": f"{TATHYA_BASE}/access/login?role=resident",
            "X-Request-Id": f"{telemetry_id}-1",
        }
        if session_cookie:
            captcha_headers["Cookie"] = f"SESSION={session_cookie}"

        cap_resp = await client.get(captcha_url, headers=captcha_headers)
        if cap_resp.status_code != 200:
            raise Exception(f"UIDAI Captcha API returned HTTP {cap_resp.status_code}")

        cap_data = cap_resp.json()
        captcha_b64 = ""
        captcha_txn_id = ""

        # UIDAI Tathya returns {"message": "{\"imageBase64\":\"...\",\"transactionId\":\"...\"}", "sessionActive": true}
        raw_msg = cap_data.get("message")
        if raw_msg:
            try:
                msg_obj = json.loads(raw_msg) if isinstance(raw_msg, str) else raw_msg
                if isinstance(msg_obj, dict):
                    captcha_b64 = msg_obj.get("imageBase64") or msg_obj.get("captchaBase64Image") or ""
                    captcha_txn_id = msg_obj.get("transactionId") or msg_obj.get("captchaTxnId") or ""
            except Exception as e:
                logger.warning(f"Error parsing inner captcha JSON string: {e}")

        # Fallback to top-level keys if present
        if not captcha_b64:
            captcha_b64 = cap_data.get("captchaBase64Image") or cap_data.get("imageBase64") or ""
        if not captcha_txn_id:
            captcha_txn_id = cap_data.get("captchaTxnId") or cap_data.get("transactionId") or ""

        if captcha_b64 and not captcha_b64.startswith("data:"):
            # UIDAI captcha images are PNG format
            mime = "image/png" if captcha_b64.startswith("iVBORw") else "image/jpeg"
            captcha_b64 = f"data:{mime};base64,{captcha_b64}"

        oauth_sessions[sid] = {
            "session_id": sid,
            "code_verifier": code_verifier,
            "code_challenge": code_challenge,
            "telemetry_id": telemetry_id,
            "session_cookie": session_cookie,
            "captcha_txn_id": captcha_txn_id,
            "created_at": time.time(),
        }

        asyncio.create_task(_expire_session(sid))

        return {
            "success": True,
            "sessionId": sid,
            "captchaTxnId": captcha_txn_id,
            "captchaImage": captcha_b64,
        }


async def generate_otp(session_id: str, uid: str, captcha: str, captcha_txn_id: str) -> Dict[str, Any]:
    """
    Stage 2: Validate Aadhaar Verhoeff checksum & send OTP via UIDAI Tathya.
    """
    clean_uid = "".join(filter(str.isdigit, str(uid)))
    if not is_valid_aadhaar(clean_uid):
        return {
            "success": False,
            "message": "Invalid Aadhaar number. Please verify the 12 digits (Verhoeff checksum failed).",
        }

    # Check local proxy first
    sess = oauth_sessions.get(session_id, {})
    if sess.get("proxied") or await _check_local_proxy():
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.post(
                    f"{LOCAL_OAUTH_PROXY}/api/generate-otp",
                    json={"sessionId": session_id, "uid": clean_uid, "captcha": captcha, "captchaTxnId": captcha_txn_id},
                )
                return res.json()
        except Exception as e:
            logger.warning(f"Local proxy generate-otp failed: {e}")

    # Native Tathya Execution
    if not sess or not sess.get("session_cookie"):
        return {"success": False, "message": "Session expired. Please refresh the captcha."}

    session_cookie = sess["session_cookie"]
    telemetry_id = sess.get("telemetry_id", str(uuid.uuid4()))

    headers = {
        **COMMON_HEADERS,
        "Referer": f"{TATHYA_BASE}/access/login?role=resident",
        "X-Request-Id": f"{telemetry_id}-2",
        "Cookie": f"SESSION={session_cookie}",
    }

    body = {
        "uid": clean_uid,
        "captcha": captcha.strip(),
        "captchaTxnId": captcha_txn_id,
    }

    async with httpx.AsyncClient(timeout=25.0) as client:
        resp = await client.post(f"{TATHYA_BASE}/access/generateOTPForOAuth", json=body, headers=headers)
        data = resp.json() if resp.status_code == 200 else {}

        if resp.status_code == 200 and (data.get("status") is True or data.get("status") == "true"):
            sess["uid"] = clean_uid
            sess["otp_txn_id"] = data.get("txnId")
            return {
                "success": True,
                "message": data.get("message", "OTP sent to your Aadhaar-linked mobile number"),
                "details": data,
            }

        err_msg = data.get("message") or f"UIDAI returned error (HTTP {resp.status_code})"
        return {"success": False, "message": err_msg}


async def login_and_get_profile(session_id: str, uid: str, otp: str) -> Dict[str, Any]:
    """
    Stages 3, 4 & 5:
    Submit OTP -> Capture Authorization Code -> PKCE Token Exchange -> Demographics Fetch.
    """
    clean_uid = "".join(filter(str.isdigit, str(uid)))
    clean_otp = "".join(filter(str.isdigit, str(otp)))

    sess = oauth_sessions.get(session_id, {})
    if sess.get("proxied") or await _check_local_proxy():
        for attempt in range(2):
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    res = await client.post(
                        f"{LOCAL_OAUTH_PROXY}/api/login",
                        json={"sessionId": session_id, "uid": clean_uid, "otp": clean_otp},
                    )
                    data = res.json()
                    if res.status_code == 200 and data.get("success") and data.get("profile"):
                        # Enrich profile with age if not calculated
                        prof = data["profile"]
                        if "age" not in prof or prof["age"] is None:
                            prof["age"] = calculate_age(prof.get("dob"))
                        return data

                    # If UIDAI Tathya cluster is syncing or returned transient error, retry once
                    if attempt == 0:
                        logger.info(f"Local proxy login attempt 1 returned HTTP {res.status_code}, retrying in 1.2s...")
                        await asyncio.sleep(1.2)
                        continue

                    err_msg = (
                        data.get("message")
                        or data.get("detail")
                        or data.get("errorMessage")
                        or f"Aadhaar authentication failed (HTTP {res.status_code})."
                    ) if isinstance(data, dict) else "Aadhaar authentication failed."
                    return {"success": False, "message": err_msg}
            except Exception as e:
                if attempt == 0:
                    logger.info(f"Local proxy login attempt 1 exception: {e}, retrying in 1.2s...")
                    await asyncio.sleep(1.2)
                    continue
                logger.warning(f"Local proxy login failed after retries: {e}")
                return {"success": False, "message": f"Connection error: {e}"}

    # Native Tathya Execution
    if not sess or not sess.get("session_cookie"):
        return {"success": False, "message": "Session expired. Please restart Aadhaar authentication."}

    session_cookie = sess["session_cookie"]
    code_verifier = sess.get("code_verifier", "")
    telemetry_id = sess.get("telemetry_id", str(uuid.uuid4()))

    headers = {
        **COMMON_HEADERS,
        "Referer": f"{TATHYA_BASE}/access/login?role=resident",
        "X-Request-Id": f"{telemetry_id}-3",
        "Cookie": f"SESSION={session_cookie}",
    }

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
        # 1. Login with OTP
        login_resp = await client.post(
            f"{TATHYA_BASE}/access/login",
            json={"uid": clean_uid, "otp": clean_otp},
            headers=headers,
        )
        login_data = login_resp.json() if login_resp.status_code == 200 else {}
        logger.info(f"[{sid}] Tathya login response: status={login_resp.status_code}, data={login_data}")
        if login_data.get("status") not in ("Y", "y", True) or not login_data.get("redirectURL"):
            return {
                "success": False,
                "message": login_data.get("errorMessage") or "Invalid OTP or authentication failed.",
            }

        redirect_url = login_data["redirectURL"]
        # CRITICAL FIX: UIDAI returns http:// but Tathya port 80 is firewalled/timed out. Force HTTPS!
        if redirect_url.startswith("http://"):
            redirect_url = redirect_url.replace("http://", "https://", 1)

        # 2. Follow Authorize Redirect to capture code
        redir_resp = await client.get(redirect_url, headers=headers)
        location = redir_resp.headers.get("location") or ""
        logger.info(f"[{sid}] Tathya authorize redirect: status={redir_resp.status_code}, location={location}")

        auth_code = None
        if "code=" in location:
            auth_code = location.split("code=")[1].split("&")[0]
        elif "code=" in str(redir_resp.url):
            auth_code = str(redir_resp.url).split("code=")[1].split("&")[0]

        if not auth_code:
            logger.error(f"[{sid}] Could not find code in location={location} or url={redir_resp.url}")
            return {"success": False, "message": "Failed to obtain authorization code from UIDAI."}

        # 3. PKCE Token Exchange
        token_url = (
            f"{TATHYA_BASE}/access/oauth/token"
            f"?client_id=myAadhaar"
            f"&grant_type=authorization_code"
            f"&code_verifier={code_verifier}"
            f"&code={auth_code}"
        )
        token_headers = {
            **COMMON_HEADERS,
            "Content-Length": "0",
        }
        token_resp = await client.post(token_url, headers=token_headers)
        logger.info(f"[{sid}] Tathya token exchange response: status={token_resp.status_code}")
        if token_resp.status_code != 200:
            logger.error(f"[{sid}] Token exchange failed: {token_resp.text[:300]}")
            return {"success": False, "message": f"Token exchange failed (HTTP {token_resp.status_code})"}

        token_data = token_resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            return {"success": False, "message": "Failed to extract access token from UIDAI response."}

        # 4. Fetch Demographic Profile
        profile_url = f"{TATHYA_BASE}/profileService/api/v1/oauth/profile"
        prof_headers = {
            **COMMON_HEADERS,
            "Authorization": f"Bearer {access_token}",
            "X-Request-ID": telemetry_id,
        }
        prof_resp = await client.post(profile_url, json={"uidNumber": clean_uid}, headers=prof_headers)
        logger.info(f"[{sid}] Tathya profile fetch: status={prof_resp.status_code}")
        if prof_resp.status_code != 200:
            logger.error(f"[{sid}] Profile fetch failed: {prof_resp.text[:300]}")
            return {"success": False, "message": "Failed to fetch demographic profile from UIDAI."}

        raw_profile = prof_resp.json()
        demo = raw_profile.get("demographicsInfo") or raw_profile

        # 5. Build Enriched Citizen Profile
        photo_raw = demo.get("photo") or ""
        photo_uri = photo_raw if (not photo_raw or photo_raw.startswith("data:")) else f"data:image/jpeg;base64,{photo_raw}"
        dob = demo.get("dob") or ""
        age = calculate_age(dob)

        profile = {
            "uid": clean_uid,
            "name": demo.get("name") or token_data.get("user_name", ""),
            "local_name": demo.get("local_name") or demo.get("tamil_name") or "",
            "gender": demo.get("gender") or "",
            "dob": dob,
            "age": age,
            "mobile": demo.get("mobile") or "",
            "email": demo.get("email") or "",
            "careof": demo.get("careof") or "",
            "local_careof": demo.get("local_careof") or "",
            "pincode": demo.get("pincode") or "",
            "eid": demo.get("eid") or "",
            "address": format_deduplicated_address(demo, is_local=False),
            "address_local": format_deduplicated_address(demo, is_local=True),
            "photo": photo_uri,
        }

        return {
            "success": True,
            "authToken": access_token,
            "message": "Aadhaar authentication successful",
            "profile": profile,
        }


async def _expire_session(session_id: str):
    await asyncio.sleep(SESSION_TIMEOUT_SECONDS)
    oauth_sessions.pop(session_id, None)
