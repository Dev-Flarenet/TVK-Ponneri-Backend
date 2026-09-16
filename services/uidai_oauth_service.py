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


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    try:
        if not token or not isinstance(token, str):
            return {}
        parts = token.split(".")
        if len(parts) >= 2:
            payload = parts[1]
            padded = payload + "=" * (-len(payload) % 4)
            data = base64.urlsafe_b64decode(padded)
            return json.loads(data.decode("utf-8", errors="ignore"))
    except Exception:
        pass
    return {}


def _extract_field(sources: list, *keys, default="") -> Any:
    for src in sources:
        if not isinstance(src, dict):
            continue
        for k in keys:
            val = src.get(k)
            if val is not None and str(val).strip() not in ("", "-", "null", "None"):
                return val
    return default


def _build_profile_from_sources(clean_uid: str, raw_profile: Any, token_data: Dict[str, Any]) -> Dict[str, Any]:
    # Collect all potential dictionaries where demographic fields could reside
    sources = []

    # 1. JWT Payload from access_token
    access_token = token_data.get("access_token") or ""
    if access_token:
        jwt_claims = decode_jwt_payload(access_token)
        if jwt_claims:
            sources.append(jwt_claims)

    # 2. JWT Payload from id_token (if present)
    id_token = token_data.get("id_token") or ""
    if id_token:
        id_claims = decode_jwt_payload(id_token)
        if id_claims:
            sources.append(id_claims)

    # 3. token_data root
    sources.append(token_data)

    # 4. raw_profile and its potential nested containers
    if isinstance(raw_profile, dict):
        sources.append(raw_profile)
        for sub_key in ("demographicsInfo", "demographics", "data", "profile", "response", "identity", "kycData", "residentDetails"):
            sub = raw_profile.get(sub_key)
            if isinstance(sub, dict):
                sources.append(sub)

    # 5. Address sub-dictionaries
    for src in list(sources):
        for addr_key in ("address", "splitAddress", "residentAddress", "formattedAddress"):
            sub_addr = src.get(addr_key) if isinstance(src, dict) else None
            if isinstance(sub_addr, dict):
                sources.append(sub_addr)

    # Extract Fields
    name = _extract_field(sources, "name", "user_name", "fullName", "resident_name", "citizen_name")
    local_name = _extract_field(sources, "local_name", "tamil_name", "name_local", "localName", "l_name")

    # Gender normalization
    gender_raw = str(_extract_field(sources, "gender", "sex", default="")).strip().upper()
    gender = "MALE" if gender_raw in ("M", "MALE") else "FEMALE" if gender_raw in ("F", "FEMALE") else "TRANSGENDER" if gender_raw in ("T", "TRANSGENDER") else gender_raw

    # DOB & Age
    dob = _extract_field(sources, "dob", "dateOfBirth", "date_of_birth", "birthDate", "birth_date", "yob")
    age = calculate_age(dob) if dob else None

    # Mobile
    mobile = _extract_field(sources, "mobile", "mobileNumber", "mobile_number", "phone", "phoneNumber", "contactNumber", "phone_number")

    # Email
    email = _extract_field(sources, "email", "emailId", "email_id", "emailAddress")

    # Care of
    careof = _extract_field(sources, "careof", "careOf", "co", "c_o", "fatherName", "guardianName", "relativeName")
    local_careof = _extract_field(sources, "local_careof", "localCareOf", "local_co")

    # Pincode
    pincode = str(_extract_field(sources, "pincode", "pinCode", "pin_code", "postalCode", "pc", "pin", default="")).strip()

    # Photo URI
    photo_raw = _extract_field(sources, "photo", "userPhoto", "image", "photoBase64", "profilePhoto", "residentPhoto", "pht")
    photo_uri = ""
    if photo_raw and isinstance(photo_raw, str) and len(photo_raw) > 50:
        if photo_raw.startswith("data:"):
            photo_uri = photo_raw
        else:
            mime = "image/png" if photo_raw.startswith("iVBORw") else "image/jpeg"
            photo_uri = f"data:{mime};base64,{photo_raw}"

    # Address Construction
    addr_str = _extract_field(sources, "fullAddress", "formattedAddress", "residentAddress", "completeAddress")
    if not addr_str:
        for s in sources:
            a = s.get("address") if isinstance(s, dict) else None
            if isinstance(a, str) and len(a.strip()) > 5:
                addr_str = a.strip()
                break

    if not addr_str:
        co_part = _extract_field(sources, "careof", "careOf", "co", "c_o")
        building = _extract_field(sources, "house", "building", "doorNo", "flatNo", "buildingName", "houseNumber")
        street = _extract_field(sources, "street", "streetName", "road", "street_name")
        landmark = _extract_field(sources, "landmark", "lm", "near")
        locality = _extract_field(sources, "locality", "loc", "area")
        vtc = _extract_field(sources, "vtcName", "vtc", "village", "city", "town")
        po = _extract_field(sources, "poName", "po", "postOffice", "post_office")
        subdist = _extract_field(sources, "subDistrictName", "subdist", "subDistrict", "taluk", "tahsil", "mandal")
        dist = _extract_field(sources, "districtName", "district", "dist")
        state = _extract_field(sources, "stateName", "state")

        parts = []
        for part in (co_part, building, street, landmark, locality, vtc, po, subdist, dist, state):
            if part and isinstance(part, str):
                p = part.strip()
                if p and (not parts or parts[-1] != p):
                    parts.append(p)
        addr_str = ", ".join(parts)
        if pincode and not addr_str.endswith(pincode):
            addr_str = f"{addr_str} - {pincode}" if addr_str else pincode

    # Local Tamil Address
    local_addr_str = _extract_field(sources, "address_local", "local_address", "tamil_address")
    if not local_addr_str:
        local_parts = []
        for lk in ("local_careof", "local_building", "local_street", "local_landmark", "local_locality", "local_vtcName", "local_poName", "local_subDistrictName", "local_districtName", "local_stateName"):
            lv = _extract_field(sources, lk)
            if lv and isinstance(lv, str):
                lp = lv.strip()
                if lp and (not local_parts or local_parts[-1] != lp):
                    local_parts.append(lp)
        local_addr_str = ", ".join(local_parts)
        if pincode and local_addr_str and not local_addr_str.endswith(pincode):
            local_addr_str = f"{local_addr_str} - {pincode}"

    eid = _extract_field(sources, "eid", "enrollmentId")

    return {
        "uid": clean_uid,
        "name": name,
        "local_name": local_name,
        "gender": gender,
        "dob": dob,
        "age": age,
        "mobile": mobile,
        "email": email,
        "careof": careof,
        "local_careof": local_careof,
        "pincode": pincode,
        "eid": eid,
        "address": addr_str,
        "address_local": local_addr_str,
        "photo": photo_uri,
    }


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
    sid = session_id

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
        logger.info(f"[{sid}] Tathya raw_profile json: {raw_profile}")
        logger.info(f"[{sid}] Tathya token_data: {token_data}")

        # 5. Build Comprehensive Enriched Citizen Profile
        profile = _build_profile_from_sources(clean_uid, raw_profile, token_data)
        logger.info(f"[{sid}] Tathya extracted profile summary: name={profile.get('name')}, dob={profile.get('dob')}, gender={profile.get('gender')}, mobile={profile.get('mobile')}, photo_len={len(profile.get('photo') or '')}")

        return {
            "success": True,
            "authToken": access_token,
            "message": "Aadhaar authentication successful",
            "profile": profile,
        }


async def _expire_session(session_id: str):
    await asyncio.sleep(SESSION_TIMEOUT_SECONDS)
    oauth_sessions.pop(session_id, None)
