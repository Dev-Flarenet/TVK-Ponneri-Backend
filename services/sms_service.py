import httpx
import logging
from db import get_dynamic_config

logger = logging.getLogger("sms_service")

async def get_whatsapp_config() -> dict:
    """Fetch live WhatsApp configuration from config.json or environment."""
    base_url = await get_dynamic_config("WHATSAPP_BASE_URL")
    instance_name = await get_dynamic_config("WHATSAPP_INSTANCE_NAME")
    api_key = await get_dynamic_config("WHATSAPP_API_KEY")

    return {
        "base_url": base_url.rstrip("/") if base_url else "",
        "instance_name": instance_name or "",
        "api_key": api_key or "",
    }

async def send_otp_sms(mobile_number: str, otp: str) -> bool:
    """Send citizen petition verification OTP via WhatsApp Flarenet Gateway."""
    config = await get_whatsapp_config()
    base_url = config["base_url"]
    instance_name = config["instance_name"]
    api_key = config["api_key"]

    if not base_url or not instance_name or not api_key:
        logger.error(
            "WhatsApp gateway configuration is incomplete. "
            "Please ensure WHATSAPP_BASE_URL, WHATSAPP_INSTANCE_NAME, and WHATSAPP_API_KEY are configured."
        )
        return False

    url = f"{base_url}/api/v1/instances/{instance_name}/send/text"
    phone = mobile_number.replace("+", "").replace(" ", "").replace("-", "")
    if len(phone) == 10:
        phone = f"91{phone}"

    payload_msg = (
        "*TVK பொன்னேரி எம்.எல்.ஏ தளம் | MLA Portal*\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "மனு பதிவுக்கான OTP / Verification Code:\n"
        f"*{otp}*\n\n"
        "இக்குறியீட்டை பகிர வேண்டாம் (Valid for 5 mins).\n"
        "Do not share this OTP with anyone.\n\n"
        "— Dr. M.S. Ravi, MLA Ponneri"
    )

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                url,
                json={"phone": phone, "message": payload_msg},
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            )
            if resp.status_code in (200, 201):
                return True
            logger.error(f"WhatsApp OTP dispatch failed (HTTP {resp.status_code}): {resp.text[:300]}")
            return False
    except Exception as e:
        logger.error(f"WhatsApp gateway network error: {e}")
        return False

async def send_status_update_sms(mobile_number: str, complaint_no: str, status: str, remarks: str = "") -> bool:
    """Send rich complaint lifecycle update via WhatsApp."""
    config = await get_whatsapp_config()
    base_url = config["base_url"]
    instance_name = config["instance_name"]
    api_key = config["api_key"]

    if not base_url or not instance_name or not api_key:
        logger.error("Cannot dispatch WhatsApp status alert: WhatsApp gateway unconfigured.")
        return False

    url = f"{base_url}/api/v1/instances/{instance_name}/send/text"
    phone = mobile_number.replace("+", "").replace(" ", "").replace("-", "")
    if len(phone) == 10:
        phone = f"91{phone}"

    tamil_status = {
        "Raised": "மனு பதிவு செய்யப்பட்டுள்ளது (Grievance Registered)",
        "In Progress": "பரிசீலனையில் / நடவடிக்கை எடுக்கப்பட்டு வருகிறது (Under Investigation)",
        "Under Review": "ஆய்வில் உள்ளது (Under Field Review)",
        "Complaint Solved": "மனு மீது தீர்வு காணப்பட்டது (Grievance Solved)",
        "Rejected": "மனு நிராகரிக்கப்பட்டது (Closed)",
    }.get(status, status)

    remarks_text = f"\n*குறிப்பு / Remarks:* {remarks}\n" if remarks else ""

    msg = (
        "*TVK பொன்னேரி எம்.எல்.ஏ அலுவலகம் | MLA Office*\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "வணக்கம், உங்கள் மனுவின் தற்போதைய நிலை:\n\n"
        f"📋 *மனு எண் / Petition No:* {complaint_no}\n"
        f"⚡ *தற்போதைய நிலை / Status:* {tamil_status}\n"
        f"{remarks_text}\n"
        "தங்கள் பகுதி மக்களின் வளர்ச்சிக்காக என்றும் உங்கள் பணியில்.\n\n"
        "— Dr. M.S. Ravi, MLA Ponneri\n"
        "https://tvkponneri.in"
    )

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                url,
                json={"phone": phone, "message": msg},
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            )
            if resp.status_code in (200, 201):
                return True
            logger.error(f"WhatsApp status alert failed (HTTP {resp.status_code}): {resp.text[:300]}")
            return False
    except Exception as e:
        logger.error(f"WhatsApp gateway network error: {e}")
        return False
