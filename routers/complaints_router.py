from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import random
import logging

from db import get_supabase
from services.sms_service import send_status_update_sms

logger = logging.getLogger("complaints_router")
router = APIRouter(prefix="/complaints", tags=["Complaints"])

class ComplaintCreateRequest(BaseModel):
    name: str
    relation: str
    mobile_number: str
    aadhar: str
    category: str
    title: str
    description: str
    priority: Optional[str] = "Normal"
    # Optional location details if provided
    village: Optional[str] = None
    ward: Optional[str] = None

@router.get("/check-active/{aadhar}")
async def check_active_complaint(aadhar: str):
    """Check if there is already an active (unsolved) petition for this Aadhaar number."""
    sb = get_supabase()
    if not sb:
        raise HTTPException(status_code=500, detail="Database connection unavailable")

    clean_aadhar = aadhar.replace(" ", "").strip()
    try:
        res = (
            sb.table("complaints")
            .select("id, complaint_no, status, title")
            .eq("aadhar", clean_aadhar)
            .neq("status", "Complaint Solved")
            .execute()
        )
        has_active = bool(res.data and len(res.data) > 0)
        return {
            "has_active": has_active,
            "complaints": res.data if has_active else [],
        }
    except Exception as e:
        logger.error(f"check_active_complaint error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("")
async def create_complaint(req: ComplaintCreateRequest):
    """Submit a new grievance petition, generate TVK-PON complaint number, and notify citizen."""
    sb = get_supabase()
    if not sb:
        raise HTTPException(status_code=500, detail="Database connection unavailable")

    clean_aadhar = req.aadhar.replace(" ", "").strip()
    clean_mobile = req.mobile_number.replace("+", "").replace(" ", "").replace("-", "").strip()

    # Generate professional complaint number: TVK-PON-YYYY-XXXXX
    year = datetime.now().year
    random_digits = str(random.randint(10000, 99999))
    complaint_no = f"TVK-PON-{year}-{random_digits}"

    payload = {
        "complaint_no": complaint_no,
        "name": req.name.strip(),
        "relation": req.relation.strip(),
        "mobile_number": clean_mobile,
        "aadhar": clean_aadhar,
        "category": req.category.strip(),
        "title": req.title.strip(),
        "description": req.description.strip(),
        "priority": req.priority or "Normal",
        "status": "Raised",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        res = sb.table("complaints").insert(payload).execute()
        if not res.data:
            raise Exception("Failed to insert complaint record into database")

        created = res.data[0]

        # Trigger asynchronous WhatsApp status alert
        try:
            await send_status_update_sms(
                mobile_number=clean_mobile,
                complaint_no=complaint_no,
                status="Raised",
                remarks="மனு வெற்றிகரமாக பதிவு செய்யப்பட்டுள்ளது."
            )
        except Exception as sms_err:
            logger.warning(f"WhatsApp notification dispatch failed: {sms_err}")

        return {
            "status": "success",
            "message": "Complaint registered successfully.",
            "complaint_no": complaint_no,
            "data": created,
        }
    except Exception as e:
        logger.error(f"create_complaint error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/track/{query}")
async def track_complaint(query: str):
    """Track complaint status by Complaint Number or Mobile Number."""
    sb = get_supabase()
    if not sb:
        raise HTTPException(status_code=500, detail="Database connection unavailable")

    clean_query = query.strip()
    try:
        # First attempt exact complaint_no lookup
        res = sb.table("complaints").select("*").eq("complaint_no", clean_query).maybe_single().execute()
        if res.data:
            return {"type": "single", "complaint": res.data}

        # Otherwise attempt mobile lookup
        res_mobile = (
            sb.table("complaints")
            .select("*")
            .eq("mobile_number", clean_query.replace("+", "").replace(" ", "").replace("-", ""))
            .order("created_at", desc=True)
            .execute()
        )
        if res_mobile.data and len(res_mobile.data) > 0:
            return {"type": "list", "complaints": res_mobile.data}

        return {"type": "not_found", "message": "No matching grievance found for this query."}
    except Exception as e:
        logger.error(f"track_complaint error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/citizen/{mobile}")
async def get_citizen_complaints(mobile: str):
    """Retrieve all petitions registered against a citizen's mobile number."""
    sb = get_supabase()
    if not sb:
        raise HTTPException(status_code=500, detail="Database connection unavailable")

    clean_mobile = mobile.replace("+", "").replace(" ", "").replace("-", "").strip()
    try:
        res = (
            sb.table("complaints")
            .select("*")
            .eq("mobile_number", clean_mobile)
            .order("created_at", desc=True)
            .execute()
        )
        return {"status": "success", "complaints": res.data or []}
    except Exception as e:
        logger.error(f"get_citizen_complaints error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats/summary")
async def get_home_stats():
    """Aggregate real-time statistics from the database for public counters."""
    sb = get_supabase()
    if not sb:
        raise HTTPException(status_code=503, detail="Database service temporarily unavailable")

    try:
        res = sb.table("complaints").select("id, status").execute()
        all_items = res.data or []
        total = len(all_items)
        solved = sum(1 for c in all_items if c.get("status") == "Complaint Solved")
        in_progress = sum(1 for c in all_items if c.get("status") in ("In Progress", "Under Review", "Raised"))
        rate = f"{round((solved / total) * 100)}%" if total > 0 else "0%"

        return {
            "total": total,
            "solved": solved,
            "in_progress": in_progress,
            "resolution_rate": rate,
        }
    except Exception as e:
        logger.error(f"get_home_stats query error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve grievance statistics")


@router.get("/{id}")
async def get_complaint_by_id(id: str):
    """Fetch complete details of a complaint by ID or complaint_no."""
    sb = get_supabase()
    if not sb:
        raise HTTPException(status_code=500, detail="Database connection unavailable")

    try:
        # Check by id (UUID) or complaint_no
        if id.startswith("TVK-"):
            res = sb.table("complaints").select("*").eq("complaint_no", id).maybe_single().execute()
        else:
            res = sb.table("complaints").select("*").eq("id", id).maybe_single().execute()

        if not res.data:
            raise HTTPException(status_code=404, detail="Complaint not found")
        return res.data
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"get_complaint_by_id error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
