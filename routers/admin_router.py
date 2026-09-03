from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import logging

from db import get_supabase
from services.sms_service import send_status_update_sms

logger = logging.getLogger("admin_router")
router = APIRouter(prefix="/admin", tags=["Admin & MLA Management"])

class StatusUpdateRequest(BaseModel):
    status: str
    remarks: Optional[str] = ""

class PriorityUpdateRequest(BaseModel):
    priority: str

class UserCreateRequest(BaseModel):
    email: str
    role: str
    name: Optional[str] = None

class UserRoleUpdateRequest(BaseModel):
    role: str

@router.get("/complaints")
async def list_complaints(
    status: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
):
    """Retrieve filtered complaints list for Admin and MLA dashboards."""
    sb = get_supabase()
    if not sb:
        raise HTTPException(status_code=500, detail="Database connection unavailable")

    try:
        query = sb.table("complaints").select("*").order("created_at", desc=True)

        if status and status.lower() != "all":
            query = query.eq("status", status)

        if category and category.lower() != "all":
            query = query.eq("category", category)

        if search:
            clean = search.strip()
            # Search by complaint_no, name, or mobile
            query = query.or_(f"complaint_no.ilike.%{clean}%,name.ilike.%{clean}%,mobile_number.ilike.%{clean}%,title.ilike.%{clean}%")

        query = query.range(offset, offset + limit - 1)
        res = query.execute()

        return {
            "status": "success",
            "count": len(res.data or []),
            "complaints": res.data or [],
        }
    except Exception as e:
        logger.error(f"list_complaints error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/complaints/{id}/status")
async def update_complaint_status(id: str, req: StatusUpdateRequest):
    """Update complaint status and automatically dispatch WhatsApp alert to citizen."""
    sb = get_supabase()
    if not sb:
        raise HTTPException(status_code=500, detail="Database connection unavailable")

    try:
        # 1. Fetch existing complaint record to get citizen mobile and complaint_no
        existing_res = sb.table("complaints").select("*").eq("id", id).maybe_single().execute()
        if not existing_res.data:
            # Fallback check by complaint_no
            existing_res = sb.table("complaints").select("*").eq("complaint_no", id).maybe_single().execute()

        if not existing_res.data:
            raise HTTPException(status_code=404, detail="Complaint not found")

        complaint = existing_res.data
        target_id = complaint["id"]
        mobile = complaint.get("mobile_number")
        complaint_no = complaint.get("complaint_no")

        # 2. Update status in database
        update_data = {
            "status": req.status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        res = sb.table("complaints").update(update_data).eq("id", target_id).execute()

        # 3. Send WhatsApp alert to citizen
        if mobile and complaint_no:
            try:
                await send_status_update_sms(
                    mobile_number=mobile,
                    complaint_no=complaint_no,
                    status=req.status,
                    remarks=req.remarks or ""
                )
            except Exception as sms_err:
                logger.warning(f"Could not dispatch status update WhatsApp: {sms_err}")

        return {
            "status": "success",
            "message": f"Status updated to {req.status}",
            "complaint": res.data[0] if res.data else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"update_complaint_status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/complaints/{id}/priority")
async def update_complaint_priority(id: str, req: PriorityUpdateRequest):
    """Update priority level of a complaint."""
    sb = get_supabase()
    if not sb:
        raise HTTPException(status_code=500, detail="Database connection unavailable")

    try:
        update_data = {
            "priority": req.priority,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        res = sb.table("complaints").update(update_data).eq("id", id).execute()
        return {
            "status": "success",
            "message": f"Priority updated to {req.priority}",
            "complaint": res.data[0] if res.data else None,
        }
    except Exception as e:
        logger.error(f"update_complaint_priority error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ================= USER ROLES & ACCESS CONTROL =================

@router.get("/users")
async def list_users():
    """List all authorized admin and superadmin accounts."""
    sb = get_supabase()
    if not sb:
        raise HTTPException(status_code=500, detail="Database connection unavailable")

    try:
        res = sb.table("user_roles").select("*").order("created_at", desc=True).execute()
        return {"status": "success", "users": res.data or []}
    except Exception as e:
        logger.error(f"list_users error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/users")
async def add_user(req: UserCreateRequest):
    """Authorize a new staff email with designated role."""
    sb = get_supabase()
    if not sb:
        raise HTTPException(status_code=500, detail="Database connection unavailable")

    clean_email = req.email.strip().lower()
    try:
        payload = {
            "email": clean_email,
            "role": req.role,
            "name": req.name or clean_email.split("@")[0],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        res = sb.table("user_roles").insert(payload).execute()
        return {"status": "success", "user": res.data[0] if res.data else payload}
    except Exception as e:
        logger.error(f"add_user error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/users/{id}/role")
async def update_user_role(id: str, req: UserRoleUpdateRequest):
    """Change authorization role of an existing user."""
    sb = get_supabase()
    if not sb:
        raise HTTPException(status_code=500, detail="Database connection unavailable")

    try:
        res = sb.table("user_roles").update({"role": req.role, "updated_at": datetime.now(timezone.utc).isoformat()}).eq("id", id).execute()
        return {"status": "success", "user": res.data[0] if res.data else None}
    except Exception as e:
        logger.error(f"update_user_role error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/users/{id}")
async def delete_user(id: str):
    """Revoke authorization for a user account."""
    sb = get_supabase()
    if not sb:
        raise HTTPException(status_code=500, detail="Database connection unavailable")

    try:
        sb.table("user_roles").delete().eq("id", id).execute()
        return {"status": "success", "message": "Access revoked successfully."}
    except Exception as e:
        logger.error(f"delete_user error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
