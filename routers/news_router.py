from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
import logging

from db import get_supabase

logger = logging.getLogger("news_router")
router = APIRouter(prefix="/news", tags=["News & Press Feed"])

@router.get("")
async def get_news_feed():
    """Retrieve real public announcement and press items from database."""
    sb = get_supabase()
    if not sb:
        raise HTTPException(status_code=503, detail="Database service temporarily unavailable")

    try:
        res = sb.table("news_feed").select("*").order("created_at", desc=True).limit(6).execute()
        return {"status": "success", "news": res.data or []}
    except Exception as e:
        logger.error(f"Failed to fetch news feed: {e}")
        raise HTTPException(status_code=500, detail="Error fetching announcements")
