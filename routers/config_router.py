import json
import os
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger("config_router")
router = APIRouter(prefix="/config", tags=["System Configuration"])

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"

def load_json_config() -> Dict[str, str]:
    if not CONFIG_PATH.exists():
        return {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to read {CONFIG_PATH}: {e}")
        return {}

def save_json_config(data: Dict[str, str]):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to write {CONFIG_PATH}: {e}")
        raise HTTPException(status_code=500, detail="Failed to write configuration file")

class ConfigItem(BaseModel):
    key: str
    value: str
    label: Optional[str] = None
    description: Optional[str] = None
    is_secret: Optional[bool] = False

class ConfigBatchUpdateRequest(BaseModel):
    configs: List[ConfigItem]

@router.get("/public")
async def get_public_config():
    """Retrieve public application parameters without secret tokens."""
    cfg = load_json_config()
    return {
        "WHATSAPP_BASE_URL": cfg.get("WHATSAPP_BASE_URL", ""),
        "INSTANCE_NAME": cfg.get("WHATSAPP_INSTANCE_NAME", ""),
    }

@router.get("/all")
async def get_all_configs():
    """Retrieve all operational variables for SuperAdmin."""
    cfg = load_json_config()
    configs_list = [
        {
            "key": k,
            "value": v,
            "is_secret": "KEY" in k.upper() or "SECRET" in k.upper(),
        }
        for k, v in cfg.items()
    ]
    return {"status": "success", "configs": configs_list}

@router.post("")
async def save_configs(req: ConfigBatchUpdateRequest):
    """Save or update system parameters directly to config.json."""
    cfg = load_json_config()
    for item in req.configs:
        cfg[item.key.strip().upper()] = item.value.strip()
    save_json_config(cfg)
    return {"status": "success", "message": "Configuration saved successfully to config.json"}
