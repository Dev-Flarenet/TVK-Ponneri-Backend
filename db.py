import os
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger("backend_db")

CONFIG_PATH = Path(__file__).resolve().parent / "config.json"

def get_config_value(key: str) -> Optional[str]:
    """Read configuration from environment variable first, then config.json."""
    # 1. Check OS Environment variable
    env_val = os.getenv(key) or os.getenv(key.upper())
    if env_val:
        return env_val.strip()

    # 2. Check config.json on disk
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                val = data.get(key) or data.get(key.upper())
                if val:
                    return str(val).strip()
        except Exception as e:
            logger.error(f"Error reading configuration file {CONFIG_PATH}: {e}")

    return None

_supabase_client = None

def get_supabase():
    """Initializes and returns the singleton Supabase client from configuration."""
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    url = get_config_value("SUPABASE_URL")
    key = get_config_value("SUPABASE_SERVICE_ROLE_KEY") or get_config_value("SUPABASE_KEY")

    if not url or not key:
        logger.error("Database connection failed: SUPABASE_URL or SUPABASE_KEY is missing from config.json and environment.")
        return None

    try:
        from supabase import create_client
        _supabase_client = create_client(url, key)
        logger.info(f"Connected to Supabase database at {url}")
        return _supabase_client
    except Exception as e:
        logger.error(f"Failed to connect to Supabase: {e}")
        return None

async def get_dynamic_config(key: str) -> Optional[str]:
    """Read a setting from config.json or environment."""
    return get_config_value(key)
