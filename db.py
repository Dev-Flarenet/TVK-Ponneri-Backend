import os
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
import httpx

logger = logging.getLogger("backend_db")

CONFIG_PATH = Path(__file__).resolve().parent / "config.json"

def get_config_value(key: str) -> Optional[str]:
    """Read configuration from environment variable first, then config.json."""
    env_val = os.getenv(key) or os.getenv(key.upper())
    if env_val:
        return env_val.strip()

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

class PostgrestResponse:
    def __init__(self, data: Any):
        self.data = data

class PostgrestQueryBuilder:
    def __init__(self, base_url: str, key: str, table_name: str):
        self.base_url = base_url.rstrip("/")
        self.key = key
        self.table_name = table_name
        self.endpoint = f"{self.base_url}/rest/v1/{table_name}"
        self.method = "GET"
        self.params: Dict[str, str] = {}
        self.headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        }
        self.body: Optional[Any] = None
        self.is_single = False

    def select(self, columns: str = "*"):
        self.params["select"] = columns
        return self

    def eq(self, column: str, value: Any):
        self.params[column] = f"eq.{value}"
        return self

    def neq(self, column: str, value: Any):
        self.params[column] = f"neq.{value}"
        return self

    def ilike(self, column: str, pattern: str):
        self.params[column] = f"ilike.{pattern}"
        return self

    def or_(self, expression: str):
        self.params["or"] = f"({expression})"
        return self

    def order(self, column: str, desc: bool = False):
        direction = "desc" if desc else "asc"
        self.params["order"] = f"{column}.{direction}"
        return self

    def limit(self, count: int):
        self.params["limit"] = str(count)
        return self

    def range(self, start: int, end: int):
        self.params["offset"] = str(start)
        self.params["limit"] = str(end - start + 1)
        return self

    def maybe_single(self):
        self.is_single = True
        return self

    def insert(self, data: Any):
        self.method = "POST"
        self.body = [data] if isinstance(data, dict) else data
        self.headers["Prefer"] = "return=representation"
        return self

    def update(self, data: Dict[str, Any]):
        self.method = "PATCH"
        self.body = data
        self.headers["Prefer"] = "return=representation"
        return self

    def upsert(self, data: Any):
        self.method = "POST"
        self.body = [data] if isinstance(data, dict) else data
        self.headers["Prefer"] = "resolution=merge-duplicates,return=representation"
        return self

    def delete(self):
        self.method = "DELETE"
        self.headers["Prefer"] = "return=representation"
        return self

    def execute(self) -> PostgrestResponse:
        with httpx.Client(timeout=15.0) as client:
            resp = client.request(
                method=self.method,
                url=self.endpoint,
                params=self.params if self.method in ("GET", "DELETE") else self.params,
                json=self.body,
                headers=self.headers,
            )
            if resp.status_code not in (200, 201, 204):
                logger.error(f"PostgREST {self.method} error (HTTP {resp.status_code}): {resp.text}")
                return PostgrestResponse(None)

            try:
                json_data = resp.json()
                if self.is_single:
                    val = json_data[0] if (isinstance(json_data, list) and len(json_data) > 0) else None
                    return PostgrestResponse(val)
                return PostgrestResponse(json_data)
            except Exception:
                return PostgrestResponse(None)

class ResilientSupabaseClient:
    def __init__(self, url: str, key: str):
        self.url = url.rstrip("/")
        self.key = key

    def table(self, table_name: str) -> PostgrestQueryBuilder:
        return PostgrestQueryBuilder(self.url, self.key, table_name)

_supabase_client = None

def get_supabase():
    """Initializes and returns a resilient Supabase database client."""
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    url = get_config_value("SUPABASE_URL")
    key = get_config_value("SUPABASE_SERVICE_ROLE_KEY") or get_config_value("SUPABASE_KEY")

    if not url or not key:
        logger.error("Database connection failed: SUPABASE_URL or SUPABASE_KEY missing.")
        return None

    # Try official SDK first if installed
    try:
        from supabase import create_client
        _supabase_client = create_client(url, key)
        logger.info(f"Connected to Supabase via official client ({url})")
        return _supabase_client
    except Exception:
        # Transparently use resilient PostgREST HTTP client (Zero external dependencies)
        logger.info(f"Connected to Supabase via resilient PostgREST client ({url})")
        _supabase_client = ResilientSupabaseClient(url, key)
        return _supabase_client

async def get_dynamic_config(key: str) -> Optional[str]:
    """Read a setting from config.json or environment."""
    return get_config_value(key)
