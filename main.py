import os
import sys
from pathlib import Path

# Ensure Backend directory is in Python path whether run from root or Backend/
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("backend_main")

app = FastAPI(
    title="TVK Ponneri MLA Portal - Unified Backend API",
    description="Centralized REST API for Aadhaar Verification, Grievance Lifecycle, WhatsApp Notifications, and Administrative Portals",
    version="2.0.0",
)

# Open CORS policy allowing requests from Vercel deployments, custom domains, and local preview
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from routers.aadhaar_router import router as aadhaar_router
from routers.complaints_router import router as complaints_router

from routers.admin_router import router as admin_router
from routers.config_router import router as config_router
from routers.news_router import router as news_router
from routers.sms_router import router as sms_router

# Mount all routers under /api (Standard path)
app.include_router(aadhaar_router, prefix="/api")
app.include_router(complaints_router, prefix="/api")
app.include_router(admin_router, prefix="/api")
app.include_router(config_router, prefix="/api")
app.include_router(news_router, prefix="/api")
app.include_router(sms_router, prefix="/api")

# Fallback alias mounts without /api prefix
app.include_router(aadhaar_router, prefix="")
app.include_router(complaints_router, prefix="")
app.include_router(admin_router, prefix="")
app.include_router(config_router, prefix="")
app.include_router(news_router, prefix="")
app.include_router(sms_router, prefix="")

@app.get("/")
def read_root():
    return {
        "service": "TVK Ponneri Unified Backend API",
        "status": "online",
        "region": "AWS Hyderabad (ap-south-2)",
        "docs": "/docs",
        "version": "2.0.0",
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "code": 200,
        "service": "TVK Ponneri Backend",
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("main:app", host=host, port=port, reload=False)
