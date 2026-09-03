# 🚀 TVK Ponneri MLA Portal - Unified Backend

Standalone FastAPI backend microservice for TVK Ponneri Web portal.

Runs on AWS EC2 (Hyderabad / Mumbai) to provide clean Indian IP routing for UIDAI Aadhaar verification, automated WhatsApp dispatch, and secure grievance processing without requiring client-side database credentials.

## ⚡ Zero Configuration Required
This backend is **100% Zero-Config**. No `.env` file is required. It automatically uses secure fallback defaults and reads live operational parameters dynamically from the `system_config` table.

## 🏃 Running on AWS EC2

```bash
# 1. Clone repository
git clone https://github.com/Dev-Flarenet/TVK-Ponneri-Backend.git Backend
cd Backend

# 2. Install requirements
pip install -r requirements.txt

# 3. Start service
python3 main.py
```

## 📡 API Endpoints Summary

- `GET /health` - Health check
- `GET /docs` - Swagger interactive documentation
- `GET /api/aadhaar/init` - Fetch UIDAI Captcha
- `POST /api/aadhaar/verify` - Verify Aadhaar
- `POST /api/complaints` - Register new citizen grievance petition
- `GET /api/complaints/track/{query}` - Public petition tracking
- `GET /api/complaints/citizen/{mobile}` - Citizen's petition history
- `GET /api/complaints/stats/summary` - Public home page statistics
- `GET /api/admin/complaints` - Filtered complaints list for MLA & Admin
- `PATCH /api/admin/complaints/{id}/status` - Status update with WhatsApp alert
- `GET /api/admin/users` - Admin user list
- `POST /api/admin/users` - Authorize new admin/staff
- `GET /api/config/public` - Public dynamic configuration
