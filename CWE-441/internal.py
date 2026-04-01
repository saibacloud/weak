# Simulated internal admin API — the target the attacker wants to reach.
# In real life this would be behind a firewall on a separate host.
# For this demo it just runs on port 8001 alongside the main app.
#
# Start with: uvicorn internal:app --port 8001

from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

# Fake sensitive config — the kind of stuff that should never leave the internal network.
INTERNAL_CONFIG = {
    "db_host":     "db-prod-01.internal",
    "db_password": "s3cr3t_prod_pw!",
    "api_key":     "sk-internal-abc123xyz789",
    "admin_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.internal",
    "network":     "10.0.0.0/8",
    "note":        "This data was fetched by the confused deputy on your behalf.",
}


@app.get("/admin")
async def admin_panel():
    # This endpoint is the target. A real firewall would block your browser from hitting this.
    # The only reason the attack works is that the server on port 5000 can reach it — you can't.
    return JSONResponse(INTERNAL_CONFIG)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "internal-api", "port": 8001}
