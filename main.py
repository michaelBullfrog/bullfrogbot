# main.py
"""
Webex Bot → Zoho CRM Lead → Google Sheet/Doc
Python FastAPI implementation

ENV (.env)
-----------
WEBEX_BOT_TOKEN=xxxxx
WEBEX_WEBHOOK_SECRET=optional-secret
WEBEX_ROOM_ID=optional-room-id

ZOHO_CLIENT_ID=xxxx
ZOHO_CLIENT_SECRET=xxxx
ZOHO_REFRESH_TOKEN=xxxx
ZOHO_DC=com  # com, eu, in

GOOGLE_CLIENT_EMAIL=sa-name@project.iam.gserviceaccount.com
GOOGLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
GOOGLE_SHEET_ID=sheetIdIfUsingSheets
GOOGLE_DOC_ID=docIdIfUsingDocs  # optional
PORT=3000
"""

import os
import hmac
import json
import re
import hashlib
from datetime import datetime

from fastapi import FastAPI, Request, Header, HTTPException
from typing import Optional
from time import time
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
import httpx
from dotenv import load_dotenv

from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build

load_dotenv()

app = FastAPI()

WEBEX_API = "https://webexapis.com/v1"
WEBEX_BOT_TOKEN = os.getenv("WEBEX_BOT_TOKEN")
WEBEX_WEBHOOK_SECRET = os.getenv("WEBEX_WEBHOOK_SECRET")
WEBEX_ROOM_ID = os.getenv("WEBEX_ROOM_ID")

ZOHO_CLIENT_ID = os.getenv("ZOHO_CLIENT_ID")
ZOHO_CLIENT_SECRET = os.getenv("ZOHO_CLIENT_SECRET")
ZOHO_REFRESH_TOKEN = os.getenv("ZOHO_REFRESH_TOKEN")
ZOHO_DC = os.getenv("ZOHO_DC", "com")

GOOGLE_CLIENT_EMAIL = os.getenv("GOOGLE_CLIENT_EMAIL")
GOOGLE_PRIVATE_KEY = os.getenv("GOOGLE_PRIVATE_KEY", "").replace("\\n", "\n")
GOOGLE_SHEET_ID = os.getenv("GOOGLE_SHEET_ID")
GOOGLE_DOC_ID = os.getenv("GOOGLE_DOC_ID")

if not WEBEX_BOT_TOKEN:
    raise RuntimeError("WEBEX_BOT_TOKEN is required")

bot_person_id = None

# --- Idempotency guard for duplicate webhook deliveries ---
RECENT_TTL_SECONDS = 300  # 5 minutes
_recent_seen: dict[str, float] = {}

def seen_before(message_id: str) -> bool:
    now = time()
    # cleanup expired
    expired = [k for k, ts in _recent_seen.items() if now - ts > RECENT_TTL_SECONDS]
    for k in expired:
        _recent_seen.pop(k, None)
    if message_id in _recent_seen:
        return True
    _recent_seen[message_id] = now
    return False

# ------------------ Webex helpers ------------------
async def webex_me():
    global bot_person_id
    if bot_person_id:
        return bot_person_id
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{WEBEX_API}/people/me", headers={"Authorization": f"Bearer {WEBEX_BOT_TOKEN}"})
        r.raise_for_status()
        bot_person_id = r.json()["id"]
        return bot_person_id

async def webex_get_message(message_id: str):
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{WEBEX_API}/messages/{message_id}", headers={"Authorization": f"Bearer {WEBEX_BOT_TOKEN}"})
        r.raise_for_status()
        return r.json()

async def webex_post_message(room_id: str, markdown: str):
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{WEBEX_API}/messages",
            headers={"Authorization": f"Bearer {WEBEX_BOT_TOKEN}", "Content-Type": "application/json"},
            json={"roomId": room_id, "markdown": markdown},
        )
        r.raise_for_status()
        return r.json()

# ------------------ Parsing ------------------
KV_RE = re.compile(r"(name|email|company|phone|first_name|last_name)\s*[:=]\s*([^;\n]+)", re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
PHONE_RE = re.compile(r"\+?\d[\d\s().-]{7,}")


def parse_lead(text: str):
    data = {}
    for m in KV_RE.finditer(text):
        key = m.group(1).lower()
        val = m.group(2).strip()
        data[key] = val

    email = data.get("email")
    if not email:
        m = EMAIL_RE.search(text)
        if m:
            email = m.group(0)

    phone = data.get("phone")
    if not phone:
        m = PHONE_RE.search(text)
        if m:
            phone = m.group(0).strip()

    name = data.get("name")
    first_name = data.get("first_name")
    last_name = data.get("last_name")

    if not name:
        # Try pipe format: Name | email | company | phone
        if "|" in text:
            parts = [p.strip() for p in text.split("|")]
            if parts:
                name = parts[0]

    company = data.get("company")
    if not company and "|" in text:
        parts = [p.strip() for p in text.split("|")]
        if len(parts) >= 3:
            company = parts[2]

    # Split name if needed
    if (not first_name or not last_name) and name:
        pieces = name.split()
        if len(pieces) == 1:
            first_name = first_name or pieces[0]
            last_name = last_name or "Unknown"
        else:
            first_name = first_name or " ".join(pieces[:-1])
            last_name = last_name or pieces[-1]

    if not last_name:
        last_name = "Unknown"

    if not company:
        company = email.split("@")[1] if email and "@" in email else "Unknown"

    return {
        "firstName": first_name or "",
        "lastName": last_name,
        "email": email or "",
        "company": company,
        "phone": phone or "",
        "raw": text,
    }

# ------------------ Zoho ------------------
async def zoho_access_token():
    if not (ZOHO_CLIENT_ID and ZOHO_CLIENT_SECRET and ZOHO_REFRESH_TOKEN):
        raise RuntimeError("Zoho OAuth env vars missing")
    url = f"https://accounts.zoho.{ZOHO_DC}/oauth/v2/token"
    data = {
        "grant_type": "refresh_token",
        "client_id": ZOHO_CLIENT_ID,
        "client_secret": ZOHO_CLIENT_SECRET,
        "refresh_token": ZOHO_REFRESH_TOKEN,
    }
    async with httpx.AsyncClient() as client:
        r = await client.post(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        r.raise_for_status()
        return r.json()["access_token"]

async def zoho_create_lead(lead: dict):
    token = await zoho_access_token()
    url = f"https://www.zohoapis.{ZOHO_DC}/crm/v2/Leads"
    payload = {
        "data": [
            {
                "First_Name": lead["firstName"],
                "Last_Name": lead["lastName"],
                "Email": lead["email"],
                "Company": lead["company"],
                "Phone": lead["phone"],
                "Description": f"Captured from Webex.\n\nRaw: {lead['raw']}",
                "Lead_Source": "Webex Bot",
            }
        ],
        "trigger": ["workflow"],
    }
    async with httpx.AsyncClient() as client:
        r = await client.post(
            url,
            json=payload,
            headers={"Authorization": f"Zoho-oauthtoken {token}", "Content-Type": "application/json"},
        )
        r.raise_for_status()
        body = r.json()
        info = (body.get("data") or [{}])[0]
        if info.get("status") == "success":
            return info["details"]["id"]
        raise RuntimeError(f"Zoho error: {json.dumps(body)})")

# ------------------ Google APIs ------------------

def google_creds(scopes):
    if not (GOOGLE_CLIENT_EMAIL and GOOGLE_PRIVATE_KEY):
        raise RuntimeError("Google SA env vars missing")
    return Credentials.from_service_account_info(
        {
            "type": "service_account",
            "client_email": GOOGLE_CLIENT_EMAIL,
            "private_key": GOOGLE_PRIVATE_KEY,
            "token_uri": "https://oauth2.googleapis.com/token",
        },
        scopes=scopes,
    )

async def sheets_append_row(values):
    if not GOOGLE_SHEET_ID:
        return None
    creds = google_creds(["https://www.googleapis.com/auth/spreadsheets"]).with_subject(None)
    service = build("sheets", "v4", credentials=creds, cache_discovery=False)
    req = service.spreadsheets().values().append(
        spreadsheetId=GOOGLE_SHEET_ID,
        range="Leads!A1",
        valueInputOption="USER_ENTERED",
        body={"values": [values]},
    )
    res = req.execute()
    return (res.get("updates") or {}).get("updatedRange")

async def gdoc_append_text(text: str):
    if not GOOGLE_DOC_ID:
        return None
    creds = google_creds(["https://www.googleapis.com/auth/documents"]).with_subject(None)
    service = build("docs", "v1", credentials=creds, cache_discovery=False)
    body = {
        "requests": [
            {"insertText": {"endOfSegmentLocation": {}, "text": text}},
            {"insertText": {"endOfSegmentLocation": {}, "text": "\n\n"}},
        ]
    }
    service.documents().batchUpdate(documentId=GOOGLE_DOC_ID, body=body).execute()
    return "Appended to Doc"

# ------------------ Webhook signature ------------------

def verify_signature(raw_body: bytes, signature: Optional[str]) -> bool:
    if not WEBEX_WEBHOOK_SECRET:
        return True
    if not signature:
        return False
    mac = hmac.new(WEBEX_WEBHOOK_SECRET.encode(), raw_body, hashlib.sha1).hexdigest()
    return hmac.compare_digest(mac, signature)

# ------------------ Models ------------------
class WebexEventData(BaseModel):
    id: str
    roomId: str
    personId: Optional[str] = None

class WebexEvent(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    resource: str
    event: str
    data: WebexEventData

# ------------------ Routes ------------------
@app.get("/healthz")
async def healthz():
    return PlainTextResponse("ok")

@app.post("/webex/webhook")
async def webex_webhook(request: Request, x_spark_signature: Optional[str] = Header(None)):
    raw = await request.body()
    if not verify_signature(raw, x_spark_signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = WebexEvent(**(await request.json()))
    if payload.resource != "messages" or payload.event != "created":
        return PlainTextResponse("ignored")

    if WEBEX_ROOM_ID and payload.data.roomId != WEBEX_ROOM_ID:
        return PlainTextResponse("wrong room")

    # Deduplicate if the same Webex event/message arrives more than once (multiple webhooks or retries)
    if seen_before(payload.data.id):
        return PlainTextResponse("duplicate")

    me = await webex_me()
    msg = await webex_get_message(payload.data.id)
    if msg.get("personId") == me:
        return PlainTextResponse("own message")

    text = (msg.get("markdown") or msg.get("text") or "").strip()
    if not text:
        return PlainTextResponse("no text")

    lead = parse_lead(text)

    try:
        zoho_id = await zoho_create_lead(lead)
    except Exception as e:
        # Notify room and return handled
        try:
            await webex_post_message(payload.data.roomId, f"❌ Zoho error: {e}")
        finally:
            return PlainTextResponse("handled")

    # Google logging (best-effort)
    ts = datetime.utcnow().isoformat()
    try:
        updated = await sheets_append_row([
            ts,
            f"{lead['firstName']} {lead['lastName']}".strip(),
            lead["email"],
            lead["company"],
            lead["phone"],
            payload.data.roomId,
            payload.data.id,
            zoho_id,
        ])
    except Exception:
        updated = None

    try:
        doc_status = await gdoc_append_text(
            (
                f"Lead @ {ts}\n"
                f"Name: {lead['firstName']} {lead['lastName']}\n"
                f"Email: {lead['email']}\n"
                f"Company: {lead['company']}\n"
                f"Phone: {lead['phone']}\n"
                f"Zoho ID: {zoho_id}\n"
                f"Room: {payload.data.roomId}\n"
                f"Message: {lead['raw']}"
            )
        )
    except Exception:
        doc_status = None

    conf = f"✅ Lead created in Zoho (ID **{zoho_id}**)."
    if updated:
        conf += f"\n📊 Logged to Google Sheet range: `{updated}`"
    if doc_status:
        conf += f"\n📄 {doc_status}"

    await webex_post_message(payload.data.roomId, conf)
    return PlainTextResponse("ok")

# --------------- Dev helper to create webhook (run once via curl) ---------------
"""
Example cURL to create the webhook (replace values):

curl -X POST "https://webexapis.com/v1/webhooks" \
 -H "Authorization: Bearer $WEBEX_BOT_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
   "name": "Leads from Space (Python)",
   "targetUrl": "https://YOUR_PUBLIC_URL/webex/webhook",
   "resource": "messages",
   "event": "created",
   "filter": "roomId=YOUR_ROOM_ID",
   "secret": "YOUR_WEBHOOK_SECRET"
 }'
"""

# ------------------ Run ------------------
# uvicorn main:app --host 0.0.0.0 --port ${PORT:-3000}
