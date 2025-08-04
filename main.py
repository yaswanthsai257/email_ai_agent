# main.py
import os
import uuid
import base64
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Request, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from jose import JWTError, jwt
from supabase import create_client, Client

from ai_service import get_summary_from_grok

# --- Configuration & Setup ---
load_dotenv()
app = FastAPI()

# --- MODIFICATION FOR DEPLOYMENT ---
# Get URLs from environment variables, with localhost as a fallback for local dev
# The default is now your live Vercel URL
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://email-agent-ai.vercel.app") 
BACKEND_URL = os.getenv("BACKEND_URL", "https://email-ai-agent-8.onrender.com")
REDIRECT_URI = f"{BACKEND_URL}/auth/google/callback"

# Add CORS Middleware
origins = [
    FRONTEND_URL, # Use the variable here
    "http://localhost:8080", # Keep localhost for local testing
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Supabase Client Setup
url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_SERVICE_KEY")
if not url or not key: raise ValueError("Supabase URL or Service Key not set.")
supabase: Client = create_client(url, key)

# Other Configs
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/gmail.readonly"]
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

client_config = {"web": {"client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET, "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token"}}

# --- Pydantic Models ---
class EmailRequest(BaseModel): email_content: str

# --- JWT & Security Functions ---
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user_id(authorization: str | None = Header(default=None)):
    if authorization is None: raise HTTPException(status_code=401, detail="Authorization header missing")
    token = authorization.replace("Bearer ", "")
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None: raise credentials_exception
        return user_id
    except JWTError: raise credentials_exception

# --- Authentication Endpoints ---
@app.get("/login/google")
async def login_google():
    flow = Flow.from_client_config(client_config, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    authorization_url, _ = flow.authorization_url(access_type='offline', prompt='consent')
    return RedirectResponse(authorization_url)

@app.get("/auth/google/callback")
async def auth_google_callback(request: Request):
    flow = Flow.from_client_config(client_config, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    flow.fetch_token(authorization_response=str(request.url))
    creds = flow.credentials
    user_info = build('oauth2', 'v2', credentials=creds).userinfo().get().execute()
    google_user_id, user_email = user_info['id'], user_info['email']
    user_data = {"id": google_user_id, "email": user_email, "refresh_token": creds.refresh_token}
    supabase.table("users").upsert(user_data).execute()
    access_token = create_access_token(data={"sub": google_user_id})
    return RedirectResponse(url=f"{FRONTEND_URL}/auth/callback?token={access_token}")

# --- Helper & API Endpoints ---
def get_user_refresh_token(user_id: str) -> str | None:
    response = supabase.table("users").select("refresh_token").eq("id", user_id).execute()
    return response.data[0].get("refresh_token") if response.data else None

@app.get("/api/sync-gmail")
async def sync_gmail(user_id: str = Depends(get_current_user_id)):
    refresh_token = get_user_refresh_token(user_id)
    if not refresh_token: raise HTTPException(status_code=404, detail="User refresh token not found. Please log in again.")
    creds = Credentials(None, refresh_token=refresh_token, token_uri="https://oauth2.googleapis.com/token", client_id=GOOGLE_CLIENT_ID, client_secret=GOOGLE_CLIENT_SECRET, scopes=SCOPES)
    try:
        gmail_service = build('gmail', 'v1', credentials=creds)
        results = gmail_service.users().messages().list(userId='me', q='category:primary', maxResults=20).execute()
        messages = results.get('messages', [])
        if not messages: return {"message": "No new emails found.", "processed_emails": []}
        
        processed_emails = []
        for message_info in messages:
            msg = gmail_service.users().messages().get(userId='me', id=message_info['id'], format='full').execute()
            payload, headers = msg['payload'], msg['payload']['headers']
            subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'No Sender')

            if 'parts' in payload:
                part = next((p for p in payload['parts'] if p.get('mimeType') == 'text/plain'), None)
                body_data = part['body'].get('data') if part else None
            else:
                body_data = payload['body'].get('data')

            if body_data:
                email_body = base64.urlsafe_b64decode(body_data).decode('utf-8', 'ignore')
                ai_result = get_summary_from_grok(sender=sender, subject=subject, email_text=email_body[:4000])
                if ai_result['category'] != 'error':
                    data_to_insert = { "user_id": user_id, "gmail_message_id": msg['id'], "sender": sender, "subject": subject, "summary": ai_result['summary'], "tag": ai_result['category'], "received_at": datetime.fromtimestamp(int(msg['internalDate']) / 1000).isoformat() }
                    supabase.table("emails").upsert(data_to_insert, on_conflict="user_id,gmail_message_id").execute()
                    processed_emails.append(data_to_insert)

        return {"message": f"Sync complete. Processed {len(processed_emails)} emails.", "processed_emails": processed_emails}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

@app.get("/api/summaries")
async def get_summaries(user_id: str = Depends(get_current_user_id)):
    try:
        response = supabase.table("emails").select("*").eq("user_id", user_id).order("received_at", desc=True).limit(20).execute()
        return {"summaries": response.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred while fetching summaries: {str(e)}")