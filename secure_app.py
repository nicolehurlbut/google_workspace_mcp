import os
import sys
import logging
import json
import io
import datetime
import time
import secrets
import base64
import httpx
from urllib.parse import urlencode, parse_qs, urlparse
from typing import Optional

# Redis support
REDIS_AVAILABLE = False
redis = None  # Define redis as None initially
try:
    import redis as redis_module
    redis = redis_module
    REDIS_AVAILABLE = True
except ImportError:
    pass

# Standard MCP & Starlette
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

# Try to import ToolAnnotations (newer MCP versions)
try:
    from mcp.types import ToolAnnotations
    HAS_TOOL_ANNOTATIONS = True
except ImportError:
    HAS_TOOL_ANNOTATIONS = False
    ToolAnnotations = None

# Google & Auth
from google.oauth2 import service_account
from googleapiclient.discovery import build

# File Handlers
from pypdf import PdfReader
import openpyxl

# --- 1. LOGGING & CONFIG ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("google_mcp")

KEY_PATH = "/app/service-account.json"
ALLOWED_DOMAIN = "singlefile.io"
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")  # Remove trailing slash

# Redis configuration
REDIS_URL = os.environ.get("REDIS_URL")  # e.g., redis://localhost:6379 or rediss://... for TLS
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")
REDIS_SSL = os.environ.get("REDIS_SSL", "false").lower() == "true"

SCOPES = [
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/spreadsheets.readonly',
    'https://www.googleapis.com/auth/documents.readonly',
    'https://www.googleapis.com/auth/presentations.readonly',
    'https://www.googleapis.com/auth/forms.body.readonly',
    'https://www.googleapis.com/auth/calendar.readonly',
    'https://www.googleapis.com/auth/directory.readonly',
    'https://www.googleapis.com/auth/drive.activity.readonly'
]

# --- 2. STATE STORAGE (Redis or In-Memory) ---

class StateStorage:
    """Abstract interface for state storage"""
    def get(self, key: str) -> Optional[dict]:
        raise NotImplementedError
    
    def set(self, key: str, value: dict, ttl: int = 600) -> None:
        raise NotImplementedError
    
    def delete(self, key: str) -> None:
        raise NotImplementedError


class InMemoryStorage(StateStorage):
    """Fallback in-memory storage (not suitable for production)"""
    def __init__(self):
        self._data = {}
        self._expiry = {}
    
    def _cleanup(self):
        now = time.time()
        expired = [k for k, exp in self._expiry.items() if exp < now]
        for k in expired:
            self._data.pop(k, None)
            self._expiry.pop(k, None)
    
    def get(self, key: str) -> Optional[dict]:
        self._cleanup()
        if key in self._data and self._expiry.get(key, 0) > time.time():
            return self._data[key]
        return None
    
    def set(self, key: str, value: dict, ttl: int = 600) -> None:
        self._data[key] = value
        self._expiry[key] = time.time() + ttl
    
    def delete(self, key: str) -> None:
        self._data.pop(key, None)
        self._expiry.pop(key, None)


class RedisStorage(StateStorage):
    """Redis-based storage for production"""
    def __init__(self, client):
        self._client = client
        self._prefix = "mcp_oauth:"
    
    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"
    
    def get(self, key: str) -> Optional[dict]:
        try:
            data = self._client.get(self._key(key))
            if data:
                return json.loads(data)
        except Exception as e:
            logger.error(f"Redis GET error: {e}")
        return None
    
    def set(self, key: str, value: dict, ttl: int = 600) -> None:
        try:
            self._client.setex(self._key(key), ttl, json.dumps(value))
        except Exception as e:
            logger.error(f"Redis SET error: {e}")
    
    def delete(self, key: str) -> None:
        try:
            self._client.delete(self._key(key))
        except Exception as e:
            logger.error(f"Redis DELETE error: {e}")


# Initialize storage
def init_storage() -> StateStorage:
    logger.info(f"🔍 Redis config check:")
    logger.info(f"   REDIS_AVAILABLE: {REDIS_AVAILABLE}")
    logger.info(f"   REDIS_URL: {REDIS_URL}")
    logger.info(f"   REDIS_HOST: {REDIS_HOST}")
    logger.info(f"   REDIS_PORT: {REDIS_PORT}")
    
    if REDIS_AVAILABLE and redis and (REDIS_URL or REDIS_HOST):
        try:
            if REDIS_URL:
                # Use URL (supports Upstash, Railway, etc.)
                logger.info(f"   Connecting via REDIS_URL...")
                client = redis.from_url(REDIS_URL, decode_responses=True)
            else:
                # Use host/port/password
                logger.info(f"   Connecting via REDIS_HOST:REDIS_PORT...")
                client = redis.Redis(
                    host=REDIS_HOST,
                    port=REDIS_PORT,
                    password=REDIS_PASSWORD,
                    ssl=REDIS_SSL,
                    decode_responses=True
                )
            # Test connection
            logger.info(f"   Testing connection with ping...")
            client.ping()
            logger.info("✅ Connected to Redis")
            return RedisStorage(client)
        except Exception as e:
            logger.warning(f"⚠️ Redis connection failed: {e}, falling back to in-memory")
    else:
        logger.warning(f"⚠️ Redis not available or not configured:")
        logger.warning(f"   REDIS_AVAILABLE={REDIS_AVAILABLE}, redis={redis is not None}, REDIS_URL={bool(REDIS_URL)}, REDIS_HOST={bool(REDIS_HOST)}")
    
    logger.warning("⚠️ Using in-memory storage (not suitable for production with multiple instances)")
    return InMemoryStorage()


storage = init_storage()

# --- 3. OAUTH PROXY ENDPOINTS ---

async def oauth_well_known(request: Request):
    """OIDC/OAuth discovery endpoint"""
    return JSONResponse({
        "issuer": PUBLIC_URL,
        "authorization_endpoint": f"{PUBLIC_URL}/authorize",
        "token_endpoint": f"{PUBLIC_URL}/token",
        "userinfo_endpoint": f"{PUBLIC_URL}/userinfo",
        "registration_endpoint": f"{PUBLIC_URL}/register",
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"] + SCOPES,
        "code_challenge_methods_supported": ["S256", "plain"],
    })


async def oauth_protected_resource(request: Request):
    """OAuth 2.0 Protected Resource Metadata (RFC 9728)"""
    # Determine which resource path is being requested
    path = request.url.path
    if "/sse" in path:
        resource = f"{PUBLIC_URL}/sse"
    else:
        resource = PUBLIC_URL
    
    return JSONResponse({
        "resource": resource,
        "authorization_servers": [PUBLIC_URL],
        "scopes_supported": ["openid", "email", "profile"] + SCOPES,
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{PUBLIC_URL}/",
    })


async def oauth_authorize(request: Request):
    """
    Step 1: ChatGPT redirects user here
    We store ChatGPT's info and redirect to Google
    """
    params = request.query_params
    chatgpt_state = params.get("state", "")
    chatgpt_redirect_uri = params.get("redirect_uri", "")
    
    logger.info(f"📥 Authorize request from ChatGPT")
    logger.info(f"   State: {chatgpt_state[:20]}..." if chatgpt_state else "   State: None")
    logger.info(f"   Redirect URI: {chatgpt_redirect_uri}")
    
    # Generate our internal state to track this flow
    internal_state = secrets.token_urlsafe(32)
    
    # Store ChatGPT's info so we can redirect back later (TTL: 10 minutes)
    storage.set(f"auth:{internal_state}", {
        "chatgpt_state": chatgpt_state,
        "chatgpt_redirect_uri": chatgpt_redirect_uri,
        "code_challenge": params.get("code_challenge", ""),
        "code_challenge_method": params.get("code_challenge_method", ""),
    }, ttl=600)
    
    # Build Google OAuth URL with OUR redirect URI
    scope_param = " ".join(SCOPES) + " openid email profile"
    
    google_params = {
        "client_id": CLIENT_ID,
        "redirect_uri": f"{PUBLIC_URL}/oauth2callback",  # OUR callback, not ChatGPT's
        "response_type": "code",
        "scope": scope_param,
        "state": internal_state,  # OUR state, not ChatGPT's
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
    }
    
    google_auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(google_params)}"
    logger.info(f"🔄 Redirecting to Google OAuth")
    
    return RedirectResponse(google_auth_url)


async def oauth_callback(request: Request):
    """
    Step 2: Google redirects user here after authorization
    We exchange Google's code for tokens, then redirect back to ChatGPT
    """
    params = request.query_params
    google_code = params.get("code")
    internal_state = params.get("state")
    error = params.get("error")
    
    logger.info(f"📥 Google callback received")
    
    # Handle Google errors
    if error:
        logger.error(f"❌ Google OAuth error: {error}")
        return JSONResponse({"error": error}, status_code=400)
    
    # Validate state and retrieve stored data
    stored = storage.get(f"auth:{internal_state}")
    if not stored:
        logger.error(f"❌ Invalid or expired state")
        return JSONResponse({"error": "Invalid or expired state"}, status_code=400)
    
    # Delete the auth state (one-time use)
    storage.delete(f"auth:{internal_state}")
    
    chatgpt_state = stored["chatgpt_state"]
    chatgpt_redirect_uri = stored["chatgpt_redirect_uri"]
    
    logger.info(f"✅ Valid state, exchanging code with Google")
    
    # Exchange Google's code for tokens
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code": google_code,
                "grant_type": "authorization_code",
                "redirect_uri": f"{PUBLIC_URL}/oauth2callback",  # Must match authorize
            }
        )
        
        if token_response.status_code != 200:
            logger.error(f"❌ Google token exchange failed: {token_response.status_code}")
            logger.error(f"   Response: {token_response.text}")
            return JSONResponse(
                {"error": "Token exchange failed", "details": token_response.text},
                status_code=400
            )
        
        google_tokens = token_response.json()
        logger.info(f"✅ Got tokens from Google")
    
    # Generate OUR authorization code to give to ChatGPT
    our_code = secrets.token_urlsafe(32)
    
    # Store the Google tokens, keyed by our code (TTL: 5 minutes for code exchange)
    storage.set(f"code:{our_code}", {
        "access_token": google_tokens.get("access_token"),
        "refresh_token": google_tokens.get("refresh_token", ""),
        "expires_in": google_tokens.get("expires_in", 3600),
        "token_type": "bearer",
        "id_token": google_tokens.get("id_token", ""),
        "scope": google_tokens.get("scope", ""),
    }, ttl=300)
    
    # Redirect back to ChatGPT with OUR code and THEIR state
    redirect_params = {
        "code": our_code,
        "state": chatgpt_state,
    }
    
    # Handle redirect URI with existing query params
    if "?" in chatgpt_redirect_uri:
        final_url = f"{chatgpt_redirect_uri}&{urlencode(redirect_params)}"
    else:
        final_url = f"{chatgpt_redirect_uri}?{urlencode(redirect_params)}"
    
    logger.info(f"🔄 Redirecting back to ChatGPT")
    logger.info(f"   URL: {chatgpt_redirect_uri[:50]}...")
    
    return RedirectResponse(final_url)


async def oauth_token(request: Request):
    """
    Step 3: ChatGPT exchanges our code for tokens
    """
    # Parse credentials from Authorization header (Basic auth)
    auth_header = request.headers.get("Authorization", "")
    header_client_id = None
    header_client_secret = None
    
    if auth_header.startswith("Basic "):
        try:
            encoded = auth_header.split(" ")[1]
            decoded = base64.b64decode(encoded).decode("utf-8")
            header_client_id, header_client_secret = decoded.split(":", 1)
        except Exception as e:
            logger.warning(f"⚠️ Failed to decode Basic auth: {e}")
    
    # Parse form data
    form = await request.form()
    
    # Get credentials (prefer form, fallback to header)
    req_client_id = form.get("client_id") or header_client_id
    req_client_secret = form.get("client_secret") or header_client_secret
    grant_type = form.get("grant_type")
    code = form.get("code")
    refresh_token_req = form.get("refresh_token")
    
    logger.info(f"📥 Token request received")
    logger.info(f"   Grant type: {grant_type}")
    logger.info(f"   Code: {code[:20]}..." if code else "   Code: None")
    
    # Handle authorization_code grant
    if grant_type == "authorization_code":
        if not code:
            logger.error("❌ Missing code")
            return JSONResponse({"error": "invalid_request", "error_description": "Missing code"}, status_code=400)
        
        # Look up our stored tokens
        stored = storage.get(f"code:{code}")
        
        if not stored:
            logger.error(f"❌ Invalid or expired code")
            return JSONResponse({"error": "invalid_grant", "error_description": "Invalid or expired code"}, status_code=400)
        
        # Delete the code (one-time use)
        storage.delete(f"code:{code}")
        
        logger.info(f"✅ Valid code, returning tokens")
        
        # Return tokens to ChatGPT
        response_data = {
            "access_token": stored["access_token"],
            "token_type": "bearer",  # Must be lowercase
            "expires_in": stored.get("expires_in", 3600),
        }
        
        # CRITICAL: ChatGPT REQUIRES refresh_token or it hides all tools!
        if stored.get("refresh_token"):
            response_data["refresh_token"] = stored["refresh_token"]
            logger.info(f"   ✅ Including refresh_token in response")
        else:
            logger.warning(f"   ⚠️ NO refresh_token available - ChatGPT may hide tools!")
        
        # Include id_token if we have one
        if stored.get("id_token"):
            response_data["id_token"] = stored["id_token"]
        
        logger.info(f"   Response keys: {list(response_data.keys())}")
        
        return JSONResponse(response_data)
    
    # Handle refresh_token grant
    elif grant_type == "refresh_token":
        if not refresh_token_req:
            return JSONResponse({"error": "invalid_request", "error_description": "Missing refresh_token"}, status_code=400)
        
        logger.info(f"🔄 Refreshing token with Google")
        
        # Exchange refresh token with Google
        async with httpx.AsyncClient() as client:
            refresh_response = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "refresh_token": refresh_token_req,
                    "grant_type": "refresh_token",
                }
            )
            
            if refresh_response.status_code != 200:
                logger.error(f"❌ Google refresh failed: {refresh_response.status_code}")
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            
            new_tokens = refresh_response.json()
            logger.info(f"✅ Got refreshed tokens from Google")
            
            return JSONResponse({
                "access_token": new_tokens.get("access_token"),
                "token_type": "bearer",
                "expires_in": new_tokens.get("expires_in", 3600),
                "refresh_token": refresh_token_req,  # Return same refresh token
            })
    
    else:
        logger.error(f"❌ Unsupported grant type: {grant_type}")
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


async def oauth_userinfo(request: Request):
    """Optional: Return user info if ChatGPT requests it"""
    auth_header = request.headers.get("Authorization", "")
    
    if not auth_header.startswith("Bearer "):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    
    token = auth_header.split(" ")[1]
    
    # Validate token with Google and get user info
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if resp.status_code != 200:
            return JSONResponse({"error": "invalid_token"}, status_code=401)
        
        return JSONResponse(resp.json())


# --- 4. SECURITY (Manual Token Verification) ---

async def verify_token_manual(token: str) -> dict | None:
    """Verifies token with Google and returns user info if valid"""
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"access_token": token}
            )
            if resp.status_code != 200:
                return None
            
            token_info = resp.json()
            email = token_info.get("email", "")
            
            if not email.endswith(f"@{ALLOWED_DOMAIN}"):
                logger.warning(f"⚠️ Email domain not allowed: {email}")
                return None
            
            return token_info
        except Exception as e:
            logger.error(f"❌ Token verification error: {e}")
            return None


# --- 5. GOOGLE SERVICES ---

drive_service = sheet_service = docs_service = slides_service = \
forms_service = calendar_service = people_service = activity_service = None

try:
    if os.path.exists(KEY_PATH):
        creds = service_account.Credentials.from_service_account_file(KEY_PATH, scopes=SCOPES)
        drive_service = build('drive', 'v3', credentials=creds)
        sheet_service = build('sheets', 'v4', credentials=creds)
        docs_service = build('docs', 'v1', credentials=creds)
        slides_service = build('slides', 'v1', credentials=creds)
        forms_service = build('forms', 'v1', credentials=creds)
        calendar_service = build('calendar', 'v3', credentials=creds)
        people_service = build('people', 'v1', credentials=creds)
        activity_service = build('driveactivity', 'v2', credentials=creds)
        logger.info("✅ All Google Services Connected.")
except Exception as e:
    logger.error(f"❌ Service Account Auth Failed: {e}")

# --- 6. MCP SERVER & ALL TOOLS ---

mcp_server = Server("google-workspace-mcp")

# Tool annotations for ChatGPT compatibility
if HAS_TOOL_ANNOTATIONS:
    READ_ONLY_ANNOTATIONS = ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False
    )
    logger.info("✅ Using ToolAnnotations class")
else:
    # Fallback to dict for older MCP versions
    READ_ONLY_ANNOTATIONS = {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
    logger.info("⚠️ ToolAnnotations not available, using dict fallback")

def create_tool(name: str, description: str, properties: dict, required: list = None):
    """Helper to create tools with or without annotations support"""
    tool_kwargs = {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required or []
        }
    }
    # Only add annotations if we have the proper type
    if HAS_TOOL_ANNOTATIONS:
        tool_kwargs["annotations"] = READ_ONLY_ANNOTATIONS
    return Tool(**tool_kwargs)

TOOLS_SCHEMA = [
    create_tool(
        name="search_files",
        description="Find files by name across Google Drive. Use this when the user wants to search for documents, spreadsheets, or other files.",
        properties={"query": {"type": "string", "description": "Search query for file names"}},
        required=["query"]
    ),
    create_tool(
        name="list_folder",
        description="List contents of a specific Google Drive folder. Use this when the user wants to see what files are in a folder.",
        properties={"folder_id": {"type": "string", "description": "The ID of the folder to list"}},
        required=["folder_id"]
    ),
    create_tool(
        name="read_file",
        description="Read content from a Google Doc, PDF, Excel file, or text file. Use this when the user wants to see the contents of a file.",
        properties={"file_id": {"type": "string", "description": "The ID of the file to read"}},
        required=["file_id"]
    ),
    create_tool(
        name="read_sheet_values",
        description="Read specific cell range from a Google Sheet. Use this when the user wants to see spreadsheet data.",
        properties={
            "spreadsheet_id": {"type": "string", "description": "The ID of the spreadsheet"},
            "range": {"type": "string", "description": "The A1 notation range to read (e.g. Sheet1!A1:B10)"}
        },
        required=["spreadsheet_id"]
    ),
    create_tool(
        name="read_doc_structure",
        description="Get full document structure including tables and lists from a Google Doc.",
        properties={"document_id": {"type": "string", "description": "The ID of the Google Doc"}},
        required=["document_id"]
    ),
    create_tool(
        name="read_slides",
        description="Read text from all slides in a Google Slides presentation.",
        properties={"presentation_id": {"type": "string", "description": "The ID of the Google Slides presentation"}},
        required=["presentation_id"]
    ),
    create_tool(
        name="list_events",
        description="List upcoming calendar events from Google Calendar. Use this when the user asks about their schedule or meetings.",
        properties={
            "calendar_id": {"type": "string", "description": "Calendar ID (use 'primary' for main calendar)"},
            "limit": {"type": "integer", "description": "Maximum number of events to return"}
        },
        required=[]
    ),
    create_tool(
        name="find_person",
        description="Search company directory for a person by name or email.",
        properties={"query": {"type": "string", "description": "Name or email to search for"}},
        required=["query"]
    ),
    create_tool(
        name="list_file_history",
        description="Get revision history of a Google Drive file.",
        properties={"file_id": {"type": "string", "description": "The ID of the file"}},
        required=["file_id"]
    ),
    create_tool(
        name="read_old_version",
        description="Read content from a specific revision of a file.",
        properties={
            "file_id": {"type": "string", "description": "The ID of the file"},
            "revision_id": {"type": "string", "description": "The revision ID to read"}
        },
        required=["file_id", "revision_id"]
    ),
    create_tool(
        name="get_file_activity",
        description="See move, rename, and edit activity logs for a file.",
        properties={"file_id": {"type": "string", "description": "The ID of the file"}},
        required=["file_id"]
    ),
]

@mcp_server.list_tools()
async def handle_list_tools() -> list[Tool]:
    logger.info(f"📋 Tools list requested, returning {len(TOOLS_SCHEMA)} tools")
    return TOOLS_SCHEMA

@mcp_server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[TextContent]:
    args = arguments or {}
    try:
        if name == "search_files":
            q = f"name contains '{args['query']}' and trashed = false"
            res = drive_service.files().list(q=q, fields="files(id, name, mimeType)").execute()
            return [TextContent(type="text", text=json.dumps(res.get('files',[]), indent=2))]
        
        elif name == "list_folder":
            q = f"'{args['folder_id']}' in parents and trashed = false"
            res = drive_service.files().list(q=q, fields="files(id, name)").execute()
            return [TextContent(type="text", text=json.dumps(res.get('files',[]), indent=2))]

        elif name == "read_file":
            fid = args['file_id']
            meta = drive_service.files().get(fileId=fid).execute()
            mime = meta.get('mimeType','')
            if "google-apps.document" in mime:
                content = drive_service.files().export_media(fileId=fid, mimeType='text/plain').execute().decode('utf-8')
            elif "pdf" in mime:
                raw = drive_service.files().get_media(fileId=fid).execute()
                content = "\n".join([p.extract_text() for p in PdfReader(io.BytesIO(raw)).pages])
            elif "spreadsheetml.sheet" in mime:
                raw = drive_service.files().get_media(fileId=fid).execute()
                wb = openpyxl.load_workbook(io.BytesIO(raw), data_only=True)
                content = "\n".join([" | ".join([str(c) for c in r if c]) for s in wb.sheetnames for r in wb[s].iter_rows(max_row=20, values_only=True)])
            else:
                content = drive_service.files().get_media(fileId=fid).execute().decode('utf-8')
            return [TextContent(type="text", text=content)]

        elif name == "read_sheet_values":
            res = sheet_service.spreadsheets().values().get(spreadsheetId=args['spreadsheet_id'], range=args.get('range','A1:Z100')).execute()
            return [TextContent(type="text", text=json.dumps(res.get('values',[]), indent=2))]

        elif name == "read_doc_structure":
            doc = docs_service.documents().get(documentId=args['document_id']).execute()
            out = []
            for e in doc.get('body').get('content', []):
                if 'paragraph' in e:
                    out.append("".join([t['textRun']['content'] for t in e['paragraph']['elements'] if 'textRun' in t]))
            return [TextContent(type="text", text="\n".join(out))]

        elif name == "read_slides":
            deck = slides_service.presentations().get(presentationId=args['presentation_id']).execute()
            out = ["Slide Data:"]
            for s in deck.get('slides', []):
                for e in s.get('pageElements', []):
                    if 'shape' in e and 'text' in e['shape']:
                        out.append("".join([t['textRun']['content'] for t in e['shape']['text'].get('textElements', []) if 'textRun' in t]))
            return [TextContent(type="text", text="\n".join(out))]

        elif name == "list_events":
            now = datetime.datetime.utcnow().isoformat() + 'Z'
            evs = calendar_service.events().list(calendarId=args.get('calendar_id','primary'), timeMin=now, maxResults=args.get('limit',10)).execute()
            txt = "\n".join([f"{e['start'].get('dateTime', e['start'].get('date'))}: {e['summary']}" for e in evs.get('items',[])])
            return [TextContent(type="text", text=txt or "No events found.")]

        elif name == "find_person":
            res = people_service.people().searchDirectoryPeople(query=args['query'], readMask="names,emailAddresses", sources=["DIRECTORY_SOURCE_TYPE_DOMAIN_CONTACT"]).execute()
            txt = "\n".join([f"{p['names'][0]['displayName']} <{p['emailAddresses'][0]['value']}>" for p in res.get('people', [])])
            return [TextContent(type="text", text=txt or "Person not found.")]

        elif name == "list_file_history":
            revs = drive_service.revisions().list(fileId=args['file_id'], fields="revisions(id, modifiedTime, lastModifyingUser)").execute().get('revisions', [])
            txt = "\n".join([f"ID: {r['id']} | Time: {r['modifiedTime']} | User: {r.get('lastModifyingUser',{}).get('displayName')}" for r in revs])
            return [TextContent(type="text", text=txt)]

        elif name == "read_old_version":
            txt = drive_service.revisions().get_media(fileId=args['file_id'], revisionId=args['revision_id']).execute().decode('utf-8')
            return [TextContent(type="text", text=txt)]

        elif name == "get_file_activity":
            res = activity_service.activity().query(body={'item_name':f'items/{args["file_id"]}','pageSize':10}).execute().get('activities', [])
            txt = "\n".join([f"{a['timestamp']}: {list(a['primaryActionDetail'].keys())[0]}" for a in res])
            return [TextContent(type="text", text=txt or "No recent activity.")]

    except Exception as e:
        logger.error(f"Error in {name}: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]
    
    return [TextContent(type="text", text="Tool not recognized.")]


# --- 7. SSE/MCP HANDLERS ---

sse_transport = SseServerTransport("/messages")

class SSEApp:
    async def __call__(self, scope, receive, send):
        headers = dict(scope.get("headers", []))
        auth = headers.get(b"authorization", b"").decode("utf-8")
        
        is_valid = False
        user_email = None
        
        # Debug: Log what we received
        if auth:
            logger.info(f"🔍 SSE request with auth header: {auth[:50]}...")
        else:
            logger.info(f"🔍 SSE request WITHOUT auth header")
            # Log all headers for debugging
            for key, value in headers.items():
                logger.debug(f"   Header: {key.decode()}: {value.decode()[:50]}")
        
        if auth.startswith("Bearer "):
            token = auth.split(" ")[1]
            logger.info(f"🔍 Validating token: {token[:20]}...")
            token_info = await verify_token_manual(token)
            if token_info:
                is_valid = True
                user_email = token_info.get('email')
                logger.info(f"✅ Secure SSE Access: {user_email}")
            else:
                logger.warning(f"❌ Token validation failed")

        if not is_valid:
            logger.info(f"🔐 SSE request without valid token - sending auth challenge")
            
            # Return 401 with WWW-Authenticate header to trigger OAuth flow
            www_auth = f'Bearer resource="{PUBLIC_URL}/sse"'
            
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", www_auth.encode("utf-8")),
                ],
            })
            await send({
                "type": "http.response.body", 
                "body": json.dumps({
                    "error": "unauthorized",
                    "error_description": "Bearer token required"
                }).encode("utf-8")
            })
            return

        async with sse_transport.connect_sse(scope, receive, send) as streams:
            await mcp_server.run(
                streams[0], 
                streams[1], 
                mcp_server.create_initialization_options()
            )

class MessageApp:
    async def __call__(self, scope, receive, send):
        await sse_transport.handle_post_message(scope, receive, send)


# --- 8. UTILITY ENDPOINTS ---

async def homepage(request: Request):
    return JSONResponse({
        "status": "active",
        "mcp": "ready",
        "oauth": {
            "authorization_endpoint": f"{PUBLIC_URL}/authorize",
            "token_endpoint": f"{PUBLIC_URL}/token",
        }
    })

async def health_check(request: Request):
    return JSONResponse({"status": "healthy", "timestamp": datetime.datetime.utcnow().isoformat()})


# --- 9. ROUTING ---

routes = [
    # Health & Status
    Route("/", endpoint=homepage),
    Route("/health", endpoint=health_check),
    
    # OAuth 2.0 Protected Resource Metadata (RFC 9728) - ChatGPT checks these
    Route("/.well-known/oauth-protected-resource", endpoint=oauth_protected_resource),
    Route("/.well-known/oauth-protected-resource/sse", endpoint=oauth_protected_resource),
    Route("/sse/.well-known/oauth-protected-resource", endpoint=oauth_protected_resource),
    
    # OAuth 2.0 / OIDC Discovery - root level
    Route("/.well-known/oauth-authorization-server", endpoint=oauth_well_known),
    Route("/.well-known/openid-configuration", endpoint=oauth_well_known),
    
    # OAuth 2.0 / OIDC Discovery - with /sse suffix (ChatGPT tries this pattern)
    Route("/.well-known/oauth-authorization-server/sse", endpoint=oauth_well_known),
    Route("/.well-known/openid-configuration/sse", endpoint=oauth_well_known),
    
    # OAuth 2.0 / OIDC Discovery - under /sse prefix (ChatGPT also tries this)
    Route("/sse/.well-known/oauth-authorization-server", endpoint=oauth_well_known),
    Route("/sse/.well-known/openid-configuration", endpoint=oauth_well_known),
    
    # OAuth Flow Endpoints
    Route("/authorize", endpoint=oauth_authorize, methods=["GET"]),
    Route("/oauth2callback", endpoint=oauth_callback, methods=["GET"]),  # Google callback
    Route("/token", endpoint=oauth_token, methods=["POST"]),
    Route("/userinfo", endpoint=oauth_userinfo, methods=["GET"]),
    
    # MCP/SSE Endpoints
    Route("/sse", endpoint=SSEApp(), methods=["GET", "POST"]),
    Route("/messages", endpoint=MessageApp(), methods=["POST"]),
]

app = Starlette(routes=routes)

if __name__ == "__main__":
    import uvicorn
    
    if not PUBLIC_URL:
        logger.error("❌ PUBLIC_URL environment variable is required!")
        sys.exit(1)
    if not CLIENT_ID or not CLIENT_SECRET:
        logger.error("❌ CLIENT_ID and CLIENT_SECRET environment variables are required!")
        sys.exit(1)
    
    logger.info(f"🚀 Starting server with PUBLIC_URL: {PUBLIC_URL}")
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))