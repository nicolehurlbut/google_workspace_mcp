"""
secure_app.py - Google Workspace MCP Server
Uses Standard MCP SDK + Starlette (NOT FastMCP)

Architecture:
- Starlette for full HTTP routing control
- SseServerTransport for MCP communication
- Manual OAuth proxy for ChatGPT/Claude compatibility
- Token validation middleware for @singlefile.io domain restriction
"""

import os
import sys
import logging
import json
import io
import datetime
import time
import secrets
import httpx
from urllib.parse import urlencode

# Standard MCP SDK (NOT FastMCP)
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent

# Starlette for routing
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

# Google APIs
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload

# File handlers
from pypdf import PdfReader
import openpyxl

# =============================================================================
# 1. CONFIGURATION
# =============================================================================

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("google_mcp")

# Environment variables
KEY_PATH = os.environ.get("SERVICE_ACCOUNT_KEY_PATH", "/app/service-account.json")
ALLOWED_DOMAIN = os.environ.get("ALLOWED_DOMAIN", "singlefile.io")
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")

# Google API Scopes
SCOPES = [
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/spreadsheets.readonly',
    'https://www.googleapis.com/auth/documents.readonly',
    'https://www.googleapis.com/auth/presentations.readonly',
    'https://www.googleapis.com/auth/forms.body.readonly',
    'https://www.googleapis.com/auth/calendar.readonly',
    'https://www.googleapis.com/auth/directory.readonly',
    'https://www.googleapis.com/auth/drive.activity.readonly',
]

# =============================================================================
# 2. OAUTH STATE STORAGE (In-memory - use Redis for production)
# =============================================================================

auth_states = {}  # {state_key: {data, expires}}

def cleanup_expired_states():
    """Remove expired OAuth states"""
    now = time.time()
    expired = [k for k, v in auth_states.items() if v.get("expires", 0) < now]
    for k in expired:
        auth_states.pop(k, None)

# =============================================================================
# 3. TOKEN VALIDATION (Domain Restriction)
# =============================================================================

async def verify_google_token(token: str) -> dict | None:
    """
    Verify a Google access token and check domain restriction.
    Returns token info if valid, None otherwise.
    """
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://oauth2.googleapis.com/tokeninfo?access_token={token}"
            )
            if resp.status_code != 200:
                logger.warning(f"Token validation failed: {resp.status_code}")
                return None
            
            info = resp.json()
            email = info.get("email", "")
            
            # Domain restriction check
            if not email.endswith(f"@{ALLOWED_DOMAIN}"):
                logger.warning(f"❌ Domain rejected: {email}")
                return None
            
            logger.info(f"✅ Token valid for: {email}")
            return info
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return None

# =============================================================================
# 4. GOOGLE SERVICE BUILDERS
# =============================================================================

def get_service_account_credentials(user_email: str):
    """Get delegated credentials for a user"""
    creds = service_account.Credentials.from_service_account_file(KEY_PATH, scopes=SCOPES)
    return creds.with_subject(user_email)

def build_drive_service(user_email: str):
    return build('drive', 'v3', credentials=get_service_account_credentials(user_email))

def build_sheets_service(user_email: str):
    return build('sheets', 'v4', credentials=get_service_account_credentials(user_email))

def build_docs_service(user_email: str):
    return build('docs', 'v1', credentials=get_service_account_credentials(user_email))

def build_slides_service(user_email: str):
    return build('slides', 'v1', credentials=get_service_account_credentials(user_email))

def build_calendar_service(user_email: str):
    return build('calendar', 'v3', credentials=get_service_account_credentials(user_email))

def build_people_service(user_email: str):
    return build('people', 'v1', credentials=get_service_account_credentials(user_email))

def build_activity_service(user_email: str):
    return build('driveactivity', 'v2', credentials=get_service_account_credentials(user_email))

# =============================================================================
# 5. FILE CONTENT EXTRACTION
# =============================================================================

def extract_file_content(drive_service, file_id: str, mime_type: str) -> str:
    """Extract text content from various file types"""
    try:
        # Google Workspace files - export as text
        if mime_type == 'application/vnd.google-apps.document':
            content = drive_service.files().export(fileId=file_id, mimeType='text/plain').execute()
            return content.decode('utf-8') if isinstance(content, bytes) else content
        
        elif mime_type == 'application/vnd.google-apps.spreadsheet':
            content = drive_service.files().export(fileId=file_id, mimeType='text/csv').execute()
            return content.decode('utf-8') if isinstance(content, bytes) else content
        
        elif mime_type == 'application/vnd.google-apps.presentation':
            content = drive_service.files().export(fileId=file_id, mimeType='text/plain').execute()
            return content.decode('utf-8') if isinstance(content, bytes) else content
        
        # Binary files - download and parse
        else:
            request = drive_service.files().get_media(fileId=file_id)
            buffer = io.BytesIO()
            downloader = MediaIoBaseDownload(buffer, request)
            done = False
            while not done:
                _, done = downloader.next_chunk()
            buffer.seek(0)
            
            if mime_type == 'application/pdf':
                reader = PdfReader(buffer)
                return "\n".join(page.extract_text() or "" for page in reader.pages)
            
            elif mime_type in ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/vnd.ms-excel']:
                wb = openpyxl.load_workbook(buffer, data_only=True)
                lines = []
                for sheet in wb.sheetnames:
                    ws = wb[sheet]
                    for row in ws.iter_rows(values_only=True):
                        lines.append(",".join(str(c) if c else "" for c in row))
                return "\n".join(lines)
            
            elif mime_type.startswith('text/'):
                return buffer.read().decode('utf-8', errors='ignore')
            
            else:
                return f"[Cannot extract text from {mime_type}]"
    
    except Exception as e:
        logger.error(f"Content extraction error: {e}")
        return f"[Error extracting content: {e}]"

# =============================================================================
# 6. MCP SERVER SETUP
# =============================================================================

mcp_server = Server("google-workspace-mcp")

@mcp_server.list_tools()
async def list_tools():
    """Define available MCP tools"""
    return [
        Tool(name="search_drive", description="Search Google Drive files", inputSchema={
            "type": "object",
            "properties": {"query": {"type": "string", "description": "Search query"}},
            "required": ["query"]
        }),
        Tool(name="read_file", description="Read content from a Drive file", inputSchema={
            "type": "object",
            "properties": {"file_id": {"type": "string", "description": "File ID"}},
            "required": ["file_id"]
        }),
        Tool(name="list_folder", description="List files in a Drive folder", inputSchema={
            "type": "object",
            "properties": {
                "folder_id": {"type": "string", "description": "Folder ID (default: root)", "default": "root"}
            }
        }),
        Tool(name="read_spreadsheet", description="Read a Google Sheet", inputSchema={
            "type": "object",
            "properties": {
                "spreadsheet_id": {"type": "string"},
                "range": {"type": "string", "default": "A1:Z1000"}
            },
            "required": ["spreadsheet_id"]
        }),
        Tool(name="read_document", description="Read a Google Doc", inputSchema={
            "type": "object",
            "properties": {"document_id": {"type": "string"}},
            "required": ["document_id"]
        }),
        Tool(name="read_presentation", description="Read a Google Slides presentation", inputSchema={
            "type": "object",
            "properties": {"presentation_id": {"type": "string"}},
            "required": ["presentation_id"]
        }),
        Tool(name="list_calendars", description="List user's calendars", inputSchema={
            "type": "object", "properties": {}
        }),
        Tool(name="list_events", description="List calendar events", inputSchema={
            "type": "object",
            "properties": {
                "calendar_id": {"type": "string", "default": "primary"},
                "max_results": {"type": "integer", "default": 10}
            }
        }),
        Tool(name="find_person", description="Search company directory", inputSchema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"]
        }),
        Tool(name="list_file_history", description="Get file revision history", inputSchema={
            "type": "object",
            "properties": {"file_id": {"type": "string"}},
            "required": ["file_id"]
        }),
        Tool(name="get_file_activity", description="Get recent activity on a file", inputSchema={
            "type": "object",
            "properties": {"file_id": {"type": "string"}},
            "required": ["file_id"]
        }),
    ]

@mcp_server.call_tool()
async def call_tool(name: str, arguments: dict):
    """Execute MCP tool calls"""
    # Default user for service account delegation
    # In production, extract from the validated token
    user_email = f"admin@{ALLOWED_DOMAIN}"
    args = arguments or {}
    
    try:
        # Build services as needed
        drive = build_drive_service(user_email)
        
        if name == "search_drive":
            results = drive.files().list(
                q=f"fullText contains '{args['query']}'",
                fields="files(id, name, mimeType, modifiedTime, webViewLink)",
                pageSize=20
            ).execute().get('files', [])
            
            if not results:
                return [TextContent(type="text", text="No files found.")]
            
            txt = "\n".join([
                f"• {f['name']} ({f['mimeType']})\n  ID: {f['id']}\n  Modified: {f.get('modifiedTime', 'N/A')}\n  Link: {f.get('webViewLink', 'N/A')}"
                for f in results
            ])
            return [TextContent(type="text", text=txt)]
        
        elif name == "read_file":
            meta = drive.files().get(fileId=args['file_id'], fields="name,mimeType").execute()
            content = extract_file_content(drive, args['file_id'], meta['mimeType'])
            return [TextContent(type="text", text=f"# {meta['name']}\n\n{content}")]
        
        elif name == "list_folder":
            folder_id = args.get('folder_id', 'root')
            results = drive.files().list(
                q=f"'{folder_id}' in parents and trashed=false",
                fields="files(id, name, mimeType)",
                pageSize=50
            ).execute().get('files', [])
            
            txt = "\n".join([f"• {f['name']} ({f['mimeType']}) - {f['id']}" for f in results])
            return [TextContent(type="text", text=txt or "Folder is empty.")]
        
        elif name == "read_spreadsheet":
            sheets = build_sheets_service(user_email)
            range_name = args.get('range', 'A1:Z1000')
            result = sheets.spreadsheets().values().get(
                spreadsheetId=args['spreadsheet_id'],
                range=range_name
            ).execute()
            
            values = result.get('values', [])
            txt = "\n".join([",".join(str(c) for c in row) for row in values])
            return [TextContent(type="text", text=txt or "Spreadsheet is empty.")]
        
        elif name == "read_document":
            docs = build_docs_service(user_email)
            doc = docs.documents().get(documentId=args['document_id']).execute()
            
            # Extract text from document structure
            content = []
            for elem in doc.get('body', {}).get('content', []):
                if 'paragraph' in elem:
                    for el in elem['paragraph'].get('elements', []):
                        if 'textRun' in el:
                            content.append(el['textRun'].get('content', ''))
            
            return [TextContent(type="text", text=f"# {doc.get('title', 'Untitled')}\n\n{''.join(content)}")]
        
        elif name == "read_presentation":
            slides = build_slides_service(user_email)
            pres = slides.presentations().get(presentationId=args['presentation_id']).execute()
            
            content = [f"# {pres.get('title', 'Untitled Presentation')}"]
            for i, slide in enumerate(pres.get('slides', []), 1):
                content.append(f"\n## Slide {i}")
                for elem in slide.get('pageElements', []):
                    if 'shape' in elem and 'text' in elem['shape']:
                        for te in elem['shape']['text'].get('textElements', []):
                            if 'textRun' in te:
                                content.append(te['textRun'].get('content', '').strip())
            
            return [TextContent(type="text", text="\n".join(content))]
        
        elif name == "list_calendars":
            cal = build_calendar_service(user_email)
            calendars = cal.calendarList().list().execute().get('items', [])
            txt = "\n".join([f"• {c['summary']} (ID: {c['id']})" for c in calendars])
            return [TextContent(type="text", text=txt)]
        
        elif name == "list_events":
            cal = build_calendar_service(user_email)
            calendar_id = args.get('calendar_id', 'primary')
            max_results = args.get('max_results', 10)
            
            now = datetime.datetime.utcnow().isoformat() + 'Z'
            events = cal.events().list(
                calendarId=calendar_id,
                timeMin=now,
                maxResults=max_results,
                singleEvents=True,
                orderBy='startTime'
            ).execute().get('items', [])
            
            lines = []
            for e in events:
                start = e['start'].get('dateTime', e['start'].get('date'))
                lines.append(f"• {e['summary']} - {start}")
            
            return [TextContent(type="text", text="\n".join(lines) or "No upcoming events.")]
        
        elif name == "find_person":
            people = build_people_service(user_email)
            results = people.people().searchDirectoryPeople(
                query=args['query'],
                readMask="names,emailAddresses",
                sources=["DIRECTORY_SOURCE_TYPE_DOMAIN_CONTACT"]
            ).execute()
            
            persons = results.get('people', [])
            txt = "\n".join([
                f"• {p['names'][0]['displayName']} <{p['emailAddresses'][0]['value']}>"
                for p in persons if p.get('names') and p.get('emailAddresses')
            ])
            return [TextContent(type="text", text=txt or "No people found.")]
        
        elif name == "list_file_history":
            revisions = drive.revisions().list(
                fileId=args['file_id'],
                fields="revisions(id,modifiedTime,lastModifyingUser)"
            ).execute().get('revisions', [])
            
            lines = []
            for r in revisions:
                user = r.get('lastModifyingUser', {}).get('displayName', 'Unknown')
                lines.append(f"• {r['modifiedTime']} by {user} (rev: {r['id']})")
            
            return [TextContent(type="text", text="\n".join(lines) or "No revision history.")]
        
        elif name == "get_file_activity":
            activity = build_activity_service(user_email)
            results = activity.activity().query(
                body={'itemName': f"items/{args['file_id']}", 'pageSize': 10}
            ).execute().get('activities', [])
            
            lines = []
            for a in results:
                action = list(a.get('primaryActionDetail', {}).keys())[0] if a.get('primaryActionDetail') else 'unknown'
                lines.append(f"• {a.get('timestamp', 'N/A')}: {action}")
            
            return [TextContent(type="text", text="\n".join(lines) or "No recent activity.")]
        
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
    
    except Exception as e:
        logger.error(f"Tool error [{name}]: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]

# =============================================================================
# 7. SSE/MCP TRANSPORT HANDLERS
# =============================================================================

sse_transport = SseServerTransport("/mcp/messages")

class SSEApp:
    """
    SSE endpoint with token validation.
    This is where we intercept and validate tokens BEFORE the MCP stream starts.
    """
    async def __call__(self, scope, receive, send):
        # Extract Authorization header
        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode("utf-8")
        
        logger.info(f"🔍 SSE request - Auth header present: {bool(auth_header)}")
        if auth_header:
            logger.info(f"🔍 Auth header starts with 'Bearer ': {auth_header.startswith('Bearer ')}")
            if auth_header.startswith("Bearer "):
                token_preview = auth_header.split(" ", 1)[1][:20]
                logger.info(f"🔍 Token preview: {token_preview}...")
        
        # Validate token
        is_valid = False
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            token_info = await verify_google_token(token)
            if token_info:
                is_valid = True
                logger.info(f"✅ SSE connection authorized: {token_info.get('email')}")
            else:
                logger.warning(f"❌ Token validation returned None")
        else:
            logger.warning(f"❌ No Bearer token in auth header: '{auth_header[:50] if auth_header else 'empty'}'")
        
        if not is_valid:
            logger.warning("❌ SSE connection rejected: invalid token")
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({
                "type": "http.response.body",
                "body": b'{"error": "Unauthorized - invalid token or domain not allowed"}'
            })
            return
        
        # Token valid - proceed with MCP connection
        async with sse_transport.connect_sse(scope, receive, send) as streams:
            await mcp_server.run(
                streams[0],
                streams[1],
                mcp_server.create_initialization_options()
            )

class MessageApp:
    """Handle POST messages for MCP transport"""
    async def __call__(self, scope, receive, send):
        await sse_transport.handle_post_message(scope, receive, send)

# =============================================================================
# 8. OAUTH PROXY ENDPOINTS
# =============================================================================

async def oauth_well_known(request: Request):
    """OAuth/OIDC discovery endpoint"""
    return JSONResponse({
        "issuer": PUBLIC_URL,
        "authorization_endpoint": f"{PUBLIC_URL}/authorize",
        "token_endpoint": f"{PUBLIC_URL}/token",
        "userinfo_endpoint": f"{PUBLIC_URL}/userinfo",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["S256"],
    })

async def oauth_protected_resource(request: Request):
    """OAuth 2.0 Protected Resource Metadata (RFC 9728)"""
    return JSONResponse({
        "resource": PUBLIC_URL,
        "authorization_servers": [PUBLIC_URL],
        "scopes_supported": ["openid", "email", "profile"],
        "bearer_methods_supported": ["header"],
    })

async def oauth_authorize(request: Request):
    """
    Step 1: ChatGPT/Claude redirects user here.
    We store their state and redirect to Google.
    """
    cleanup_expired_states()
    
    params = request.query_params
    chatgpt_state = params.get("state", "")
    chatgpt_redirect = params.get("redirect_uri", "")
    
    logger.info(f"📥 OAuth authorize request - state: {chatgpt_state[:20]}...")
    
    # Generate our internal state to track this flow
    internal_state = secrets.token_urlsafe(32)
    auth_states[internal_state] = {
        "chatgpt_state": chatgpt_state,
        "chatgpt_redirect_uri": chatgpt_redirect,
        "expires": time.time() + 600  # 10 min expiry
    }
    
    # Build Google OAuth URL
    google_params = {
        "client_id": CLIENT_ID,
        "redirect_uri": f"{PUBLIC_URL}/oauth2callback",
        "response_type": "code",
        "scope": "openid email profile " + " ".join(SCOPES),
        "state": internal_state,
        "access_type": "offline",
        "prompt": "consent",
        "hd": ALLOWED_DOMAIN,  # Restrict to domain
    }
    
    google_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(google_params)}"
    logger.info(f"🔄 Redirecting to Google OAuth")
    return RedirectResponse(google_url)

async def oauth_callback(request: Request):
    """
    Step 2: Google redirects user back here.
    We exchange the code with Google, then redirect to ChatGPT/Claude.
    """
    params = request.query_params
    code = params.get("code")
    internal_state = params.get("state")
    error = params.get("error")
    
    if error:
        logger.error(f"❌ Google OAuth error: {error}")
        return JSONResponse({"error": error}, status_code=400)
    
    # Retrieve stored ChatGPT info
    stored = auth_states.pop(internal_state, None)
    if not stored:
        logger.error("❌ Invalid or expired state")
        return JSONResponse({"error": "Invalid or expired state"}, status_code=400)
    
    logger.info(f"📥 Google callback received, exchanging code...")
    
    # Exchange code with Google
    async with httpx.AsyncClient() as client:
        resp = await client.post("https://oauth2.googleapis.com/token", data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": f"{PUBLIC_URL}/oauth2callback"
        })
        
        if resp.status_code != 200:
            logger.error(f"❌ Google token exchange failed: {resp.status_code} - {resp.text}")
            return JSONResponse({"error": "Token exchange failed"}, status_code=400)
        
        token_data = resp.json()
        logger.info(f"✅ Got tokens from Google - keys: {list(token_data.keys())}")
        logger.info(f"   Has refresh_token: {'refresh_token' in token_data}")
    
    # Store tokens with a new code for ChatGPT/Claude
    proxy_code = secrets.token_urlsafe(32)
    auth_states[proxy_code] = {
        "tokens": token_data,
        "expires": time.time() + 300  # 5 min expiry
    }
    
    # Redirect back to ChatGPT/Claude with OUR code
    callback_url = stored["chatgpt_redirect_uri"]
    redirect_url = f"{callback_url}?code={proxy_code}&state={stored['chatgpt_state']}"
    
    logger.info(f"🔄 Redirecting back to client")
    return RedirectResponse(redirect_url)

async def oauth_token(request: Request):
    """
    Step 3: ChatGPT/Claude exchanges our code for tokens.
    """
    form = await request.form()
    grant_type = form.get("grant_type")
    
    logger.info(f"📥 Token request - grant_type: {grant_type}")
    
    if grant_type == "authorization_code":
        code = form.get("code")
        stored = auth_states.pop(code, None)
        
        if not stored or stored.get("expires", 0) < time.time():
            logger.error("❌ Invalid or expired code")
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        
        token_data = stored["tokens"]
        logger.info(f"✅ Returning tokens - has refresh_token: {'refresh_token' in token_data}")
        logger.info(f"   refresh_token value: {token_data.get('refresh_token', 'MISSING')[:20] if token_data.get('refresh_token') else 'MISSING'}...")
        
        return JSONResponse({
            "access_token": token_data["access_token"],
            "token_type": "bearer",  # lowercase required!
            "expires_in": token_data.get("expires_in", 3600),
            "refresh_token": token_data.get("refresh_token", ""),
            "scope": token_data.get("scope", ""),
        })
    
    elif grant_type == "refresh_token":
        refresh_token = form.get("refresh_token")
        
        async with httpx.AsyncClient() as client:
            resp = await client.post("https://oauth2.googleapis.com/token", data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token"
            })
            
            if resp.status_code != 200:
                logger.error(f"❌ Refresh token failed: {resp.status_code}")
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            
            token_data = resp.json()
            logger.info("✅ Returning refreshed tokens")
            
            return JSONResponse({
                "access_token": token_data["access_token"],
                "token_type": "bearer",
                "expires_in": token_data.get("expires_in", 3600),
                "refresh_token": token_data.get("refresh_token", refresh_token),
                "scope": token_data.get("scope", ""),
            })
    
    else:
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

async def oauth_userinfo(request: Request):
    """Return user info from token"""
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    
    token = auth_header.split(" ", 1)[1]
    token_info = await verify_google_token(token)
    
    if not token_info:
        return JSONResponse({"error": "invalid_token"}, status_code=401)
    
    return JSONResponse({
        "sub": token_info.get("sub", ""),
        "email": token_info.get("email", ""),
        "email_verified": token_info.get("email_verified", False),
    })

# =============================================================================
# 9. UTILITY ENDPOINTS
# =============================================================================

async def homepage(request: Request):
    """Info endpoint - moved to /info since / is now SSE"""
    return JSONResponse({
        "service": "Google Workspace MCP Server",
        "status": "active",
        "architecture": "Standard MCP SDK + Starlette",
        "oauth": {
            "authorization_endpoint": f"{PUBLIC_URL}/authorize",
            "token_endpoint": f"{PUBLIC_URL}/token",
        },
        "mcp": {
            "sse_endpoint": f"{PUBLIC_URL}/",
            "messages_endpoint": f"{PUBLIC_URL}/mcp/messages",
        }
    })

async def health_check(request: Request):
    return JSONResponse({
        "status": "healthy",
        "timestamp": datetime.datetime.utcnow().isoformat()
    })

# =============================================================================
# 10. STARLETTE APP & ROUTING
# =============================================================================

routes = [
    # MCP/SSE Endpoints - both root and /sse for compatibility
    Route("/", endpoint=SSEApp()),
    Route("/sse", endpoint=SSEApp()),
    Route("/mcp/messages", endpoint=MessageApp(), methods=["POST"]),
    
    # Health & Info
    Route("/info", endpoint=homepage),
    Route("/health", endpoint=health_check),
    
    # OAuth Discovery (multiple paths for compatibility)
    Route("/.well-known/oauth-authorization-server", endpoint=oauth_well_known),
    Route("/.well-known/oauth-authorization-server/sse", endpoint=oauth_well_known),
    Route("/.well-known/oauth-authorization-server/mcp", endpoint=oauth_well_known),
    Route("/.well-known/openid-configuration", endpoint=oauth_well_known),
    Route("/.well-known/openid-configuration/sse", endpoint=oauth_well_known),
    Route("/.well-known/oauth-protected-resource", endpoint=oauth_protected_resource),
    Route("/.well-known/oauth-protected-resource/sse", endpoint=oauth_protected_resource),
    
    # OAuth Flow
    Route("/authorize", endpoint=oauth_authorize, methods=["GET"]),
    Route("/oauth2callback", endpoint=oauth_callback, methods=["GET"]),
    Route("/token", endpoint=oauth_token, methods=["POST"]),
    Route("/userinfo", endpoint=oauth_userinfo, methods=["GET"]),
]

app = Starlette(routes=routes)

# Log registered routes on startup
@app.on_event("startup")
async def startup_event():
    logger.info("📋 Registered routes:")
    for route in app.routes:
        if hasattr(route, 'path'):
            methods = getattr(route, 'methods', ['ALL'])
            logger.info(f"   {route.path} -> {methods}")

# =============================================================================
# 11. ENTRYPOINT
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    # Validate required config
    if not PUBLIC_URL:
        logger.error("❌ PUBLIC_URL environment variable is required!")
        sys.exit(1)
    if not CLIENT_ID or not CLIENT_SECRET:
        logger.error("❌ CLIENT_ID and CLIENT_SECRET environment variables are required!")
        sys.exit(1)
    if not os.path.exists(KEY_PATH):
        logger.warning(f"⚠️ Service account key not found at {KEY_PATH}")
    
    logger.info(f"🚀 Starting Google Workspace MCP Server")
    logger.info(f"   PUBLIC_URL: {PUBLIC_URL}")
    logger.info(f"   ALLOWED_DOMAIN: {ALLOWED_DOMAIN}")
    logger.info(f"   Architecture: Standard MCP SDK + Starlette (NOT FastMCP)")
    
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))