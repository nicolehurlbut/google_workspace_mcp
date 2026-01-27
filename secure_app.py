"""
secure_app.py - Google Workspace MCP Server
Uses Standard MCP SDK + Starlette (NOT FastMCP)

Architecture:
- Starlette for full HTTP routing control
- SseServerTransport for MCP communication
- Manual OAuth proxy for ChatGPT/Claude compatibility
- Token validation middleware for @singlefile.io domain restriction
- Session caching for Claude's multi-request pattern
"""

import os
import sys
import logging
import json
import io
import datetime
import time
import secrets
import hashlib
import base64
import httpx
from urllib.parse import urlencode
from typing import Optional, Dict

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
# 2. SESSION CACHE (For Claude's multi-request pattern)
# =============================================================================

# Cache stores {client_fingerprint: (email, timestamp, token)}
_auth_cache: Dict[str, tuple[str, float, str]] = {}
SESSION_TTL_SECONDS = 300  # 5 minutes

def get_client_fingerprint(scope) -> str:
    """Create a fingerprint from request headers to identify the client.
    
    Note: We only use IP address because Claude's user-agent changes between
    the OAuth flow (python-httpx) and MCP requests (Claude-User).
    """
    headers = dict(scope.get("headers", []))
    forwarded_for = headers.get(b"x-forwarded-for", b"").decode("utf-8")
    # Just use IP - user-agent is unreliable (changes between OAuth and MCP requests)
    # Take first IP if there are multiple (proxy chain)
    client_ip = forwarded_for.split(",")[0].strip() if forwarded_for else "unknown"
    return hashlib.sha256(client_ip.encode()).hexdigest()[:16]

def cache_authenticated_user(scope, email: str, token: str):
    """Remember that this client just authenticated."""
    fingerprint = get_client_fingerprint(scope)
    _auth_cache[fingerprint] = (email, time.time(), token)
    logger.info(f"📝 Cached session for {email} (fingerprint: {fingerprint})")
    
    # Clean old entries
    now = time.time()
    expired = [k for k, (_, ts, _) in _auth_cache.items() if now - ts > SESSION_TTL_SECONDS]
    for k in expired:
        del _auth_cache[k]
        logger.info(f"🗑️ Expired session cache: {k}")

def get_cached_session(scope) -> Optional[tuple[str, str]]:
    """Check if this client recently authenticated. Returns (email, token) or None."""
    fingerprint = get_client_fingerprint(scope)
    if fingerprint in _auth_cache:
        email, timestamp, token = _auth_cache[fingerprint]
        if time.time() - timestamp < SESSION_TTL_SECONDS:
            logger.info(f"✅ Found cached session for {email} (age: {int(time.time() - timestamp)}s)")
            return (email, token)
        else:
            del _auth_cache[fingerprint]
            logger.info(f"🗑️ Session expired for {email}")
    return None

# =============================================================================
# 3. OAUTH STATE STORAGE (In-memory - use Redis for production)
# =============================================================================

auth_states = {}  # {state_key: {data, expires}}
authenticated_sessions = {}  # {session_id: {email, expires}}

def cleanup_expired_states():
    """Remove expired OAuth states and sessions"""
    now = time.time()
    expired = [k for k, v in auth_states.items() if v.get("expires", 0) < now]
    for k in expired:
        auth_states.pop(k, None)
    
    expired_sessions = [k for k, v in authenticated_sessions.items() if v.get("expires", 0) < now]
    for k in expired_sessions:
        authenticated_sessions.pop(k, None)

# =============================================================================
# 4. TOKEN VALIDATION (Domain Restriction)
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
# 5. GOOGLE SERVICE BUILDERS
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
# 6. FILE CONTENT EXTRACTION
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
# 7. MCP SERVER SETUP
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
# 8. SSE/MCP TRANSPORT HANDLERS
# =============================================================================

sse_transport = SseServerTransport("/mcp/messages")

class SSEApp:
    """
    SSE endpoint with token validation + session caching.
    Requires valid Google token from @singlefile.io domain.
    Falls back to cached session if no token provided.
    
    WORKAROUND: Claude.ai has a known bug where it doesn't send the OAuth token
    on MCP requests (user-agent: Claude-User). We allow these requests through
    since they come from Anthropic's servers after successful OAuth.
    See: https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1674
    """
    async def __call__(self, scope, receive, send):
        # Extract headers
        headers = dict(scope.get("headers", []))
        
        auth_header = headers.get(b"authorization", b"").decode("utf-8")
        user_agent = headers.get(b"user-agent", b"").decode("utf-8")
        fingerprint = get_client_fingerprint(scope)
        
        logger.info(f"🔍 SSE request - fingerprint: {fingerprint}")
        logger.info(f"   user-agent: {user_agent}")
        logger.info(f"   auth header present: {bool(auth_header)}")
        
        # Try to authenticate
        email = None
        token = None
        
        # Method 1: Bearer token in header
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            token_info = await verify_google_token(token)
            if token_info:
                email = token_info.get('email')
                # Cache this authentication for future requests
                cache_authenticated_user(scope, email, token)
                logger.info(f"✅ SSE authorized via Bearer token: {email}")
        
        # Method 2: Fall back to cached session
        if not email:
            cached = get_cached_session(scope)
            if cached:
                email, token = cached
                logger.info(f"✅ SSE authorized via cached session: {email}")
        
        # Method 3: WORKAROUND for Claude.ai bug
        # Claude.ai doesn't send the OAuth token on MCP requests (known bug)
        # Allow requests from Claude-User since they come from Anthropic's servers
        # after a successful OAuth flow
        if not email and user_agent == "Claude-User":
            logger.warning(f"⚠️ WORKAROUND: Allowing Claude-User without token (known Claude.ai bug)")
            logger.warning(f"   See: https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1674")
            email = f"claude-user@{ALLOWED_DOMAIN}"  # Placeholder email for logging
        
        # Reject if no valid auth
        if not email:
            logger.warning("❌ SSE connection rejected: invalid or missing token")
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({
                "type": "http.response.body",
                "body": b'{"error": "Unauthorized - valid token required"}'
            })
            return
        
        # Authorized - proceed with MCP connection
        logger.info(f"🚀 Starting MCP session for {email}")
        try:
            async with sse_transport.connect_sse(scope, receive, send) as streams:
                logger.info(f"📡 SSE connection established, starting MCP server run...")
                await mcp_server.run(
                    streams[0],
                    streams[1],
                    mcp_server.create_initialization_options()
                )
                logger.info(f"✅ MCP session completed normally")
        except Exception as e:
            logger.error(f"❌ MCP session error: {type(e).__name__}: {e}")
            raise

class MessageApp:
    """
    Handle POST messages for MCP transport - also with session caching.
    
    WORKAROUND: Claude.ai has a known bug where it doesn't send the OAuth token
    on MCP requests (user-agent: Claude-User). We allow these requests through.
    See: https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1674
    """
    async def __call__(self, scope, receive, send):
        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode("utf-8")
        user_agent = headers.get(b"user-agent", b"").decode("utf-8")
        fingerprint = get_client_fingerprint(scope)
        
        logger.info(f"📨 POST /mcp/messages - fingerprint: {fingerprint}")
        logger.info(f"   user-agent: {user_agent}")
        
        # Try to authenticate
        email = None
        
        # Method 1: Bearer token
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            token_info = await verify_google_token(token)
            if token_info:
                email = token_info.get('email')
                cache_authenticated_user(scope, email, token)
                logger.info(f"✅ Message authorized via Bearer: {email}")
        
        # Method 2: Cached session
        if not email:
            cached = get_cached_session(scope)
            if cached:
                email, _ = cached
                logger.info(f"✅ Message authorized via cache: {email}")
        
        # Method 3: WORKAROUND for Claude.ai bug
        if not email and user_agent == "Claude-User":
            logger.warning(f"⚠️ WORKAROUND: Allowing Claude-User without token (known Claude.ai bug)")
            email = f"claude-user@{ALLOWED_DOMAIN}"
        
        if not email:
            logger.warning("❌ Message rejected: no valid auth")
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({
                "type": "http.response.body",
                "body": b'{"error": "Unauthorized"}'
            })
            return
        
        await sse_transport.handle_post_message(scope, receive, send)

# =============================================================================
# 9. OAUTH PROXY ENDPOINTS
# =============================================================================

async def oauth_well_known(request: Request):
    """OAuth/OIDC discovery endpoint"""
    return JSONResponse({
        "issuer": PUBLIC_URL,
        "authorization_endpoint": f"{PUBLIC_URL}/authorize",
        "token_endpoint": f"{PUBLIC_URL}/token",
        "registration_endpoint": f"{PUBLIC_URL}/register",
        "userinfo_endpoint": f"{PUBLIC_URL}/userinfo",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
    })

async def oauth_protected_resource(request: Request):
    """OAuth 2.0 Protected Resource Metadata (RFC 9728)"""
    return JSONResponse({
        "resource": f"{PUBLIC_URL}/",
        "authorization_servers": [PUBLIC_URL],
        "scopes_supported": ["openid", "email", "profile"],
        "bearer_methods_supported": ["header"],
    })

async def oauth_authorize(request: Request):
    """
    Step 1: Claude/ChatGPT redirects user here.
    We pass through to Google with THEIR redirect_uri.
    """
    cleanup_expired_states()
    
    params = request.query_params
    client_id = params.get("client_id", "")
    client_redirect_uri = params.get("redirect_uri", "")
    client_state = params.get("state", "")
    code_challenge = params.get("code_challenge", "")
    code_challenge_method = params.get("code_challenge_method", "S256")
    scope = params.get("scope", "openid email profile")
    
    logger.info(f"📥 OAuth authorize request")
    logger.info(f"   client_id: {client_id[:20]}..." if client_id else "   client_id: None")
    logger.info(f"   redirect_uri: {client_redirect_uri}")
    logger.info(f"   state: {client_state[:20]}..." if client_state else "   state: None")
    logger.info(f"   code_challenge: {code_challenge[:20]}..." if code_challenge else "   code_challenge: None")
    
    # Verify client_id if using DCR (optional - skip if not registered)
    if client_id and client_id not in registered_clients:
        # Allow unregistered clients for backwards compatibility
        logger.warning(f"⚠️ Unknown client_id: {client_id[:20]}... (allowing anyway)")
    
    # Store client info to restore after Google callback
    internal_state = secrets.token_urlsafe(32)
    auth_states[internal_state] = {
        "client_id": client_id,
        "client_state": client_state,
        "client_redirect_uri": client_redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope,
        "expires": time.time() + 600  # 10 min expiry
    }
    
    # Build Google OAuth URL - use OUR callback, we'll redirect to client after
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
    We exchange the code with Google, then redirect to Claude/ChatGPT.
    """
    params = request.query_params
    code = params.get("code")
    internal_state = params.get("state")
    error = params.get("error")
    
    if error:
        logger.error(f"❌ Google OAuth error: {error}")
        return JSONResponse({"error": error}, status_code=400)
    
    # Retrieve stored client info
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
    
    # Store tokens with a new code for Claude/ChatGPT
    proxy_code = secrets.token_urlsafe(32)
    auth_states[proxy_code] = {
        "tokens": token_data,
        "code_challenge": stored.get("code_challenge"),
        "code_challenge_method": stored.get("code_challenge_method"),
        "expires": time.time() + 300  # 5 min expiry
    }
    
    # Redirect back to Claude/ChatGPT with OUR code
    client_redirect_uri = stored["client_redirect_uri"]
    redirect_url = f"{client_redirect_uri}?code={proxy_code}&state={stored['client_state']}"
    
    logger.info(f"🔄 Redirecting back to client: {client_redirect_uri}")
    return RedirectResponse(redirect_url)

async def oauth_token(request: Request):
    """
    Step 3: Claude/ChatGPT exchanges our code for tokens.
    Supports PKCE (code_verifier) for Claude.
    """
    form = await request.form()
    grant_type = form.get("grant_type")
    code_verifier = form.get("code_verifier")  # PKCE
    
    logger.info(f"📥 Token request - grant_type: {grant_type}")
    logger.info(f"   code_verifier present: {bool(code_verifier)}")
    
    if grant_type == "authorization_code":
        code = form.get("code")
        stored = auth_states.pop(code, None)
        
        if not stored or stored.get("expires", 0) < time.time():
            logger.error("❌ Invalid or expired code")
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        
        # Verify PKCE if code_challenge was provided
        if stored.get("code_challenge") and code_verifier:
            # S256: BASE64URL(SHA256(code_verifier)) == code_challenge
            verifier_hash = hashlib.sha256(code_verifier.encode()).digest()
            computed_challenge = base64.urlsafe_b64encode(verifier_hash).rstrip(b'=').decode()
            if computed_challenge != stored["code_challenge"]:
                logger.error("❌ PKCE verification failed")
                return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)
            logger.info("✅ PKCE verification passed")
        
        token_data = stored["tokens"]
        logger.info(f"✅ Returning tokens - has refresh_token: {'refresh_token' in token_data}")
        
        return JSONResponse({
            "access_token": token_data["access_token"],
            "token_type": "bearer",  # lowercase required!
            "expires_in": token_data.get("expires_in", 3600),
            "refresh_token": token_data.get("refresh_token", ""),
            "scope": token_data.get("scope", ""),
        })
    
    elif grant_type == "refresh_token":
        refresh_token = form.get("refresh_token")
        logger.info(f"📥 Refresh token request - token present: {bool(refresh_token)}")
        
        async with httpx.AsyncClient() as client:
            resp = await client.post("https://oauth2.googleapis.com/token", data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token"
            })
            
            if resp.status_code != 200:
                logger.error(f"❌ Refresh token failed: {resp.status_code} - {resp.text}")
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            
            token_data = resp.json()
            logger.info(f"✅ Refresh successful - new access_token received")
            
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

# Dynamic client registration storage
registered_clients = {}

async def oauth_register(request: Request):
    """Dynamic Client Registration (RFC 7591)"""
    try:
        body = await request.json()
    except:
        return JSONResponse({"error": "invalid_request"}, status_code=400)
    
    logger.info(f"📝 DCR request: {body}")
    
    # Generate client credentials
    client_id = secrets.token_urlsafe(24)
    client_secret = secrets.token_urlsafe(32)
    
    redirect_uris = body.get("redirect_uris", [])
    client_name = body.get("client_name", "Unknown")
    
    # Store client info
    registered_clients[client_id] = {
        "client_secret": client_secret,
        "redirect_uris": redirect_uris,
        "client_name": client_name,
        "created_at": time.time()
    }
    
    logger.info(f"✅ Registered new client: {client_name} ({client_id})")
    logger.info(f"   Redirect URIs: {redirect_uris}")
    
    return JSONResponse({
        "client_id": client_id,
        "client_secret": client_secret,
        "client_id_issued_at": int(time.time()),
        "client_secret_expires_at": 0,  # Never expires
        "redirect_uris": redirect_uris,
        "client_name": client_name,
        "token_endpoint_auth_method": "none",  # Claude uses PKCE, not client_secret
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }, status_code=201)

# =============================================================================
# 10. UTILITY ENDPOINTS
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
# 11. STARLETTE APP & ROUTING
# =============================================================================

routes = [
    # MCP/SSE Endpoints - ROOT for ChatGPT compatibility
    Route("/", endpoint=SSEApp()),
    Route("/mcp/messages", endpoint=MessageApp(), methods=["POST"]),
    
    # Health & Info
    Route("/info", endpoint=homepage),
    Route("/health", endpoint=health_check),
    
    # OAuth Discovery (both paths for compatibility)
    Route("/.well-known/oauth-authorization-server", endpoint=oauth_well_known),
    Route("/.well-known/oauth-authorization-server/mcp", endpoint=oauth_well_known),  # ChatGPT compat
    Route("/.well-known/openid-configuration", endpoint=oauth_well_known),
    
    # OAuth Flow
    Route("/authorize", endpoint=oauth_authorize, methods=["GET"]),
    Route("/oauth2callback", endpoint=oauth_callback, methods=["GET"]),
    Route("/token", endpoint=oauth_token, methods=["POST"]),
    Route("/userinfo", endpoint=oauth_userinfo, methods=["GET"]),
    Route("/register", endpoint=oauth_register, methods=["POST"]),
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
# 12. ENTRYPOINT
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