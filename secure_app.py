import os
import sys
import logging
import json
import io
import datetime
import httpx
from urllib.parse import urlencode

# Standard MCP & Starlette
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Route
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

# Google & Auth
from google.oauth2 import service_account
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
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
PUBLIC_URL = os.environ.get("PUBLIC_URL")

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

# --- 2. OAUTH PROXY ENDPOINTS (ChatGPT Integration) ---

async def oauth_well_known(request: Request):
    return JSONResponse({
        "issuer": PUBLIC_URL,
        "authorization_endpoint": f"{PUBLIC_URL}/authorize",
        "token_endpoint": f"{PUBLIC_URL}/token",
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "response_types_supported": ["code"]
    })

async def oauth_authorize(request: Request):
    params = request.query_params
    payload = {
        "client_id": CLIENT_ID,
        "redirect_uri": params.get("redirect_uri"),
        "response_type": "code",
        "scope": "openid email",
        "state": params.get("state"),
        "access_type": "online",
        "prompt": "consent"
    }
    return RedirectResponse(f"https://accounts.google.com/o/oauth2/auth?{urlencode(payload)}")

async def oauth_token(request: Request):
    form = await request.form()
    async with httpx.AsyncClient() as client:
        resp = await client.post("https://oauth2.googleapis.com/token", data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": form.get("code"),
            "grant_type": "authorization_code",
            "redirect_uri": form.get("redirect_uri")
        })
        return JSONResponse(resp.json(), status_code=resp.status_code)

# --- 3. SECURITY MIDDLEWARE (Access Token Validation) ---

class OAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        allowed_paths = ["/", "/health", "/authorize", "/token", "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"]
        if request.url.path in allowed_paths:
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"error": "Missing Token"})
        
        token = auth_header.split(" ")[1]
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get("https://oauth2.googleapis.com/tokeninfo", params={"access_token": token})
                if response.status_code != 200:
                    return JSONResponse(status_code=401, content={"error": "Invalid Token"})
                user_email = response.json().get("email", "")
                if not user_email.endswith(f"@{ALLOWED_DOMAIN}"):
                    return JSONResponse(status_code=403, content={"error": "Unauthorized domain"})
                return await call_next(request)
            except Exception as e:
                return JSONResponse(status_code=500, content={"error": str(e)})

# --- 4. GOOGLE SERVICES ---

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

# --- 5. MCP SERVER & ALL TOOLS ---

mcp_server = Server("google-workspace-mcp")

TOOLS_SCHEMA = [
    Tool(name="search_files", description="Find files by name across Drive.", inputSchema={"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}),
    Tool(name="list_folder", description="List contents of a specific folder.", inputSchema={"type":"object","properties":{"folder_id":{"type":"string"}},"required":["folder_id"]}),
    Tool(name="read_file", description="Read content from Doc, PDF, Excel, or Text.", inputSchema={"type":"object","properties":{"file_id":{"type":"string"}},"required":["file_id"]}),
    Tool(name="read_sheet_values", description="Read specific range from Google Sheet.", inputSchema={"type":"object","properties":{"spreadsheet_id":{"type":"string"},"range":{"type":"string"}},"required":["spreadsheet_id"]}),
    Tool(name="read_doc_structure", description="Get full document structure (tables/lists).", inputSchema={"type":"object","properties":{"document_id":{"type":"string"}},"required":["document_id"]}),
    Tool(name="read_slides", description="Read text from all slides in a deck.", inputSchema={"type":"object","properties":{"presentation_id":{"type":"string"}},"required":["presentation_id"]}),
    Tool(name="list_events", description="List upcoming calendar events.", inputSchema={"type":"object","properties":{"calendar_id":{"type":"string"},"limit":{"type":"integer"}},"required":[]}),
    Tool(name="find_person", description="Search company directory for a person.", inputSchema={"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}),
    Tool(name="list_file_history", description="Get revision history of a file.", inputSchema={"type":"object","properties":{"file_id":{"type":"string"}},"required":["file_id"]}),
    Tool(name="read_old_version", description="Read content from a specific file revision.", inputSchema={"type":"object","properties":{"file_id":{"type":"string"},"revision_id":{"type":"string"}},"required":["file_id","revision_id"]}),
    Tool(name="get_file_activity", description="See move/rename/edit logs.", inputSchema={"type":"object","properties":{"file_id":{"type":"string"}},"required":["file_id"]}),
]

@mcp_server.list_tools()
async def handle_list_tools() -> list[Tool]:
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

# --- 6. SERVER WIRING & ROBUST HANDLERS ---

# We create the transport once at the top level
sse_transport = SseServerTransport("/messages")

async def handle_sse(scope, receive, send):
    """Explicit ASGI handler for SSE to prevent NoneType errors."""
    async with sse_transport.connect_sse(scope, receive, send) as streams:
        await mcp_server.run(
            streams[0], 
            streams[1], 
            mcp_server.create_initialization_options()
        )

async def handle_messages(scope, receive, send):
    """Explicit ASGI handler for POST messages."""
    await sse_transport.handle_post_message(scope, receive, send)

# Simple Response Helpers
async def homepage(request: Request):
    return JSONResponse({"status": "active", "mode": "standard_mcp"})

async def healthcheck(request: Request):
    return JSONResponse({"status": "ok"})

# THE FINAL ROUTES LIST
# Using the function names directly (without Request) for SSE/Messages
# is the standard way to handle low-level ASGI transports in Starlette.
routes = [
    Route("/", endpoint=homepage),
    Route("/health", endpoint=healthcheck),
    Route("/sse", endpoint=handle_sse, methods=["GET", "POST"]),
    Route("/messages", endpoint=handle_messages, methods=["POST"]),
    # OAuth Handshake Endpoints
    Route("/.well-known/oauth-authorization-server", endpoint=oauth_well_known),
    Route("/.well-known/openid-configuration", endpoint=oauth_well_known),
    Route("/authorize", endpoint=oauth_authorize),
    Route("/token", endpoint=oauth_token, methods=["POST"])
]

app = Starlette(
    routes=routes, 
    middleware=[Middleware(OAuthMiddleware)]
)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    logger.info(f"🚀 Deployment Finalizing on port {port}...")
    uvicorn.run(app, host="0.0.0.0", port=port)