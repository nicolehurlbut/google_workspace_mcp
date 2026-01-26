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

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("google_mcp")

# --- CONFIGURATION ---
KEY_PATH = "/app/service-account.json"
ALLOWED_DOMAIN = "yourcompany.com" # ⚠️ CHANGE THIS
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

# --- 1. OAUTH PROXY ENDPOINTS (ChatGPT Integration) ---

async def oauth_well_known(request: Request):
    """Tells ChatGPT where to find our Auth endpoints."""
    return JSONResponse({
        "issuer": PUBLIC_URL,
        "authorization_endpoint": f"{PUBLIC_URL}/authorize",
        "token_endpoint": f"{PUBLIC_URL}/token",
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "response_types_supported": ["code"]
    })

async def oauth_authorize(request: Request):
    """Redirects the user to Google."""
    params = request.query_params
    google_auth_url = "https://accounts.google.com/o/oauth2/auth"
    payload = {
        "client_id": CLIENT_ID,
        "redirect_uri": params.get("redirect_uri"),
        "response_type": "code",
        "scope": "openid email",
        "state": params.get("state"),
        "access_type": "online",
        "prompt": "consent"
    }
    logger.info(f"🔗 Redirecting to Google with callback: {payload['redirect_uri']}")
    return RedirectResponse(f"{google_auth_url}?{urlencode(payload)}")

async def oauth_token(request: Request):
    """Exchanges the code for a token (Server-to-Google)."""
    form = await request.form()
    async with httpx.AsyncClient() as client:
        resp = await client.post("https://oauth2.googleapis.com/token", data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": form.get("code"),
            "grant_type": "authorization_code",
            "redirect_uri": form.get("redirect_uri")
        })
        if resp.status_code != 200:
            logger.error(f"❌ Google Token Fail: {resp.text}")
            return JSONResponse(status_code=400, content={"error": "Failed to get token from Google"})
        return JSONResponse(resp.json())

# --- 2. SECURITY MIDDLEWARE (The Bouncer) ---
class OAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Allow discovery and auth endpoints to pass through
        if request.url.path in ["/", "/health", "/authorize", "/token", "/.well-known/oauth-authorization-server"]:
             return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"error": "Missing Auth Token"})
            
        token = auth_header.split(" ")[1]
        
        try:
            id_info = id_token.verify_oauth2_token(token, google_requests.Request(), clock_skew_in_seconds=10)
            user_domain = id_info.get('hd')
            
            if user_domain != ALLOWED_DOMAIN:
                logger.warning(f"⛔ Blocked external domain: {id_info.get('email')}")
                return JSONResponse(status_code=403, content={"error": f"Must use {ALLOWED_DOMAIN}"})
                
            return await call_next(request)
        except ValueError:
            return JSONResponse(status_code=401, content={"error": "Invalid Token"})

# --- 3. INTERNAL AUTH (Service Account) ---
drive_service = None
sheet_service = None
docs_service = None
slides_service = None
forms_service = None
calendar_service = None
people_service = None
activity_service = None

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
        logger.info("✅ Service Account Connected.")
except Exception as e:
    logger.error(f"❌ Auth Failed: {e}")

# --- 4. TOOL DEFINITIONS (The Full Menu) ---
def _run_drive_list(query_str: str, limit: int = 10):
    if not drive_service: return "Error: Server not authenticated."
    try:
        results = drive_service.files().list(q=query_str, pageSize=limit, fields="files(id, name, mimeType, webViewLink, parents)").execute()
        items = results.get('files', [])
        return json.dumps(items, indent=2) if items else "No files found."
    except Exception as e: return f"Error: {e}"

TOOLS_SCHEMA = [
    Tool(name="search_files", description="Find files by name.", inputSchema={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
    Tool(name="list_contents_of_folder", description="List files inside a folder.", inputSchema={"type": "object", "properties": {"folder_id": {"type": "string"}}, "required": ["folder_id"]}),
    Tool(name="read_file", description="Read file content (Doc/PDF/Excel/Text).", inputSchema={"type": "object", "properties": {"file_id": {"type": "string"}}, "required": ["file_id"]}),
    Tool(name="read_sheet_values", description="Read rows from a Google Sheet.", inputSchema={"type": "object", "properties": {"spreadsheet_id": {"type": "string"}, "range_name": {"type": "string"}}, "required": ["spreadsheet_id"]}),
    Tool(name="read_doc_structure", description="Read Doc preserving tables/lists.", inputSchema={"type": "object", "properties": {"document_id": {"type": "string"}}, "required": ["document_id"]}),
    Tool(name="read_slides", description="Read text from Slides.", inputSchema={"type": "object", "properties": {"presentation_id": {"type": "string"}}, "required": ["presentation_id"]}),
    Tool(name="read_form", description="Read questions from a Form.", inputSchema={"type": "object", "properties": {"form_id": {"type": "string"}}, "required": ["form_id"]}),
    Tool(name="list_calendars", description="List available calendars.", inputSchema={"type": "object", "properties": {}, "required": []}),
    Tool(name="list_events", description="List calendar events.", inputSchema={"type": "object", "properties": {"calendar_id": {"type": "string"}, "limit": {"type": "integer"}}, "required": []}),
    Tool(name="find_person", description="Find contact info.", inputSchema={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
    Tool(name="list_file_history", description="See who changed a file and when.", inputSchema={"type": "object", "properties": {"file_id": {"type": "string"}}, "required": ["file_id"]}),
    Tool(name="read_old_version", description="Read a past version of a file.", inputSchema={"type": "object", "properties": {"file_id": {"type": "string"}, "revision_id": {"type": "string"}}, "required": ["file_id", "revision_id"]}),
    Tool(name="get_file_activity", description="See move/rename/edit history.", inputSchema={"type": "object", "properties": {"file_id": {"type": "string"}}, "required": ["file_id"]}),
]

mcp_server = Server("google-workspace-mcp")

@mcp_server.list_tools()
async def handle_list_tools() -> list[Tool]:
    return TOOLS_SCHEMA

@mcp_server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[TextContent]:
    if not arguments: arguments = {}
    res = ""
    
    try:
        # --- NAVIGATION ---
        if name == "search_files":
            q = f"name contains '{arguments['query']}' and trashed = false"
            res = _run_drive_list(q)
        elif name == "list_contents_of_folder":
            target = arguments.get('folder_id') or 'root'
            q = f"'{target}' in parents and trashed = false"
            res = _run_drive_list(q, limit=20)

        # --- READERS ---
        elif name == "read_file":
            fid = arguments['file_id']
            if not drive_service: res = "Error: No Auth."
            else:
                meta = drive_service.files().get(fileId=fid).execute()
                mime = meta.get('mimeType', '')
                if "application/vnd.google-apps.document" in mime:
                    res = drive_service.files().export_media(fileId=fid, mimeType='text/plain').execute().decode('utf-8')
                elif "application/pdf" in mime:
                    content = drive_service.files().get_media(fileId=fid).execute()
                    reader = PdfReader(io.BytesIO(content))
                    pages = [p.extract_text() for p in reader.pages]
                    res = "\n".join(pages)
                elif "spreadsheetml.sheet" in mime:
                    content = drive_service.files().get_media(fileId=fid).execute()
                    wb = openpyxl.load_workbook(io.BytesIO(content), data_only=True)
                    rows = []
                    for s in wb.sheetnames:
                        for r in wb[s].iter_rows(max_row=10, values_only=True):
                            clean = [str(c) for c in r if c]
                            if clean: rows.append("|".join(clean))
                    res = "\n".join(rows)
                else:
                    res = drive_service.files().get_media(fileId=fid).execute().decode('utf-8')

        elif name == "read_sheet_values":
            if not sheet_service: res = "Error: No Auth."
            else:
                r = sheet_service.spreadsheets().values().get(spreadsheetId=arguments['spreadsheet_id'], range=arguments.get('range_name', 'A1:Z100')).execute()
                res = json.dumps(r.get('values', []), indent=2)

        elif name == "read_doc_structure":
            if not docs_service: res = "Error: No Auth."
            else:
                doc = docs_service.documents().get(documentId=arguments['document_id']).execute()
                content = doc.get('body').get('content', [])
                out = []
                for e in content:
                    if 'paragraph' in e:
                        out.append("".join([t['textRun']['content'] for t in e['paragraph']['elements'] if 'textRun' in t]))
                    elif 'table' in e:
                        out.append("[TABLE]")
                        for r in e['table']['tableRows']:
                            row_txt = []
                            for c in r['tableCells']:
                                cell_txt = "".join([t['textRun']['content'] for ce in c['content'] for t in ce.get('paragraph', {}).get('elements', []) if 'textRun' in t])
                                row_txt.append(cell_txt.strip())
                            out.append(" | ".join(row_txt))
                res = "\n".join(out)

        elif name == "read_slides":
            if not slides_service: res = "Error: No Auth."
            else:
                deck = slides_service.presentations().get(presentationId=arguments['presentation_id']).execute()
                out = []
                for s in deck.get('slides', []):
                    for e in s.get('pageElements', []):
                        if 'shape' in e and 'text' in e['shape']:
                            out.append("".join([t['textRun']['content'] for t in e['shape']['text'].get('textElements', []) if 'textRun' in t]))
                res = "\n".join(out)

        elif name == "read_form":
            if not forms_service: res = "Error: No Auth."
            else:
                form = forms_service.forms().get(form_id=arguments['form_id']).execute()
                res = "\n".join([f"Q: {i.get('title')}" for i in form.get('items', [])])

        # --- CALENDAR & PEOPLE ---
        elif name == "list_calendars":
            if not calendar_service: res = "Error: No Auth."
            else:
                cals = calendar_service.calendarList().list().execute().get('items', [])
                res = "\n".join([f"{c['summary']} ({c['id']})" for c in cals])

        elif name == "list_events":
            if not calendar_service: res = "Error: No Auth."
            else:
                now = datetime.datetime.utcnow().isoformat() + 'Z'
                evs = calendar_service.events().list(calendarId=arguments.get('calendar_id', 'primary'), timeMin=now, maxResults=arguments.get('limit', 5), singleEvents=True).execute().get('items', [])
                res = "\n".join([f"{e['start'].get('dateTime', e['start'].get('date'))}: {e.get('summary')}" for e in evs])

        elif name == "find_person":
            if not people_service: res = "Error: No Auth."
            else:
                ppl = people_service.people().searchDirectoryPeople(query=arguments['query'], readMask="names,emailAddresses", sources=["DIRECTORY_SOURCE_TYPE_DOMAIN_CONTACT"]).execute()
                res = "\n".join([f"{p['names'][0]['displayName']} <{p['emailAddresses'][0]['value']}>" for p in ppl.get('people', [])])

        # --- HISTORY & ACTIVITY ---
        elif name == "list_file_history":
            if not drive_service: res = "Error: No Auth."
            else:
                revs = drive_service.revisions().list(fileId=arguments['file_id'], fields="revisions(id, modifiedTime, lastModifyingUser)").execute().get('revisions', [])
                res = "\n".join([f"{r['modifiedTime']} - {r.get('lastModifyingUser', {}).get('displayName')} (ID: {r['id']})" for r in revs])

        elif name == "read_old_version":
            if not drive_service: res = "Error: No Auth."
            else:
                res = drive_service.revisions().get_media(fileId=arguments['file_id'], revisionId=arguments['revision_id']).execute().decode('utf-8')

        elif name == "get_file_activity":
            if not activity_service: res = "Error: No Auth."
            else:
                acts = activity_service.activity().query(body={'item_name': f'items/{arguments["file_id"]}', 'pageSize': 10}).execute().get('activities', [])
                res = "\n".join([f"{a['timestamp']}: {list(a['primaryActionDetail'].keys())[0]}" for a in acts])

        else:
            res = f"Tool {name} not found."

    except Exception as e:
        res = f"Error: {e}"

    return [TextContent(type="text", text=str(res))]

# --- 5. APP SERVER ---
async def handle_sse(request: Request):
    async with mcp_server.run_sse(request.scope, request.receive, request._send) as streams:
        await streams.run()

async def handle_messages(request: Request):
    await mcp_server.run_sse_messages(request.scope, request.receive, request._send)

routes = [
    Route("/sse", endpoint=handle_sse),
    Route("/messages", endpoint=handle_messages, methods=["POST"]),
    Route("/.well-known/oauth-authorization-server", endpoint=oauth_well_known),
    Route("/authorize", endpoint=oauth_authorize),
    Route("/token", endpoint=oauth_token, methods=["POST"])
]

app = Starlette(routes=routes, middleware=[Middleware(OAuthMiddleware)])

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=port)