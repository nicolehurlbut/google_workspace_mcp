import os
import sys
import logging
import json
import io
import datetime
from fastmcp import FastMCP

# Google Libraries
from google.oauth2 import service_account
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from googleapiclient.discovery import build

# Starlette (Server & Security)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# File Handlers
from pypdf import PdfReader
import openpyxl

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("google_mcp")

# --- 1. SETUP SERVER & AUTH ---
server = FastMCP("google-workspace-mcp")

KEY_PATH = "/app/service-account.json"

# Internal Service Account Scopes (The Bot's Power)
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

# --- SECURITY CONFIGURATION ---
ALLOWED_DOMAIN = "singlefile.io" 

# --- SECURITY MIDDLEWARE (The "Gatekeeper") ---
class OAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Allow health checks or browser pings (optional)
        if request.url.path == "/" or request.url.path == "/health":
            return await call_next(request)

        # 1. Get the Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            # If valid, allow it to proceed to the endpoint handler (which might just fail if it's SSE)
            # But strictly speaking, ChatGPT sends the token.
            return JSONResponse(status_code=401, content={"error": "Missing Auth Token"})
            
        token = auth_header.split(" ")[1]
        
        try:
            # 2. Ask Google: "Who does this token belong to?"
            # We use a generic request because we just want to validate the email domain
            # We skip client_id check here because ChatGPT manages the client ID
            id_info = id_token.verify_oauth2_token(
                token, 
                google_requests.Request(), 
                clock_skew_in_seconds=10
            )
            
            # 3. Check the Domain ("hd" = Hosted Domain)
            user_domain = id_info.get('hd')
            user_email = id_info.get('email')
            
            # 3a. If user has no domain (gmail.com), 'hd' is None
            if not user_domain:
                logger.warning(f"⛔ Blocked public gmail user: {user_email}")
                return JSONResponse(status_code=403, content={"error": "Public Gmail accounts not allowed."})

            # 3b. Check if it matches YOUR domain
            if user_domain != ALLOWED_DOMAIN:
                logger.warning(f"⛔ Blocked external domain: {user_email}")
                return JSONResponse(
                    status_code=403, 
                    content={"error": f"Unauthorized. You must use a {ALLOWED_DOMAIN} email."}
                )
                
            # 4. Success!
            logger.info(f"✅ Access granted to: {user_email}")
            return await call_next(request)
            
        except ValueError as e:
            logger.warning(f"Invalid Token: {e}")
            return JSONResponse(status_code=401, content={"error": "Invalid or Expired Token"})

# --- INTERNAL SERVICE AUTH (The Bot's Badge) ---
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
        creds = service_account.Credentials.from_service_account_file(
            KEY_PATH, scopes=SCOPES
        )
        drive_service = build('drive', 'v3', credentials=creds)
        sheet_service = build('sheets', 'v4', credentials=creds)
        docs_service = build('docs', 'v1', credentials=creds)
        slides_service = build('slides', 'v1', credentials=creds)
        forms_service = build('forms', 'v1', credentials=creds)
        calendar_service = build('calendar', 'v3', credentials=creds)
        people_service = build('people', 'v1', credentials=creds)
        activity_service = build('driveactivity', 'v2', credentials=creds)
        logger.info("✅ Internal Service Account Connected.")
    else:
        logger.critical(f"❌ FATAL: Key file not found at {KEY_PATH}")
except Exception as e:
    logger.error(f"❌ Auth Failed: {e}")

# --- HELPER ---
def _run_drive_list(query_str: str, limit: int = 10):
    if not drive_service: return "Error: Server not authenticated."
    try:
        results = drive_service.files().list(
            q=query_str, pageSize=limit, 
            fields="files(id, name, mimeType, webViewLink, parents)"
        ).execute()
        items = results.get('files', [])
        return json.dumps(items, indent=2) if items else "No files found."
    except Exception as e:
        return f"Error: {e}"

# --- TOOLS ---

@server.tool()
def search_files(query: str):
    """Find files by name (e.g. 'Project Plan'). Searches entire Drive."""
    q = f"name contains '{query}' and trashed = false"
    return _run_drive_list(q)

@server.tool()
def list_contents_of_folder(folder_id: str = None):
    """Browse inside a specific folder. If no ID, checks root."""
    target = folder_id if folder_id else 'root'
    q = f"'{target}' in parents and trashed = false"
    return _run_drive_list(q, limit=20)

@server.tool()
def read_file(file_id: str):
    """Master Reader: Handles Docs, PDFs, Excel, and Text."""
    if not drive_service: return "Error: No Auth."
    try:
        meta = drive_service.files().get(fileId=file_id).execute()
        mime = meta.get('mimeType', '')
        name = meta.get('name', '')

        if "application/vnd.google-apps.document" in mime:
            req = drive_service.files().export_media(fileId=file_id, mimeType='text/plain')
            return req.execute().decode('utf-8')
        elif "application/pdf" in mime:
            req = drive_service.files().get_media(fileId=file_id)
            content = req.execute()
            reader = PdfReader(io.BytesIO(content))
            text = [f"--- PDF: {name} ---"]
            for i, page in enumerate(reader.pages):
                text.append(f"[Page {i+1}]\n{page.extract_text()}")
            return "\n".join(text)
        elif "spreadsheetml.sheet" in mime:
            req = drive_service.files().get_media(fileId=file_id)
            wb = openpyxl.load_workbook(io.BytesIO(req.execute()), data_only=True)
            output = [f"--- Excel: {name} ---"]
            for sheet in wb.sheetnames:
                output.append(f"\n[Sheet: {sheet}]")
                for row in wb[sheet].iter_rows(max_row=20, values_only=True):
                    clean = [str(c) for c in row if c is not None]
                    if clean: output.append(" | ".join(clean))
            return "\n".join(output)
        else:
            req = drive_service.files().get_media(fileId=file_id)
            return req.execute().decode('utf-8')
    except Exception as e:
        return f"Error reading file: {e}"

@server.tool()
def read_sheet_values(spreadsheet_id: str, range_name: str = "A1:Z100"):
    if not sheet_service: return "Error: No Auth."
    try:
        res = sheet_service.spreadsheets().values().get(spreadsheetId=spreadsheet_id, range=range_name).execute()
        return json.dumps(res.get('values', []), indent=2)
    except Exception as e: return f"Error: {e}"

@server.tool()
def read_doc_structure(document_id: str):
    if not docs_service: return "Error: No Auth."
    try:
        doc = docs_service.documents().get(documentId=document_id).execute()
        output = []
        def parse(elements):
            for e in elements:
                if 'paragraph' in e:
                    txt = "".join([t['textRun']['content'] for t in e['paragraph']['elements'] if 'textRun' in t])
                    output.append(txt.strip())
                elif 'table' in e:
                    output.append("\n[TABLE]")
                    for r in e['table']['tableRows']:
                        row = []
                        for c in r['tableCells']:
                            cell_txt = "".join([t['textRun']['content'] for ce in c['content'] for t in ce.get('paragraph', {}).get('elements', []) if 'textRun' in t])
                            row.append(cell_txt.strip())
                        output.append(" | ".join(row))
                    output.append("[END TABLE]\n")
        parse(doc.get('body').get('content'))
        return "\n".join(output)
    except Exception as e: return f"Error: {e}"

@server.tool()
def read_slides(presentation_id: str):
    if not slides_service: return "Error: No Auth."
    try:
        deck = slides_service.presentations().get(presentationId=presentation_id).execute()
        output = [f"--- Slides: {deck.get('title')} ---"]
        for i, slide in enumerate(deck.get('slides', [])):
            output.append(f"\n[Slide {i+1}]")
            for elem in slide.get('pageElements', []):
                if 'shape' in elem and 'text' in elem['shape']:
                    txt = "".join([t['textRun']['content'] for t in elem['shape']['text'].get('textElements', []) if 'textRun' in t])
                    output.append(txt.strip())
        return "\n".join(output)
    except Exception as e: return f"Error: {e}"

@server.tool()
def read_form(form_id: str):
    if not forms_service: return "Error: No Auth."
    try:
        form = forms_service.forms().get(form_id=form_id).execute()
        output = [f"Form: {form.get('info', {}).get('title')}"]
        for item in form.get('items', []):
            q_title = item.get('title', 'Unknown')
            q_type = list(item.get('questionItem', {}).get('question', {}).keys()) if 'questionItem' in item else "Layout/Image"
            output.append(f"Q: {q_title} ({q_type})")
        return "\n".join(output)
    except Exception as e: return f"Error: {e}"

@server.tool()
def list_calendars():
    if not calendar_service: return "Error: No Auth."
    try:
        res = calendar_service.calendarList().list().execute()
        return "\n".join([f"{c['summary']} (ID: {c['id']})" for c in res.get('items', [])])
    except Exception as e: return f"Error: {e}"

@server.tool()
def list_events(calendar_id: str = 'primary', limit: int = 5):
    if not calendar_service: return "Error: No Auth."
    try:
        now = datetime.datetime.utcnow().isoformat() + 'Z'
        res = calendar_service.events().list(calendarId=calendar_id, timeMin=now, maxResults=limit, singleEvents=True, orderBy='startTime').execute()
        events = res.get('items', [])
        return "\n".join([f"{e['start'].get('dateTime', e['start'].get('date'))}: {e.get('summary')}" for e in events])
    except Exception as e: return f"Error: {e}"

@server.tool()
def find_person(query: str):
    if not people_service: return "Error: No Auth."
    try:
        res = people_service.people().searchDirectoryPeople(query=query, readMask="names,emailAddresses,organizations", sources=["DIRECTORY_SOURCE_TYPE_DOMAIN_CONTACT"]).execute()
        output = []
        for p in res.get('people', []):
            name = p.get('names', [{}])[0].get('displayName', 'Unknown')
            email = p.get('emailAddresses', [{}])[0].get('value', '')
            output.append(f"{name} <{email}>")
        return "\n".join(output) if output else "Person not found."
    except Exception as e: return f"Error: {e}"

# --- STARTUP WITH OAUTH GATEKEEPER ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    
    # 1. Create the base app
    app = server._create_starlette_app()
    
    # 2. Add the OAuth Middleware (The Bouncer)
    app.add_middleware(OAuthMiddleware)
    
    # 3. Run
    import uvicorn
    logger.info(f"🚀 Starting Secure OAuth-Gatekept Bot on 0.0.0.0:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port)