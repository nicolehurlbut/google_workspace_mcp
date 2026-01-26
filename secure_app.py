import os
import sys
import logging
import json
import io
import datetime
from fastmcp import FastMCP

# Google Libraries
from google.oauth2 import service_account
from googleapiclient.discovery import build

# File Handlers
from pypdf import PdfReader
import openpyxl

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("google_mcp")

# --- 1. SETUP SERVER & AUTH ---
server = FastMCP("google-workspace-mcp")

# The Service Account Key (Mounted by Cloud Run)
KEY_PATH = "/app/service-account.json"

# All the permissions the bot needs
SCOPES = [
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/spreadsheets.readonly',
    'https://www.googleapis.com/auth/documents.readonly',
    'https://www.googleapis.com/auth/presentations.readonly',
    'https://www.googleapis.com/auth/forms.body.readonly',
    'https://www.googleapis.com/auth/calendar.readonly',
    'https://www.googleapis.com/auth/directory.readonly',     # People
    'https://www.googleapis.com/auth/drive.activity.readonly' # Activity
]

# Initialize Global Services
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
        # Build ALL services
        drive_service = build('drive', 'v3', credentials=creds)
        sheet_service = build('sheets', 'v4', credentials=creds)
        docs_service = build('docs', 'v1', credentials=creds)
        slides_service = build('slides', 'v1', credentials=creds)
        forms_service = build('forms', 'v1', credentials=creds)
        calendar_service = build('calendar', 'v3', credentials=creds)
        people_service = build('people', 'v1', credentials=creds)
        activity_service = build('driveactivity', 'v2', credentials=creds)
        
        logger.info("✅ Auth Success: Connected as Service Account.")
    else:
        logger.critical(f"❌ FATAL: Key file not found at {KEY_PATH}")
except Exception as e:
    logger.error(f"❌ Auth Failed: {e}")

# --- HELPER: GENERIC LISTER ---
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

# --- TOOLS: NAVIGATION ---

@server.tool()
def search_files(query: str):
    """Find files by name (e.g. 'Project Plan'). Searches entire Drive."""
    return _run_drive_list(f"name contains '{query}' and trashed = false")

@server.tool()
def list_contents_of_folder(folder_id: str = None):
    """Browse inside a specific folder. If no ID, checks root."""
    target = folder_id if folder_id else 'root'
    return _run_drive_list(f"'{target}' in parents and trashed = false", limit=20)

# --- TOOLS: READERS ---

@server.tool()
def read_file(file_id: str):
    """
    Master Reader: Handles Docs, PDFs, Excel, and Text.
    """
    if not drive_service: return "Error: No Auth."
    try:
        # Get Metadata
        meta = drive_service.files().get(fileId=file_id).execute()
        mime = meta.get('mimeType', '')
        name = meta.get('name', '')

        # 1. Google Doc (Text Export)
        if "application/vnd.google-apps.document" in mime:
            req = drive_service.files().export_media(fileId=file_id, mimeType='text/plain')
            return req.execute().decode('utf-8')
        
        # 2. PDF
        elif "application/pdf" in mime:
            req = drive_service.files().get_media(fileId=file_id)
            content = req.execute()
            reader = PdfReader(io.BytesIO(content))
            text = [f"--- PDF: {name} ---"]
            for i, page in enumerate(reader.pages):
                text.append(f"[Page {i+1}]\n{page.extract_text()}")
            return "\n".join(text)

        # 3. Excel (.xlsx)
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

        # 4. Text / Code
        else:
            req = drive_service.files().get_media(fileId=file_id)
            return req.execute().decode('utf-8')

    except Exception as e:
        return f"Error reading file: {e}"

@server.tool()
def read_sheet_values(spreadsheet_id: str, range_name: str = "A1:Z100"):
    """Read raw data from a Google Sheet."""
    if not sheet_service: return "Error: No Auth."
    try:
        res = sheet_service.spreadsheets().values().get(spreadsheetId=spreadsheet_id, range=range_name).execute()
        return json.dumps(res.get('values', []), indent=2)
    except Exception as e: return f"Error: {e}"

@server.tool()
def read_doc_structure(document_id: str):
    """Read Google Doc preserving tables/lists (Advanced)."""
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
    """Read text from Google Slides."""
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
    """Read questions from a Google Form."""
    if not forms_service: return "Error