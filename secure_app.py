import os
import sys
import logging
import json
from fastmcp import FastMCP
from google.oauth2 import service_account
from googleapiclient.discovery import build

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("google_mcp")

# --- SETUP ---
server = FastMCP("google-workspace-mcp")
KEY_PATH = "/app/service-account.json"
SCOPES = [
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/spreadsheets.readonly'
]

drive_service = None
sheet_service = None

try:
    if os.path.exists(KEY_PATH):
        creds = service_account.Credentials.from_service_account_file(KEY_PATH, scopes=SCOPES)
        drive_service = build('drive', 'v3', credentials=creds)
        sheet_service = build('sheets', 'v4', credentials=creds)
        logger.info("✅ Connected to Google APIs")
    else:
        logger.warning(f"⚠️ Key file missing at {KEY_PATH}")
except Exception as e:
    logger.error(f"❌ Auth Failed: {e}")

# --- HELPER FUNCTION ---
def _run_drive_list(query_str: str, limit: int = 10):
    try:
        results = drive_service.files().list(
            q=query_str, pageSize=limit, fields="files(id, name, mimeType, webViewLink)"
        ).execute()
        items = results.get('files', [])
        if not items: return "No files found."
        return json.dumps(items, indent=2)
    except Exception as e:
        return f"Error: {e}"

# --- TOOLS ---

@server.tool()
def list_drive_items(query: str = None, limit: int = 10):
    """List all files. Optional query filters by name."""
    if not drive_service: return "Error: No Auth."
    q = "trashed = false"
    if query: q += f" and name contains '{query}'"
    return _run_drive_list(q, limit)

@server.tool()
def list_sheets(query: str = None, limit: int = 10):
    """List ONLY Google Sheets."""
    if not drive_service: return "Error: No Auth."
    q = "mimeType = 'application/vnd.google-apps.spreadsheet' and trashed = false"
    if query: q += f" and name contains '{query}'"
    return _run_drive_list(q, limit)

@server.tool()
def list_docs(query: str = None, limit: int = 10):
    """List ONLY Google Docs."""
    if not drive_service: return "Error: No Auth."
    q = "mimeType = 'application/vnd.google-apps.document' and trashed = false"
    if query: q += f" and name contains '{query}'"
    return _run_drive_list(q, limit)

@server.tool()
def search_files(name_query: str):
    """Find files by exact name match."""
    if not drive_service: return "Error: No Auth."
    q = f"name contains '{name_query}' and trashed = false"
    return _run_drive_list(q, 10)

@server.tool()
def read_file(file_id: str):
    """Read text content of a Google Doc."""
    if not drive_service: return "Error: No Auth."
    try:
        meta = drive_service.files().get(fileId=file_id).execute()
        if "application/vnd.google-apps" in meta.get('mimeType', ''):
            req = drive_service.files().export_media(fileId=file_id, mimeType='text/plain')
        else:
            req = drive_service.files().get_media(fileId=file_id)
        return req.execute().decode('utf-8')
    except Exception as e:
        return f"Error reading: {e}"

@server.tool()
def read_sheet_values(spreadsheet_id: str, range_name: str = "A1:Z100"):
    """Read cells from a Google Sheet."""
    if not sheet_service: return "Error: No Sheets Auth."
    try:
        res = sheet_service.spreadsheets().values().get(spreadsheetId=spreadsheet_id, range=range_name).execute()
        return json.dumps(res.get('values', []), indent=2)
    except Exception as e:
        return f"Error reading sheet: {e}"

@server.tool()
def read_comments(file_id: str):
    """Read comments on a file."""
    if not drive_service: return "Error: No Auth."
    try:
        res = drive_service.comments().list(fileId=file_id, fields="comments(content, author(displayName))").execute()
        return json.dumps(res.get('comments', []), indent=2)
    except Exception as e:
        return f"Error reading comments: {e}"

@server.tool()
def get_file_metadata(file_id: str):
    """Get owner, modified time, and type."""
    if not drive_service: return "Error: No Auth."
    try:
        return json.dumps(drive_service.files().get(fileId=file_id, fields="id, name, owners, modifiedTime").execute(), indent=2)
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    logger.info(f"🚀 Starting Secure Server on 0.0.0.0:{port}")
    server.run(transport="sse", host="0.0.0.0", port=port)