import os
import sys
import logging
import json
from functools import wraps
from fastmcp import FastMCP

# Google Libraries
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("google_mcp")

# --- 1. SETUP SERVER & AUTH ---
server = FastMCP("google-workspace-mcp")

KEY_PATH = "/app/service-account.json"
# Added 'spreadsheets.readonly' scope
SCOPES = [
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/spreadsheets.readonly'
]

drive_service = None
sheet_service = None

try:
    if os.path.exists(KEY_PATH):
        creds = service_account.Credentials.from_service_account_file(
            KEY_PATH, scopes=SCOPES
        )
        # Build BOTH services
        drive_service = build('drive', 'v3', credentials=creds)
        sheet_service = build('sheets', 'v4', credentials=creds)
        logger.info("✅ Successfully connected to Drive and Sheets APIs")
    else:
        logger.warning(f"⚠️ Key file not found at {KEY_PATH}. Tools will fail.")
except Exception as e:
    logger.error(f"❌ Auth Failed: {e}")

# --- 2. DEFINE TOOLS ---

@server.tool()
def list_drive_items(query: str = None, limit: int = 10):
    """List files in Google Drive. Optional query filters by name."""
    if not drive_service: return "Error: Server not authenticated."
    try:
        q = "trashed = false"
        if query:
            q += f" and name contains '{query}'"
            
        results = drive_service.files().list(
            q=q, pageSize=limit, fields="files(id, name, mimeType, webViewLink)"
        ).execute()
        return json.dumps(results.get('files', []), indent=2)
    except Exception as e:
        return f"Error listing files: {e}"

@server.tool()
def search_files(name_query: str):
    """Find files specifically by name (e.g. 'Budget 2024')."""
    if not drive_service: return "Error: Server not authenticated."
    try:
        q = f"name contains '{name_query}' and trashed = false"
        results = drive_service.files().list(
            q=q, pageSize=10, fields="files(id, name, mimeType, webViewLink)"
        ).execute()
        items = results.get('files', [])
        if not items: return "No files found."
        return json.dumps(items, indent=2)
    except Exception as e:
        return f"Error searching: {e}"

@server.tool()
def read_file(file_id: str):
    """Read the text content of a Google Doc."""
    if not drive_service: return "Error: Server not authenticated."
    try:
        file_meta = drive_service.files().get(fileId=file_id).execute()
        mime_type = file_meta.get('mimeType')

        if "application/vnd.google-apps" in mime_type:
            # Export Google Docs to plain text
            request = drive_service.files().export_media(fileId=file_id, mimeType='text/plain')
        else:
            # Download regular text files
            request = drive_service.files().get_media(fileId=file_id)
            
        content = request.execute()
        return content.decode('utf-8')
    except Exception as e:
        return f"Error reading file: {e}"

@server.tool()
def read_sheet_values(spreadsheet_id: str, range_name: str = "A1:Z100"):
    """
    Read data from a Google Sheet.
    Args:
        spreadsheet_id: The ID of the sheet file.
        range_name: The range to read (e.g. 'Sheet1!A1:B10'). Defaults to first 100 rows.
    """
    if not sheet_service: return "Error: Sheets service not authenticated."
    try:
        result = sheet_service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range=range_name
        ).execute()
        rows = result.get('values', [])
        if not rows: return "No data found."
        return json.dumps(rows, indent=2)
    except Exception as e:
        return f"Error reading sheet: {e}"

@server.tool()
def get_file_metadata(file_id: str):
    """Get details about a file (owner, modified time, type) without downloading it."""
    if not drive_service: return "Error: Server not authenticated."
    try:
        file = drive_service.files().get(
            fileId=file_id, 
            fields="id, name, mimeType, parents, modifiedTime, owners, webViewLink"
        ).execute()
        return json.dumps(file, indent=2)
    except Exception as e:
        return f"Error getting metadata: {e}"

# --- 3. SECURITY ---

ALLOWED_FILE_IDS = [id.strip() for id in os.environ.get("ALLOWED_FILE_IDS", "").split(",") if id.strip()]

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    logger.info(f"🚀 Starting Secure Server on 0.0.0.0:{port}")
    
    # Run the server
    server.run(transport="sse", host="0.0.0.0", port=port)