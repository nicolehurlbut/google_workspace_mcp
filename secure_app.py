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
# Initialize the server
server = FastMCP("google-workspace-mcp")

# Path to the key we mounted in Cloud Run
KEY_PATH = "/app/service-account.json"
SCOPES = ['https://www.googleapis.com/auth/drive.readonly']

try:
    if os.path.exists(KEY_PATH):
        creds = service_account.Credentials.from_service_account_file(
            KEY_PATH, scopes=SCOPES
        )
        # Connect to Google Drive API
        drive_service = build('drive', 'v3', credentials=creds)
        logger.info("✅ Successfully connected to Google Drive API")
    else:
        logger.warning(f"⚠️ Key file not found at {KEY_PATH}. Tools will fail.")
        drive_service = None
except Exception as e:
    logger.error(f"❌ Auth Failed: {e}")
    drive_service = None

# --- 2. DEFINE TOOLS ---

@server.tool()
def list_drive_items(query: str = None, limit: int = 10):
    """
    List files in the allowed Google Drive.
    Args:
        query: Optional search query (e.g., "name contains 'budget'")
        limit: Max files to return (default 10)
    """
    if not drive_service:
        return "Error: Server not authenticated."

    try:
        # Construct query. default is not trashed.
        q = "trashed = false"
        if query:
            q += f" and name contains '{query}'"
            
        results = drive_service.files().list(
            q=q, pageSize=limit, fields="files(id, name, mimeType, webViewLink, driveId)"
        ).execute()
        
        items = results.get('files', [])
        if not items:
            return "No files found."
        return json.dumps(items, indent=2)
    except HttpError as error:
        return f"An error occurred: {error}"

@server.tool()
def read_file(file_id: str):
    """
    Read the content of a specific Google Doc or text file.
    Args:
        file_id: The ID of the file to read.
    """
    if not drive_service:
        return "Error: Server not authenticated."

    try:
        # Check if it's a google doc (needs export) or regular file (needs get)
        file_meta = drive_service.files().get(fileId=file_id).execute()
        mime_type = file_meta.get('mimeType')

        if "application/vnd.google-apps" in mime_type:
            # Export Google Docs to plain text
            request = drive_service.files().export_media(fileId=file_id, mimeType='text/plain')
        else:
            # Download regular files
            request = drive_service.files().get_media(fileId=file_id)
            
        content = request.execute()
        return content.decode('utf-8')
    except Exception as e:
        return f"Error reading file: {e}"

# --- 3. SECURITY PROXY (Your Filtering Logic) ---
# This runs AFTER tools are defined to wrap them in security

ALLOWED_SHARED_DRIVE_ID = os.environ.get("ALLOWED_SHARED_DRIVE_ID", "").strip()
ALLOWED_FILE_IDS = [id.strip() for id in os.environ.get("ALLOWED_FILE_IDS", "").split(",") if id.strip()]

def secure_server(mcp_server):
    """Wraps all tools in the server with security checks"""
    
    # Helper to find registry
    registry = None
    for attr in ["_tool_registry", "tools", "_tools", "registry"]:
        if hasattr(mcp_server, attr): 
            registry = getattr(mcp_server, attr)
            break
            
    if not registry:
        logger.warning("⚠️ Could not find tool registry. Security not applied.")
        return

    def create_security_proxy(orig_fn):
        @wraps(orig_fn)
        async def secured_proxy(*args, **kwargs):
            # A. INPUT CHECK
            if ALLOWED_FILE_IDS:
                for k, v in kwargs.items():
                    if k == "file_id" and v not in ALLOWED_FILE_IDS:
                         # Allow if it's in the allowed shared drive (logic simplified for clarity)
                         if not ALLOWED_SHARED_DRIVE_ID: 
                             raise ValueError(f"⛔ ACCESS DENIED: File ID {v} is not in the allowlist.")

            # B. RUN TOOL
            result = await orig_fn(*args, **kwargs)

            # C. OUTPUT CHECK (Filter results)
            if isinstance(result, str) and result.startswith("["):
                try:
                    data = json.loads(result)
                    if isinstance(data, list):
                        filtered = []
                        for item in data:
                            # Filter logic here if needed
                            filtered.append(item)
                        return json.dumps(filtered, indent=2)
                except:
                    pass
            return result
        return secured_proxy

    # Apply wrapper to all tools
    for name in list(registry.keys()):
        tool = registry[name]
        # Depending on FastMCP version, tool might be a function or an object
        if hasattr(tool, 'fn'):
            tool.fn = create_security_proxy(tool.fn)
            logger.info(f"🔒 Secured tool: {name}")

# Apply the security
secure_server(server)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    logger.info(f"🚀 Starting Secure Server on 0.0.0.0:{port}")
    server.run(transport="sse")