import os
import sys
import logging
import json
import io
import openpyxl 
from pypdf import PdfReader
from fastmcp import FastMCP
from google.oauth2 import service_account
from googleapiclient.discovery import build

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("google_mcp")

# --- 1. SETUP SERVER & AUTH ---
server = FastMCP("google-workspace-mcp")

KEY_PATH = "/app/service-account.json"
SCOPES = [
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/spreadsheets.readonly',
    'https://www.googleapis.com/auth/presentations.readonly',
    'https://www.googleapis.com/auth/calendar.readonly',
    'https://www.googleapis.com/auth/documents.readonly',
    'https://www.googleapis.com/auth/forms.body.readonly',
    'https://www.googleapis.com/auth/forms.responses.readonly'
]

# Initialize GLOBAL variables for all services
drive_service = None
sheet_service = None
docs_service = None 

try:
    if os.path.exists(KEY_PATH):
        creds = service_account.Credentials.from_service_account_file(
            KEY_PATH, scopes=SCOPES
        )
        # Build ALL services here
        drive_service = build('drive', 'v3', credentials=creds)
        sheet_service = build('sheets', 'v4', credentials=creds)
        docs_service = build('docs', 'v1', credentials=creds)
        forms_service = build('forms', 'v1', credentials=creds)
        
        logger.info("✅ Connected to Drive, Sheets, Forms, and Docs APIs")
    else:
        logger.warning(f"⚠️ Key file not found at {KEY_PATH}. Tools will fail.")
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
    """
    Read the content of a file. Supports Google Docs, Text files, and PDFs.
    """
    if not drive_service: return "Error: Server not authenticated."
    try:
        # 1. Get File Metadata (to check type)
        file_meta = drive_service.files().get(fileId=file_id).execute()
        mime_type = file_meta.get('mimeType')
        name = file_meta.get('name')

        # 2. Handle Google Docs (Export)
        if "application/vnd.google-apps" in mime_type:
            request = drive_service.files().export_media(fileId=file_id, mimeType='text/plain')
            content = request.execute()
            return content.decode('utf-8')

        # 3. Handle PDFs (Download & Parse)
        elif mime_type == 'application/pdf':
            request = drive_service.files().get_media(fileId=file_id)
            file_content = request.execute() # Returns raw bytes
            
            # Use pypdf to read the bytes
            pdf_file = io.BytesIO(file_content)
            reader = PdfReader(pdf_file)
            
            text = [f"--- Content of PDF: {name} ---"]
            for i, page in enumerate(reader.pages):
                text.append(f"[Page {i+1}]")
                text.append(page.extract_text())
                
            return "\n".join(text)

        # NEW: Handle Excel
         if mime_type == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':
        request = drive_service.files().get_media(fileId=file_id)
        file_content = request.execute()
        
        # Load into openpyxl
        wb = openpyxl.load_workbook(filename=io.BytesIO(file_content), data_only=True)
        
        output = []
        for sheet_name in wb.sheetnames:
            ws = wb[sheet_name]
            output.append(f"--- Sheet: {sheet_name} ---")
            # Read first 20 rows to avoid massive output
            for row in ws.iter_rows(max_row=20, values_only=True):
                # Filter out None values
                clean_row = [str(cell) for cell in row if cell is not None]
                if clean_row:
                    output.append(" | ".join(clean_row))
                    
        return "\n".join(output)

        # 4. Handle Regular Text/Code Files (Download directly)
        else:
            request = drive_service.files().get_media(fileId=file_id)
            content = request.execute()
            # Try decoding as utf-8, fallback if binary
            try:
                return content.decode('utf-8')
            except UnicodeDecodeError:
                return f"Error: File '{name}' seems to be a binary file (image/video) and cannot be read as text."

    except Exception as e:
        return f"Error reading file: {e}"

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

@server.tool()
def read_presentation_text(presentation_id: str):
    """Read all text from a Google Slides presentation."""
    service = build('slides', 'v1', credentials=creds)
    try:
        presentation = service.presentations().get(presentationId=presentation_id).execute()
        slides = presentation.get('slides', [])
        text_content = []
        
        for i, slide in enumerate(slides):
            text_content.append(f"--- Slide {i+1} ---")
            # Iterate through elements on the slide to find text
            for element in slide.get('pageElements', []):
                if 'shape' in element and 'text' in element['shape']:
                    for text_run in element['shape']['text'].get('textElements', []):
                        if 'textRun' in text_run:
                            text_content.append(text_run['textRun']['content'].strip())
                            
        return "\n".join([t for t in text_content if t])
    except Exception as e:
        return f"Error reading slides: {e}"

@server.tool()
def check_file_permissions(file_id: str):
    """
    See who has access to a file.
    Returns a list of names, emails, and their roles (owner, writer, reader).
    """
    if not drive_service: return "Error: No Auth."
    try:
        # Get permissions list
        res = drive_service.permissions().list(
            fileId=file_id, 
            fields="permissions(type, role, emailAddress, displayName)"
        ).execute()
        
        perms = res.get('permissions', [])
        
        # Format it nicely for the AI to read
        summary = []
        for p in perms:
            name = p.get('displayName', 'Unknown')
            email = p.get('emailAddress', 'No Email/Link Shared')
            role = p.get('role')
            summary.append(f"{role.upper()}: {name} ({email})")
            
        return "\n".join(summary)
    except Exception as e:
        return f"Error checking permissions: {e}"

@server.tool()
def read_doc_structure(document_id: str):
    """
    Read a Google Doc preserving structure (tables, lists).
    Use this if 'read_file' returns messy text.
    """
    # Check the global variable we just created
    if not docs_service: return "Error: Docs service not authenticated."
    
    try:
        doc = docs_service.documents().get(documentId=document_id).execute()
        content = doc.get('body').get('content')
        
        text_output = []
        
        def read_struc(elements):
            for elem in elements:
                # Text Paragraphs
                if 'paragraph' in elem:
                    para = elem['paragraph']['elements']
                    line = "".join([t['textRun']['content'] for t in para if 'textRun' in t])
                    text_output.append(line.strip())
                
                # Tables
                elif 'table' in elem:
                    text_output.append("\n[TABLE]")
                    for row in elem['table']['tableRows']:
                        row_text = []
                        for cell in row['tableCells']:
                            cell_content = [] 
                            for cell_elem in cell['content']:
                                if 'paragraph' in cell_elem:
                                    para = cell_elem['paragraph']['elements']
                                    cell_content.append("".join([t['textRun']['content'] for t in para if 'textRun' in t]).strip())
                            row_text.append(" | ".join(cell_content))
                        text_output.append(" | ".join(row_text))
                    text_output.append("[END TABLE]\n")

        read_struc(content)
        return "\n".join(text_output)
    except Exception as e:
        return f"Error reading doc structure: {e}"

@server.tool()
def read_form_structure(form_id: str):
    """
    Read the questions and options from a Google Form.
    """
    if not forms_service: return "Error: Forms service not authenticated."
    
    try:
        # Get the form content
        form = forms_service.forms().get(form_id=form_id).execute()
        
        output = [f"FORM TITLE: {form.get('info', {}).get('title')}"]
        
        for item in form.get('items', []):
            title = item.get('title', 'Untitled Question')
            
            # Check question type (Text, Multiple Choice, etc.)
            q_type = "Unknown"
            options = []
            
            if 'questionItem' in item:
                q = item['questionItem']['question']
                
                if 'textQuestion' in q: q_type = "Text Input"
                elif 'choiceQuestion' in q:
                    q_type = "Multiple Choice"
                    options = [o['value'] for o in q['choiceQuestion'].get('options', []) if 'value' in o]
                
                output.append(f"\nQ: {title} [{q_type}]")
                if options:
                    output.append(f"   Options: {', '.join(options)}")
                    
        return "\n".join(output)
    except Exception as e:
        return f"Error reading form: {e}"

@server.tool()
def list_contents_of_folder(folder_id: str = None):
    """
    Explore a specific folder. 
    Use this to navigate through sub-folders.
    Args:
        folder_id: The ID of the folder to look inside. 
                   If None, looks at the Root of the drive.
    """
    if not drive_service: return "Error: No Auth."
    
    # "root" tells Drive to look at the top level
    target_id = folder_id if folder_id else 'root'
    
    try:
        # The magic query: "'parent_id' in parents"
        q = f"'{target_id}' in parents and trashed = false"
        
        results = drive_service.files().list(
            q=q, 
            pageSize=20, 
            # We ask for 'mimeType' so the bot knows which items are folders
            fields="files(id, name, mimeType, webViewLink)"
        ).execute()
        
        items = results.get('files', [])
        
        # Helper to make the output readable
        output = [f"--- Contents of folder: {target_id} ---"]
        for item in items:
            type_icon = "📁" if "folder" in item['mimeType'] else "📄"
            output.append(f"{type_icon} {item['name']} (ID: {item['id']})")
            
        return "\n".join(output) if items else "This folder is empty."
    except Exception as e:
        return f"Error listing folder: {e}"

# --- NEW TOOL: TIME MACHINE ---
@server.tool()
def list_file_history(file_id: str):
    """
    See the history of a file (who changed it and when).
    Returns a list of Revision IDs you can use to read old versions.
    """
    if not drive_service: return "Error: No Auth."
    try:
        # Request revisions
        revisions = drive_service.revisions().list(
            fileId=file_id, fields="revisions(id, modifiedTime, lastModifyingUser)"
        ).execute()
        
        items = revisions.get('revisions', [])
        output = []
        for rev in items:
            user = rev.get('lastModifyingUser', {}).get('displayName', 'Unknown')
            time = rev.get('modifiedTime')
            rev_id = rev.get('id')
            output.append(f"Time: {time} | User: {user} | ID: {rev_id}")
            
        return "\n".join(output)
    except Exception as e:
        return f"Error listing history: {e}"

@server.tool()
def read_old_version(file_id: str, revision_id: str):
    """Read the text content of a file as it existed in the past."""
    if not drive_service: return "Error: No Auth."
    try:
        # We download the specific revision
        request = drive_service.revisions().get_media(
            fileId=file_id, revisionId=revision_id
        )
        content = request.execute()
        return content.decode('utf-8')
    except Exception as e:
        return f"Error reading old version: {e}"

@server.tool()
def get_file_activity(file_id: str):
    """
    See RECENT ACTIONS on a file (Move, Rename, Edit, Permission Change).
    This is different from 'revisions' because it shows WHO did it and WHAT type of action.
    """
    # Requires 'driveactivity' service
    service = build('driveactivity', 'v2', credentials=creds)
    
    try:
        # Query for the specific file
        request = {'item_name': f'items/{file_id}', 'pageSize': 10}
        response = service.activity().query(body=request).execute()
        
        activities = response.get('activities', [])
        output = []
        
        for activity in activities:
            # 1. Get Timestamp
            time = activity.get('timestamp', 'Unknown Time')
            
            # 2. Get Actor (Who did it?)
            actors = activity.get('actors', [])
            if actors and 'user' in actors[0]:
                user = actors[0]['user'].get('knownUser', {}).get('personName', 'Unknown User')
            else:
                user = "System/Anonymous"
                
            # 3. Get Action (What did they do?)
            # Actions are keys like 'edit', 'move', 'rename'
            action_type = "Unknown Action"
            primary_action = activity.get('primaryActionDetail', {})
            if primary_action:
                action_type = list(primary_action.keys())[0] # e.g. 'edit' or 'move'
            
            output.append(f"[{time}] {user} performed: {action_type.upper()}")
            
        return "\n".join(output)
    except Exception as e:
        return f"Error getting activity: {e}"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    logger.info(f"🚀 Starting Secure Server on 0.0.0.0:{port}")
    server.run(transport="sse", host="0.0.0.0", port=port)