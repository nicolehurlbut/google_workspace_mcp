import os
import uvicorn
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastmcp_server import mcp
from pydantic import create_model
from typing import Any, Optional

# --- Configuration ---

# 1. Enable Stateless Mode
os.environ["MCP_ENABLE_OAUTH21"] = "true"
os.environ["EXTERNAL_OAUTH21_PROVIDER"] = "true"
os.environ["WORKSPACE_MCP_STATELESS_MODE"] = "true"

# 2. Define Allowed File IDs (Comma Separated in Env Var)
# Example: "1AbC..., 1XyZ..."
ALLOWED_FILE_IDS = [
    id.strip() for id in os.environ.get("ALLOWED_FILE_IDS", "").split(",") 
    if id.strip()
]

# 3. Define Allowed Services (Keywords to match in tool names)
ALLOWED_SERVICES_KEYWORDS = [
    "drive", "sheet", "doc", "slide", "presentation", "form"
]

# 4. Define "Write" Keywords to BLOCK (Double safety)
# Even with read-only scopes, we'll hide these tools to avoid confusion.
BLOCKED_ACTION_KEYWORDS = [
    "create", "update", "delete", "modify", "append", "write", "trash", "upload"
]

app = FastAPI(title="Restricted Google Workspace Bridge", version="1.0")
security = HTTPBearer()

# --- Tool Registration ---

registered_tools = 0

for tool_name, tool in mcp._tool_registry.items():
    tool_name_lower = tool_name.lower()

    # FILTER 1: Must belong to allowed services
    if not any(kw in tool_name_lower for kw in ALLOWED_SERVICES_KEYWORDS):
        continue

    # FILTER 2: Must NOT be a write operation
    if any(kw in tool_name_lower for kw in BLOCKED_ACTION_KEYWORDS):
        continue

    # Create Pydantic model for arguments
    fields = {
        param_name: (param.annotation if param.annotation != NotImplemented else Any, ...)
        for param_name, param in tool.fn_signature.parameters.items()
    }
    ArgumentModel = create_model(f"{tool_name}_Args", **fields) if fields else None

    # Define the endpoint wrapper
    async def endpoint_wrapper(
        request: Request,
        args: Optional[ArgumentModel] = None, # type: ignore
        token: HTTPAuthorizationCredentials = Depends(security)
    ):
        tool_args = args.dict() if args else {}

        # SECURITY CHECK: File Allowlist
        # We check common argument names used for IDs
        id_args = ['file_id', 'document_id', 'spreadsheet_id', 'presentation_id', 'form_id', 'id']
        
        # If the user defined an allowlist, enforce it
        if ALLOWED_FILE_IDS:
            for key, value in tool_args.items():
                if key in id_args and isinstance(value, str):
                    if value not in ALLOWED_FILE_IDS:
                        print(f"Blocked access to file: {value}")
                        raise HTTPException(
                            status_code=403, 
                            detail=f"Access denied: You are not allowed to access file ID {value}"
                        )

        # Call the tool
        try:
            # Note: The MCP server normally relies on internal context.
            # In stateless mode with this repo, we rely on the logic passing through 
            # or the underlying library handling the token if we could inject it.
            # For this repo specifically, it often inspects `mcp.request_context`.
            # To make this robust without rewriting the repo, we rely on the 
            # 'Authorization' header being present in the incoming request (which FastAPI passes).
            return await mcp.call_tool(tool_name, arguments=tool_args)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # Register Route
    app.post(f"/{tool_name}", operation_id=tool_name)(endpoint_wrapper)
    registered_tools += 1

print(f"Server initialized. Registered {registered_tools} read-only tools.")

@app.get("/health")
def health():
    return {"status": "ok", "tools_count": registered_tools}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)