import os
import inspect
from functools import wraps
from fastmcp_server import mcp as original_mcp
from fastmcp import FastMCP

# --- CONFIGURATION ---

# 1. Stateless Mode
os.environ["MCP_ENABLE_OAUTH21"] = "true"
os.environ["EXTERNAL_OAUTH21_PROVIDER"] = "true"
os.environ["WORKSPACE_MCP_STATELESS_MODE"] = "true"

# 2. Strict Allowlist for File IDs
ALLOWED_FILE_IDS = [
    id.strip() for id in os.environ.get("ALLOWED_FILE_IDS", "").split(",") 
    if id.strip()
]

# 3. Service Allowlist
ALLOWED_SERVICES = ["drive", "sheet", "doc", "slide", "form"]

# 4. Blocked Actions
BLOCKED_KEYWORDS = ["create", "update", "delete", "modify", "append", "write", "trash", "upload"]

# --- INITIALIZE SECURE SERVER ---

# We create a new MCP server that will "host" the filtered tools
secure_mcp = FastMCP(
    "Secure Google Workspace App"
)

# --- TOOL FILTERING & WRAPPING ---

print("🔒 Initializing Secure MCP Wrapper...")
registered_count = 0

# Iterate through the original server's tools
for tool_name, tool_def in original_mcp._tool_registry.items():
    t_name = tool_name.lower()
    
    # FILTER 1: Must be in allowed services
    if not any(svc in t_name for svc in ALLOWED_SERVICES):
        continue

    # FILTER 2: Must NOT be a write operation
    if any(b in t_name for b in BLOCKED_KEYWORDS):
        continue

    # FILTER 3: Wrap the function to check File IDs
    original_func = tool_def.fn
    
    @wraps(original_func)
    async def secured_proxy_func(*args, **kwargs):
        # Merge args and kwargs into a single dictionary for checking
        sig = inspect.signature(original_func)
        bound = sig.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        all_args = bound.arguments

        # Check every argument value
        if ALLOWED_FILE_IDS:
            for key, value in all_args.items():
                # If a value looks like a file ID (string) and is NOT in the allowlist
                if isinstance(value, str) and "id" in key.lower(): 
                    # We only strictly check keys with "id" to avoid blocking normal text search queries
                    # But for maximum security, you might check ALL strings.
                    if value not in ALLOWED_FILE_IDS:
                         raise ValueError(f"⛔ ACCESS DENIED: You are not allowed to access File ID: {value}")
        
        # If safe, call the original tool
        return await original_func(*args, **kwargs)

    # Register the wrapped tool to our new Secure Server
    secure_mcp.add_tool(
        name=tool_name,
        description=tool_def.description,
    )(secured_proxy_func)
    
    registered_count += 1

print(f"✅ Registered {registered_count} secure tools.")

# --- ENTRY POINT ---

# This runs the server using the 'streamable-http' transport required by ChatGPT Apps
if __name__ == "__main__":
    # Get the PORT from Google Cloud (defaults to 8080 if not set)
    port = int(os.environ.get("PORT", 8080))
    
    # Run the server binding to 0.0.0.0 (required for Cloud Run)
    secure_mcp.run(transport="sse", host="0.0.0.0", port=port)