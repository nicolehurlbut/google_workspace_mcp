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

# We remove the 'description' argument as it caused an error in your version
secure_mcp = FastMCP("Secure Google Workspace App")

# --- HELPER: Find the Tool Registry ---

def get_tool_registry(mcp_obj):
    """
    Attempts to find the tool registry in the mcp object, handling 
    custom wrappers like SecureFastMCP or different FastMCP versions.
    """
    # List of possible attribute names where tools might be stored
    candidates = ["_tool_registry", "tools", "_tools", "registry"]
    
    # 1. Check direct attributes
    for attr in candidates:
        if hasattr(mcp_obj, attr):
            return getattr(mcp_obj, attr)
            
    # 2. Check if it's a wrapper (e.g. has .mcp or ._mcp inside)
    if hasattr(mcp_obj, "mcp"):
        return get_tool_registry(mcp_obj.mcp)
    if hasattr(mcp_obj, "_mcp"):
        return get_tool_registry(mcp_obj._mcp)
        
    # 3. If we can't find it, print debug info and crash
    print(f"❌ CRITICAL ERROR: Could not find tool registry in {type(mcp_obj)}")
    print(f"Available attributes: {dir(mcp_obj)}")
    raise AttributeError("Could not find tool registry to secure.")

# --- TOOL FILTERING & WRAPPING ---

print("🔒 Initializing Secure MCP Wrapper...")
registered_count = 0

# Retrieve the registry using our robust helper
try:
    source_registry = get_tool_registry(original_mcp)
except Exception as e:
    print(f"⚠️ Failed to inspect original MCP: {e}")
    source_registry = {}

# Iterate through the original server's tools
# Note: depending on version, items() might be (name, tool) or just a list
items = source_registry.items() if hasattr(source_registry, "items") else []

for tool_name, tool_def in items:
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
                if isinstance(value, str) and "id" in key.lower(): 
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    # Listen on 0.0.0.0 to expose to Cloud Run
    secure_mcp.run(transport="sse", host="0.0.0.0", port=port)