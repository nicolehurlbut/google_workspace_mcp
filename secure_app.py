import os
import inspect
import sys
from functools import wraps
from fastmcp import FastMCP

# --- CONFIGURATION (Must be set BEFORE importing the server) ---
# This ensures the original server initializes in the correct "External Auth" mode
os.environ["MCP_ENABLE_OAUTH21"] = "true"
os.environ["EXTERNAL_OAUTH21_PROVIDER"] = "true"
os.environ["WORKSPACE_MCP_STATELESS_MODE"] = "true"

# Define your restrictions
ALLOWED_SERVICES = ["drive", "sheet", "doc", "slide", "form"]
BLOCKED_KEYWORDS = ["create", "update", "delete", "modify", "append", "write", "trash", "upload"]
ALLOWED_FILE_IDS = [
    id.strip() for id in os.environ.get("ALLOWED_FILE_IDS", "").split(",") 
    if id.strip()
]

print("🔒 Starting Secure Proxy Initialization...")

# --- IMPORT EXISTING SERVER ---
# We import the 'mcp' object from the repo. It already has the OAuth setup!
try:
    from fastmcp_server import mcp as server
except ImportError:
    print("❌ Error: Could not import 'mcp' from 'fastmcp_server'. Make sure you are in the repo root.")
    sys.exit(1)

# --- HELPER: FIND REGISTRY ---
def get_tool_registry(mcp_obj):
    """Finds the tool registry dictionary inside the FastMCP object."""
    candidates = ["_tool_registry", "tools", "_tools", "registry"]
    for attr in candidates:
        if hasattr(mcp_obj, attr):
            return getattr(mcp_obj, attr)
    # Check for wrappers
    if hasattr(mcp_obj, "mcp"): return get_tool_registry(mcp_obj.mcp)
    if hasattr(mcp_obj, "_mcp"): return get_tool_registry(mcp_obj._mcp)
    raise AttributeError(f"Could not find tool registry. Attributes: {dir(mcp_obj)}")

# --- APPLY RESTRICTIONS ---
try:
    registry = get_tool_registry(server)
    print(f"ℹ️  Found {len(registry)} tools. Applying security filters...")

    # We need to collect changes first, then apply them (can't modify dict while iterating)
    tools_to_remove = []
    tools_to_secure = []

    for tool_name, tool_def in registry.items():
        t_name = tool_name.lower()
        
        # 1. CHECK ALLOWED SERVICES
        if not any(svc in t_name for svc in ALLOWED_SERVICES):
            tools_to_remove.append(tool_name)
            continue

        # 2. CHECK BLOCKED ACTIONS
        if any(b in t_name for b in BLOCKED_KEYWORDS):
            tools_to_remove.append(tool_name)
            continue
            
        # 3. IF ALLOWED, MARK FOR WRAPPING
        tools_to_secure.append(tool_name)

    # REMOVE BANNED TOOLS
    for name in tools_to_remove:
        del registry[name]
    
    print(f"🚫 Removed {len(tools_to_remove)} blocked/irrelevant tools.")

    # SECURE ALLOWED TOOLS
    for name in tools_to_secure:
        original_tool = registry[name]
        original_func = original_tool.fn

        @wraps(original_func)
        async def secured_proxy_func(*args, **kwargs):
            # Inspect arguments for File IDs
            sig = inspect.signature(original_func)
            try:
                bound = sig.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                all_args = bound.arguments
            except:
                # If binding fails, just pass through (let original function handle error)
                all_args = kwargs

            # Enforce Allowlist
            if ALLOWED_FILE_IDS:
                for key, value in all_args.items():
                    # Check any string argument that looks like an ID
                    if isinstance(value, str) and ("id" in key.lower() or len(value) > 20):
                        # Skip short strings (likely not IDs) to avoid false positives
                        if len(value) > 10 and value not in ALLOWED_FILE_IDS:
                            print(f"⛔ Blocked access to ID: {value}")
                            raise ValueError(f"⛔ ACCESS DENIED: You are not allowed to access File ID: {value}")

            return await original_func(*args, **kwargs)

        # Replace the function in the registry
        original_tool.fn = secured_proxy_func

    print(f"✅ Secured {len(tools_to_secure)} tools.")

except Exception as e:
    print(f"❌ Critical Error securing tools: {e}")
    # We continue, so the server at least starts (logs will show the error)

# --- RUN SERVER ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    # Run the ORIGINAL server object, which has all the correct Auth config
    server.run(transport="sse", host="0.0.0.0", port=port)