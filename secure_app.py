import os
import inspect
import sys
from functools import wraps
from fastmcp import FastMCP

# --- CONFIGURATION ---
# Must be set BEFORE importing the server to trigger correct auth modes
os.environ["MCP_ENABLE_OAUTH21"] = "true"
os.environ["EXTERNAL_OAUTH21_PROVIDER"] = "true"
os.environ["WORKSPACE_MCP_STATELESS_MODE"] = "true"

# Security Rules
ALLOWED_SERVICES = ["drive", "sheet", "doc", "slide", "form"]
BLOCKED_KEYWORDS = ["create", "update", "delete", "modify", "append", "write", "trash", "upload"]
ALLOWED_FILE_IDS = [
    id.strip() for id in os.environ.get("ALLOWED_FILE_IDS", "").split(",") 
    if id.strip()
]

print("🔒 Starting Secure Proxy Initialization...")

# --- IMPORT EXISTING SERVER ---
try:
    from fastmcp_server import mcp as server
except ImportError:
    print("❌ Error: Could not import 'mcp' from 'fastmcp_server'.")
    sys.exit(1)

# --- HELPER: FIND REGISTRY (Updated for your version) ---
def get_tool_registry(mcp_obj):
    """
    Locates the dictionary where tools are stored.
    Updated to support 'FastMCP._tool_manager'.
    """
    # 1. Check if we have a Tool Manager (New FastMCP structure)
    if hasattr(mcp_obj, "_tool_manager"):
        manager = mcp_obj._tool_manager
        # The manager likely holds the dict in '_tools' or 'tools'
        if hasattr(manager, "_tools"): return manager._tools
        if hasattr(manager, "tools"): return manager.tools
    
    # 2. Check direct attributes (Older FastMCP structure)
    candidates = ["_tool_registry", "tools", "_tools", "registry"]
    for attr in candidates:
        if hasattr(mcp_obj, attr):
            return getattr(mcp_obj, attr)
            
    # 3. Check for wrappers (SecureFastMCP, etc)
    if hasattr(mcp_obj, "mcp"): return get_tool_registry(mcp_obj.mcp)
    if hasattr(mcp_obj, "_mcp"): return get_tool_registry(mcp_obj._mcp)
    
    # If still not found, print available attributes of the manager if it exists
    if hasattr(mcp_obj, "_tool_manager"):
         raise AttributeError(f"Found _tool_manager but could not find tools inside it. Manager attrs: {dir(mcp_obj._tool_manager)}")
    
    raise AttributeError(f"Could not find tool registry. Main object attrs: {dir(mcp_obj)}")

# --- APPLY RESTRICTIONS ---
try:
    # Get the registry dictionary (e.g. { 'tool_name': ToolObject })
    registry = get_tool_registry(server)
    print(f"ℹ️  Found {len(registry)} tools. Applying security filters...")

    tools_to_remove = []
    tools_to_secure = []

    # Identify tools to keep vs remove
    for tool_name, tool_def in registry.items():
        t_name = tool_name.lower()
        
        # Filter Logic
        if not any(svc in t_name for svc in ALLOWED_SERVICES):
            tools_to_remove.append(tool_name)
            continue
        if any(b in t_name for b in BLOCKED_KEYWORDS):
            tools_to_remove.append(tool_name)
            continue
            
        tools_to_secure.append(tool_name)

    # REMOVE tools using the public API if possible, otherwise dict deletion
    # Your log showed 'remove_tool' exists, which is safer!
    for name in tools_to_remove:
        if hasattr(server, "remove_tool"):
            server.remove_tool(name)
        else:
            del registry[name]
    
    print(f"🚫 Removed {len(tools_to_remove)} blocked tools.")

    # SECURE the remaining tools
    for name in tools_to_secure:
        original_tool = registry[name]
        original_func = original_tool.fn

        @wraps(original_func)
        async def secured_proxy_func(*args, **kwargs):
            # Inspect arguments
            try:
                sig = inspect.signature(original_func)
                bound = sig.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                all_args = bound.arguments
            except:
                all_args = kwargs

            # Enforce File IDs
            if ALLOWED_FILE_IDS:
                for key, value in all_args.items():
                    if isinstance(value, str) and ("id" in key.lower() or len(value) > 20):
                        if len(value) > 10 and value not in ALLOWED_FILE_IDS:
                            # Allow simple keywords, block complex IDs
                            print(f"⛔ Blocked access to ID: {value}")
                            raise ValueError(f"⛔ ACCESS DENIED: File ID {value} is not in the allowlist.")

            return await original_func(*args, **kwargs)

        # Update the function reference in the tool definition
        original_tool.fn = secured_proxy_func

    print(f"✅ Secured {len(tools_to_secure)} tools.")

except Exception as e:
    print(f"❌ Critical Error securing tools: {e}")
    # We exit here because if security fails, we shouldn't run unsafe
    sys.exit(1)

# --- RUN SERVER ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    # Run the server on 0.0.0.0 for Cloud Run
    server.run(transport="sse", host="0.0.0.0", port=port)