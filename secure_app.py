import os
import sys
import logging
import inspect
from functools import wraps
from fastmcp import FastMCP, Context

# --- LOGGING SETUP ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("secure_proxy")

# --- CONFIGURATION ---
os.environ["MCP_ENABLE_OAUTH21"] = "true"
os.environ["EXTERNAL_OAUTH21_PROVIDER"] = "true"
os.environ["WORKSPACE_MCP_STATELESS_MODE"] = "true"

ALLOWED_SERVICES = ["drive", "sheet", "doc", "slide", "form"]
BLOCKED_KEYWORDS = ["create", "update", "delete", "modify", "append", "write", "trash", "upload"]
ALLOWED_FILE_IDS = [
    id.strip() for id in os.environ.get("ALLOWED_FILE_IDS", "").split(",") 
    if id.strip()
]

# --- IMPORT ORIGINAL SERVER ---
try:
    from fastmcp_server import mcp as original_server
    logger.info("✅ Imported original server.")
except ImportError:
    logger.critical("❌ Could not import 'fastmcp_server'.")
    sys.exit(1)

# --- CREATE NEW STRICT SERVER ---
strict_mcp = FastMCP("Secure Google Workspace")

# --- HELPER: FIND TOOLS ---
def get_all_tools(obj):
    candidates = ["_tool_registry", "tools", "_tools", "registry"]
    for attr in candidates:
        if hasattr(obj, attr):
            val = getattr(obj, attr)
            if isinstance(val, dict) and len(val) > 0: return val
    if hasattr(obj, "_tool_manager"): return get_all_tools(obj._tool_manager)
    if hasattr(obj, "mcp"): return get_all_tools(obj.mcp)
    return {}

# --- TRANSFER & SECURE TOOLS ---
registry = get_all_tools(original_server)
if not registry:
    logger.critical("🛑 CRITICAL: Could not find tools to copy.")
    sys.exit(1)

count = 0
for tool_name, tool_def in registry.items():
    t_name = tool_name.lower()
    
    # 1. Filter
    if not any(svc in t_name for svc in ALLOWED_SERVICES): continue
    if any(b in t_name for b in BLOCKED_KEYWORDS): continue
    
    # 2. Wrap Logic
    original_func = tool_def.fn
    
    # Factory to safely capture closure variables
    def create_secured_func(func):
        @wraps(func)
        async def secured_proxy(*args, **kwargs):
            # Enforce Allowlist for File IDs
            if ALLOWED_FILE_IDS:
                for k, v in kwargs.items():
                    if isinstance(v, str) and "id" in k.lower() and len(v) > 5:
                        if v not in ALLOWED_FILE_IDS:
                            raise ValueError(f"⛔ ACCESS DENIED: File ID {v} not allowed.")
            return await func(*args, **kwargs)
        return secured_proxy

    secured_fn = create_secured_func(original_func)

    # 3. Register on NEW Server (FIXED)
    # We use strict_mcp.tool() as a function that returns a decorator, 
    # then immediately call it with our function.
    try:
        strict_mcp.tool(
            name=tool_name, 
            description=tool_def.description
        )(secured_fn)
        count += 1
    except Exception as e:
        logger.error(f"⚠️ Failed to register tool {tool_name}: {e}")

logger.info(f"✅ Secure Server Ready with {count} tools.")

# --- HANDSHAKE INTERCEPTOR ---
import uvicorn
from starlette.responses import JSONResponse

if __name__ == "__main__":
    original_app = strict_mcp._create_asgi_app()
    
    async def app_wrapper(scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            if path.endswith("/sse"):
                headers = dict(scope.get("headers", []))
                if b"authorization" not in headers:
                    logger.warning("⛔ No Token on /sse - Sending 401")
                    response = JSONResponse(
                        {"error": "Authentication required"}, 
                        status_code=401, 
                        headers={"WWW-Authenticate": "Bearer"}
                    )
                    await response(scope, receive, send)
                    return

        await original_app(scope, receive, send)

    port = int(os.environ.get("PORT", 8080))
    logger.info(f"🚀 Starting STRICT server on port {port}")
    uvicorn.run(app_wrapper, host="0.0.0.0", port=port)