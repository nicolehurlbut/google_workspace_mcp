import os
import sys
import logging
import inspect
from functools import wraps
from fastmcp import FastMCP, Context
from fastmcp.exceptions import FastMCPError

# --- LOGGING SETUP ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("secure_proxy")

# --- CONFIGURATION ---
# We enable these to ensure the underlying tools know how to handle tokens
os.environ["MCP_ENABLE_OAUTH21"] = "true"
os.environ["EXTERNAL_OAUTH21_PROVIDER"] = "true"
os.environ["WORKSPACE_MCP_STATELESS_MODE"] = "true"

# Security Allowlist
ALLOWED_SERVICES = ["drive", "sheet", "doc", "slide", "form"]
BLOCKED_KEYWORDS = ["create", "update", "delete", "modify", "append", "write", "trash", "upload"]
ALLOWED_FILE_IDS = [
    id.strip() for id in os.environ.get("ALLOWED_FILE_IDS", "").split(",") 
    if id.strip()
]

# --- IMPORT ORIGINAL TOOLS ---
try:
    from fastmcp_server import mcp as original_server
    logger.info("✅ Imported original server.")
except ImportError:
    logger.critical("❌ Could not import 'fastmcp_server'.")
    sys.exit(1)

# --- CREATE NEW STRICT SERVER ---
# We create a FRESH server to control the handshake logic
strict_mcp = FastMCP("Secure Google Workspace")

# --- HELPER: FIND TOOLS ---
def get_all_tools(obj):
    """Deep scan for tools in the original server object."""
    candidates = ["_tool_registry", "tools", "_tools", "registry"]
    for attr in candidates:
        if hasattr(obj, attr):
            val = getattr(obj, attr)
            if isinstance(val, dict) and len(val) > 0: return val
    
    # Check Managers/Wrappers
    if hasattr(obj, "_tool_manager"): return get_all_tools(obj._tool_manager)
    if hasattr(obj, "mcp"): return get_all_tools(obj.mcp)
    return {}

# --- TRANSFER & SECURE TOOLS ---
registry = get_all_tools(original_server)
if not registry:
    logger.critical("🛑 CRITICAL: Could not find tools to copy.")
    sys.exit(1)

count = 0
for name, tool in registry.items():
    t_name = name.lower()
    
    # 1. Filter
    if not any(s in t_name for s in ALLOWED_SERVICES): continue
    if any(b in t_name for b in BLOCKED_KEYWORDS): continue
    
    # 2. Wrap Logic
    original_func = tool.fn
    
    @wraps(original_func)
    async def secured_proxy(ctx: Context, *args, **kwargs):
        # AUTH CHECK: The token comes in the context
        # In External Mode, we rely on the token being valid.
        # We can add extra validation here if needed.
        
        # FILE ID CHECK
        all_args = kwargs.copy()
        if ALLOWED_FILE_IDS:
            for k, v in all_args.items():
                if isinstance(v, str) and "id" in k.lower() and len(v) > 5:
                    if v not in ALLOWED_FILE_IDS:
                        raise ValueError(f"⛔ ACCESS DENIED: File ID {v} not allowed.")
        
        # Call Original
        # We pass 'ctx' if the original function expects it
        sig = inspect.signature(original_func)
        if "ctx" in sig.parameters:
            return await original_func(ctx=ctx, *args, **kwargs)
        else:
            return await original_func(*args, **kwargs)

    # 3. Register on NEW Server
    strict_mcp.add_tool(
        name=name,
        description=tool.description
    )(secured_proxy)
    count += 1

logger.info(f"✅ Secure Server Ready with {count} tools.")

# --- CUSTOM RUNNER WITH AUTH CHECK ---
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
import uvicorn

# We mount the FastMCP app but intercept the handshake
mcp_app = strict_mcp._create_asgi_app()

async def auth_middleware(request: Request, call_next):
    # Check if this is the SSE connection
    if request.url.path.endswith("/sse"):
        auth_header = request.headers.get("Authorization")
        
        logger.info(f"🔒 Handshake Attempt. Headers: {request.headers.keys()}")
        
        if not auth_header:
            logger.warning("⛔ REJECTING Handshake: No Token Present")
            # Return 401 to tell ChatGPT it needs to login
            return JSONResponse(
                {"error": "Authentication required"}, 
                status_code=401, 
                headers={"WWW-Authenticate": "Bearer"}
            )
        else:
            logger.info("✅ Token Present. Accepting connection.")

    return await call_next(request)

# Create the final app
app = Starlette(middleware=[])
# We have to wrap it manually since Starlette middleware syntax is different
# Ideally, we just run uvicorn on the mcp_app but add the middleware

if __name__ == "__main__":
    # We patch the FastMCP app to include our auth check
    # FastMCP uses Starlette internally.
    original_app = strict_mcp._create_asgi_app()
    
    # Wrap in simple middleware function
    async def app_wrapper(scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            auth = headers.get(b"authorization")
            
            # If hitting /sse and no auth, reject
            path = scope.get("path", "")
            if path.endswith("/sse") and not auth:
                logger.warning("⛔ No Token on /sse - Sending 401")
                response = JSONResponse(
                    {"error": "Missing Authorization Header"}, 
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"}
                )
                await response(scope, receive, send)
                return

        await original_app(scope, receive, send)

    port = int(os.environ.get("PORT", 8080))
    logger.info(f"🚀 Starting STRICT server on port {port}")
    uvicorn.run(app_wrapper, host="0.0.0.0", port=port)