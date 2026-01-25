import os
import sys
import logging
import inspect
from functools import wraps
from fastmcp import FastMCP, Context
import uvicorn
from starlette.responses import JSONResponse
from starlette.routing import Route

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
    if not any(svc in t_name for svc in ALLOWED_SERVICES): continue
    if any(b in t_name for b in BLOCKED_KEYWORDS): continue
    
    original_func = tool_def.fn
    
    def create_secured_func(func):
        @wraps(func)
        async def secured_proxy(*args, **kwargs):
            if ALLOWED_FILE_IDS:
                for k, v in kwargs.items():
                    if isinstance(v, str) and "id" in k.lower() and len(v) > 5:
                        if v not in ALLOWED_FILE_IDS:
                            raise ValueError(f"⛔ ACCESS DENIED: File ID {v} not allowed.")
            return await func(*args, **kwargs)
        return secured_proxy

    secured_fn = create_secured_func(original_func)

    try:
        strict_mcp.tool(name=tool_name, description=tool_def.description)(secured_fn)
        count += 1
    except Exception as e:
        logger.error(f"⚠️ Failed to register tool {tool_name}: {e}")

logger.info(f"✅ Secure Server Ready with {count} tools.")

# --- HELPER: FIND ASGI APP ---
def find_asgi_app(mcp_obj):
    methods = ["_create_asgi_app", "create_asgi_app", "get_asgi_app"]
    for m in methods:
        if hasattr(mcp_obj, m) and callable(getattr(mcp_obj, m)):
            return getattr(mcp_obj, m)()
    attrs = ["app", "_app", "fastapi_app", "http_app"]
    for a in attrs:
        if hasattr(mcp_obj, a):
            return getattr(mcp_obj, a)
    if hasattr(mcp_obj, "_mcp_server"):
        return find_asgi_app(mcp_obj._mcp_server)
    return None

# --- RUN SERVER WITH SHIM ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    
    try:
        original_app = find_asgi_app(strict_mcp)
        if not original_app: raise AttributeError("No App Found")
    except:
        strict_mcp.run(transport="sse", host="0.0.0.0", port=port)
        sys.exit(0)

    # --- IDENTITY SHIM CONFIG ---
    # This tells ChatGPT to use Google for login
    GOOGLE_CONFIG = {
        "issuer": "https://accounts.google.com",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        "response_types_supported": ["code", "token", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile", "https://www.googleapis.com/auth/drive.readonly"]
    }

    async def middleware_and_shim(scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            
            # 1. SHIM: Serve Discovery Files
            if path in ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]:
                logger.info(f"ℹ️  Serving OIDC Config to {path}")
                response = JSONResponse(GOOGLE_CONFIG)
                await response(scope, receive, send)
                return

            # 2. AUTH CHECK: Enforce login on /sse
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

    logger.info(f"🚀 Starting STRICT server with OIDC Shim on port {port}")
    uvicorn.run(middleware_and_shim, host="0.0.0.0", port=port)