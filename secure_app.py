import os
import sys
import logging
import inspect
from functools import wraps
from fastmcp import FastMCP
import uvicorn
from starlette.responses import JSONResponse

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("secure_proxy")

# --- CONFIG ---
os.environ["MCP_ENABLE_OAUTH21"] = "true"
os.environ["EXTERNAL_OAUTH21_PROVIDER"] = "true"
os.environ["WORKSPACE_MCP_STATELESS_MODE"] = "true"

ALLOWED_SERVICES = ["drive", "sheet", "doc", "slide", "form"]
BLOCKED_KEYWORDS = ["create", "update", "delete", "modify", "append", "write", "trash", "upload"]
ALLOWED_FILE_IDS = [
    id.strip() for id in os.environ.get("ALLOWED_FILE_IDS", "").split(",") 
    if id.strip()
]

# --- IMPORT SERVER ---
try:
    # We use the ORIGINAL server object instead of creating a new one
    from fastmcp_server import mcp as server
    logger.info("✅ Imported original server.")
except ImportError:
    logger.critical("❌ Could not import 'fastmcp_server'.")
    sys.exit(1)

# --- RECURSIVE TOOL FINDER ---
def get_tool_registry(obj):
    # 1. Check Manager (New FastMCP)
    if hasattr(obj, "_tool_manager"):
        tm = obj._tool_manager
        if hasattr(tm, "_tools"): return tm._tools
        if hasattr(tm, "tools"): return tm.tools
    
    # 2. Check Direct Attributes
    candidates = ["_tool_registry", "tools", "_tools", "registry"]
    for attr in candidates:
        if hasattr(obj, attr):
            return getattr(obj, attr)
            
    # 3. Check Wrappers
    if hasattr(obj, "mcp"): return get_tool_registry(obj.mcp)
    if hasattr(obj, "_mcp"): return get_tool_registry(obj._mcp)
    
    return None

# --- SECURE TOOLS IN-PLACE ---
try:
    registry = get_tool_registry(server)
    if not registry:
        raise Exception("Could not find tool registry")
    
    logger.info(f"ℹ️  Found {len(registry)} tools. Modifying in-place...")
    
    # Identify tools to remove vs secure
    to_remove = []
    to_secure = []

    for name, tool in registry.items():
        t_name = name.lower()
        if not any(s in t_name for s in ALLOWED_SERVICES) or any(b in t_name for b in BLOCKED_KEYWORDS):
            to_remove.append(name)
        else:
            to_secure.append(name)

    # 1. REMOVE TOOLS
    for name in to_remove:
        # We delete directly from the dictionary to be sure
        del registry[name]
    logger.info(f"🚫 Removed {len(to_remove)} blocked tools.")

    # 2. SECURE TOOLS
    for name in to_secure:
        tool_obj = registry[name]
        original_func = tool_obj.fn
        
        # Create wrapper
        @wraps(original_func)
        async def secured_proxy(*args, **kwargs):
            # Enforce Allowlist
            if ALLOWED_FILE_IDS:
                for k, v in kwargs.items():
                    if isinstance(v, str) and "id" in k.lower() and len(v) > 5:
                        if v not in ALLOWED_FILE_IDS:
                            raise ValueError(f"⛔ ACCESS DENIED: File ID {v} not allowed.")
            return await original_func(*args, **kwargs)
        
        # Replace the function ON THE EXISTING TOOL
        tool_obj.fn = secured_proxy

    logger.info(f"✅ Secured {len(to_secure)} tools.")

except Exception as e:
    logger.critical(f"❌ Failed to secure tools: {e}")
    sys.exit(1)

# --- MIDDLEWARE & SHIM ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))

    # Helper to extract the internal ASGI app
    def get_app(obj):
        for m in ["_create_asgi_app", "create_asgi_app", "get_asgi_app"]:
            if hasattr(obj, m): return getattr(obj, m)()
        return getattr(obj, "fastapi_app", None)

    # Get the app from the NOW MODIFIED server
    original_app = get_app(server)
    if not original_app:
        logger.critical("Could not find internal app.")
        sys.exit(1)

    # GOOGLE CONFIG
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

    async def secure_middleware(scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            
            # 1. SHIM: Catch OIDC requests
            if path in ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]:
                logger.info(f"ℹ️  Serving OIDC Config")
                response = JSONResponse(GOOGLE_CONFIG)
                await response(scope, receive, send)
                return

            # 2. AUTH: Protect /sse
            if path.endswith("/sse"):
                headers = dict(scope.get("headers", []))
                if b"authorization" not in headers:
                    logger.warning("⛔ No Token on /sse - Sending 401")
                    response = JSONResponse({"error": "Auth Required"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
                    await response(scope, receive, send)
                    return

        await original_app(scope, receive, send)

    logger.info(f"🚀 Starting In-Place Secured Server on {port}")
    uvicorn.run(secure_middleware, host="0.0.0.0", port=port)