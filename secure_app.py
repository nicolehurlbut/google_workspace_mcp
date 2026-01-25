import os
import sys
import logging
from functools import wraps
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
    from fastmcp_server import mcp as server
    logger.info("✅ Imported original server.")
except ImportError:
    logger.critical("❌ Could not import 'fastmcp_server'.")
    sys.exit(1)

# --- SECURE TOOLS IN-PLACE ---
def get_tool_registry(obj):
    if hasattr(obj, "_tool_manager"):
        tm = obj._tool_manager
        if hasattr(tm, "_tools"): return tm._tools
        if hasattr(tm, "tools"): return tm.tools
    for attr in ["_tool_registry", "tools", "_tools", "registry"]:
        if hasattr(obj, attr): return getattr(obj, attr)
    if hasattr(obj, "mcp"): return get_tool_registry(obj.mcp)
    return None

try:
    registry = get_tool_registry(server)
    if registry:
        logger.info(f"ℹ️  Found {len(registry)} tools. Securing...")
        to_remove = [n for n in registry if not any(s in n.lower() for s in ALLOWED_SERVICES) or any(b in n.lower() for b in BLOCKED_KEYWORDS)]
        
        for name in to_remove:
            del registry[name]
            
        for name in registry:
            tool = registry[name]
            orig_fn = tool.fn
            @wraps(orig_fn)
            async def secured_proxy(*args, **kwargs):
                if ALLOWED_FILE_IDS:
                    for k,v in kwargs.items():
                        if isinstance(v, str) and "id" in k.lower() and len(v)>5 and v not in ALLOWED_FILE_IDS:
                            raise ValueError(f"⛔ ACCESS DENIED: File ID {v} not allowed.")
                return await orig_fn(*args, **kwargs)
            tool.fn = secured_proxy
            
        logger.info(f"✅ Secured registry. Active tools: {len(registry)}")
except Exception as e:
    logger.warning(f"⚠️ Tool security skipped (registry not found): {e}")

# --- THE INTERCEPTOR (Monkey Patch) ---
# We save the real uvicorn runner
original_uvicorn_run = uvicorn.run

# We define our own runner that wraps the app
def intercepted_run(app, **kwargs):
    logger.info(f"🕸️ Intercepted ASGI App: {type(app)}")
    
    # 1. Define the Google Config
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

    # 2. Wrap the app with Middleware
    async def middleware(scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            
            # SHIM: Serve OIDC Discovery
            if path in ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]:
                logger.info(f"ℹ️  Serving OIDC Config to {path}")
                response = JSONResponse(GOOGLE_CONFIG)
                await response(scope, receive, send)
                return

            # AUTH: Protect /sse
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

        await app(scope, receive, send)

    # 3. Force Cloud Run Settings
    port = int(os.environ.get("PORT", 8080))
    kwargs["host"] = "0.0.0.0"
    kwargs["port"] = port
    
    logger.info(f"🚀 Starting Intercepted Server on {port}")
    return original_uvicorn_run(middleware, **kwargs)

# Apply the patch
uvicorn.run = intercepted_run

# --- RUN ---
if __name__ == "__main__":
    # This call will trigger 'intercepted_run' automatically
    server.run(transport="sse")