import os
import sys
import logging
from functools import wraps

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

# --- SECURE TOOLS ---
try:
    # Helper to find the registry in different versions of FastMCP
    def get_tool_registry(obj):
        if hasattr(obj, "_tool_manager"): 
            tm = obj._tool_manager
            if hasattr(tm, "_tools"): return tm._tools
            if hasattr(tm, "tools"): return tm.tools
        for attr in ["_tool_registry", "tools", "_tools", "registry"]:
            if hasattr(obj, attr): return getattr(obj, attr)
        return None

    registry = get_tool_registry(server)

    if registry:
        logger.info(f"ℹ️  Found {len(registry)} tools. Applying security...")
        
        # 1. Remove Dangerous Tools
        to_remove = [n for n in registry if not any(s in n.lower() for s in ALLOWED_SERVICES) or any(b in n.lower() for b in BLOCKED_KEYWORDS)]
        for name in to_remove:
            del registry[name]
        
        # 2. Add File ID Checks to Remaining Tools
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
            
        logger.info(f"✅ Security Active. Tools available: {len(registry)}")
    else:
        logger.warning("⚠️ Could not find registry to secure. Running in insecure mode.")

except Exception as e:
    logger.error(f"⚠️ Security setup failed: {e}")

# --- RUN THE SERVER ---
if __name__ == "__main__":
    # CRITICAL FIX: Explicitly tell the server to listen on 0.0.0.0 and port 8080
    # This overrides the default 127.0.0.1:8000 that was causing the crash
    port = int(os.environ.get("PORT", 8080))
    logger.info(f"🚀 Starting Server on 0.0.0.0:{port}")
    
    server.run(transport="sse", host="0.0.0.0", port=port)