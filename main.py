import asyncio
import json
import os
import hashlib
import secrets
import time
from datetime import datetime
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
import psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("REN-Gateway")

app = FastAPI(title="REN", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connections: dict = {}
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

# XHTTP session queues: uuid -> asyncio.Queue of bytes
XHTTP_QUEUES: dict = {}
XHTTP_QUEUES_LOCK = asyncio.Lock()

SESSION_COOKIE = "ren_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
                logger.info("Keep-alive ping sent")
        except Exception:
            pass

@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    logger.info(f"REN started on port {CONFIG['port']} with XHTTP transport")
    asyncio.create_task(keep_alive())

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def generate_vless_link(uuid: str, remark: str = "REN") -> str:
    domain = get_domain()
    path = f"/xhttp/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "xhttp",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "h2",
        "mode": "auto",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{domain}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            uid = generate_uuid("default")
            LINKS[uid] = {"label": "Default", "limit_bytes": 0, "used_bytes": 0, "created_at": datetime.now().isoformat(), "active": True}

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None: return False
        if not link["active"]: return False
        if link["limit_bytes"] == 0: return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

@app.get("/")
async def root():
    return {"service": "REN", "version": "2.0", "status": "active", "transport": "xhttp", "domain": get_domain()}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": await is_valid_session(token)}

@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "hourly_traffic": dict(hourly_traffic),
    }

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    import re as _re
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    custom_uuid = (body.get("custom_uuid") or "").strip()
    uuid_pattern = _re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
    if custom_uuid:
        if not uuid_pattern.match(custom_uuid):
            raise HTTPException(status_code=400, detail="Invalid UUID format. Expected: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
        uid = custom_uuid.lower()
        async with LINKS_LOCK:
            if uid in LINKS:
                raise HTTPException(status_code=409, detail="UUID already exists")
    else:
        uid = generate_uuid(label)
    async with LINKS_LOCK:
        LINKS[uid] = {"label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "created_at": datetime.now().isoformat(), "active": True}
    return {"uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "active": True, "created_at": LINKS[uid]["created_at"], "vless_link": generate_vless_link(uid, remark=f"REN-{label}")}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({"uuid": uid, "label": data["label"], "limit_bytes": data["limit_bytes"], "used_bytes": data["used_bytes"], "active": data["active"], "created_at": data["created_at"], "vless_link": generate_vless_link(uid, remark=f"REN-{data['label']}")})
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    # Close any active XHTTP sessions for this link
    async with XHTTP_QUEUES_LOCK:
        queue = XHTTP_QUEUES.pop(uid, None)
        if queue:
            await queue.put(None)  # Signal EOF
    return {"ok": True}

# ─────────────────────────────────────────────────
#  XHTTP Transport Implementation
#  VLESS over XHTTP (SplitHTTP / XHTTP)
#
#  Flow:
#  1) Client sends GET /xhttp/{uuid}        → opens long-lived streaming response (server→client)
#  2) Client sends POST /xhttp/{uuid}       → sends data chunks to server (client→server)
#  Each connection identified by X-Padding or session query param
# ─────────────────────────────────────────────────

RELAY_BUF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 0
    pos += 1; pos += 16
    addon_len = first_chunk[pos]; pos += 1; pos += addon_len
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]


class XHTTPSession:
    """Holds state for one XHTTP tunnel session."""
    def __init__(self, uuid: str):
        self.uuid = uuid
        self.conn_id = secrets.token_urlsafe(8)
        # Data going to client (server→client)
        self.to_client: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=512)
        # Data received from client (client→server)
        self.from_client: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=512)
        self.tcp_reader: asyncio.StreamReader | None = None
        self.tcp_writer: asyncio.StreamWriter | None = None
        self.started = False
        self.closed = False
        self.created_at = datetime.now().isoformat()

# session_id -> XHTTPSession
XHTTP_SESSIONS: dict[str, XHTTPSession] = {}
XHTTP_SESSIONS_LOCK = asyncio.Lock()


async def xhttp_tcp_relay(session: XHTTPSession):
    """Relay data between TCP target and the XHTTP queues."""
    uuid = session.uuid
    try:
        # Wait for first data from client (contains VLESS header)
        first_chunk = await asyncio.wait_for(session.from_client.get(), timeout=15.0)
        if first_chunk is None:
            return

        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        size = len(first_chunk)
        stats["total_bytes"] += size
        stats["total_requests"] += 1
        hourly_traffic[datetime.now().strftime("%H:00")] += size
        await add_usage(uuid, size)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )
        session.tcp_reader = reader
        session.tcp_writer = writer

        connections[session.conn_id] = {
            "uuid": uuid, "connected_at": session.created_at,
            "bytes": 0, "target": f"{address}:{port}"
        }
        logger.info(f"[XHTTP] {session.conn_id} → {address}:{port}")

        # Send VLESS response header (0x00 + 0x00) then initial payload
        await session.to_client.put(b"\x00\x00")

        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            connections[session.conn_id]["bytes"] += p_size
            hourly_traffic[datetime.now().strftime("%H:00")] += p_size
            await add_usage(uuid, p_size)
            writer.write(initial_payload)
            await writer.drain()

        async def client_to_tcp():
            try:
                while not session.closed:
                    try:
                        data = await asyncio.wait_for(session.from_client.get(), timeout=60.0)
                    except asyncio.TimeoutError:
                        continue
                    if data is None:
                        break
                    size = len(data)
                    if not await check_quota(uuid, size):
                        break
                    stats["total_bytes"] += size
                    connections.get(session.conn_id, {})["bytes"] = connections.get(session.conn_id, {}).get("bytes", 0) + size
                    hourly_traffic[datetime.now().strftime("%H:00")] += size
                    await add_usage(uuid, size)
                    writer.write(data)
                    await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.write_eof()
                except Exception:
                    pass

        async def tcp_to_client():
            first = True
            try:
                while not session.closed:
                    data = await reader.read(RELAY_BUF)
                    if not data:
                        break
                    size = len(data)
                    if not await check_quota(uuid, size):
                        break
                    stats["total_bytes"] += size
                    connections.get(session.conn_id, {})["bytes"] = connections.get(session.conn_id, {}).get("bytes", 0) + size
                    hourly_traffic[datetime.now().strftime("%H:00")] += size
                    await add_usage(uuid, size)
                    await session.to_client.put(data)
                    first = False
            except Exception:
                pass
            finally:
                await session.to_client.put(None)  # EOF signal

        task_up = asyncio.create_task(client_to_tcp())
        task_down = asyncio.create_task(tcp_to_client())
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()

    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"[XHTTP] relay error: {exc}")
    finally:
        session.closed = True
        await session.to_client.put(None)
        if session.tcp_writer:
            try:
                session.tcp_writer.close()
            except Exception:
                pass
        connections.pop(session.conn_id, None)
        async with XHTTP_SESSIONS_LOCK:
            XHTTP_SESSIONS.pop(session.conn_id, None)


@app.get("/xhttp/{uuid}")
async def xhttp_downstream(uuid: str, request: Request, sid: str = ""):
    """
    Client opens GET to receive data stream (server → client).
    Returns chunked HTTP response streaming bytes.
    """
    await ensure_default_link()

    if not await check_quota(uuid, 0):
        raise HTTPException(status_code=403, detail="quota exceeded or link disabled")

    # Use sid query param or X-Padding header as session identifier
    session_id = sid or request.headers.get("x-padding", "") or secrets.token_urlsafe(8)

    async with XHTTP_SESSIONS_LOCK:
        session = XHTTP_SESSIONS.get(session_id)
        if session is None:
            session = XHTTPSession(uuid)
            session.conn_id = session_id
            XHTTP_SESSIONS[session_id] = session
            # Start TCP relay coroutine
            asyncio.create_task(xhttp_tcp_relay(session))

    async def generate():
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(session.to_client.get(), timeout=120.0)
                except asyncio.TimeoutError:
                    # Send keepalive empty bytes
                    yield b""
                    continue
                if chunk is None:
                    break
                yield chunk
        except Exception:
            pass

    return StreamingResponse(
        generate(),
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
            "Transfer-Encoding": "chunked",
        },
    )


@app.post("/xhttp/{uuid}")
async def xhttp_upstream(uuid: str, request: Request, sid: str = ""):
    """
    Client sends POST with binary body (client → server data).
    """
    await ensure_default_link()

    if not await check_quota(uuid, 0):
        raise HTTPException(status_code=403, detail="quota exceeded or link disabled")

    session_id = sid or request.headers.get("x-padding", "") or ""

    if not session_id:
        raise HTTPException(status_code=400, detail="missing session id")

    async with XHTTP_SESSIONS_LOCK:
        session = XHTTP_SESSIONS.get(session_id)
        if session is None:
            # GET hasn't arrived yet – create session and wait for relay
            session = XHTTPSession(uuid)
            session.conn_id = session_id
            XHTTP_SESSIONS[session_id] = session
            asyncio.create_task(xhttp_tcp_relay(session))

    body = await request.body()
    if body:
        try:
            await asyncio.wait_for(session.from_client.put(body), timeout=10.0)
        except asyncio.TimeoutError:
            raise HTTPException(status_code=503, detail="session buffer full")

    return Response(status_code=200, content=b"", media_type="application/octet-stream")


LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REN</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
html[data-theme="dark"]{--bg:#0a0a0a;--surface:#141414;--surface2:#1c1c1c;--border:rgba(255,255,255,0.06);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#dc2626;--primary-glow:rgba(220,38,38,0.15);--accent:#991b1b;--error:#ef4444;--error-bg:rgba(239,68,68,0.08)}
html[data-theme="light"]{--bg:#ffffff;--surface:#ffffff;--surface2:#f9fafb;--border:rgba(0,0,0,0.06);--text:rgba(0,0,0,0.88);--text2:rgba(0,0,0,0.5);--text3:rgba(0,0,0,0.25);--primary:#16a34a;--primary-glow:rgba(22,163,74,0.12);--accent:#15803d;--error:#dc2626;--error-bg:rgba(220,38,38,0.06)}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);transition:background .3s,color .3s}
.toolbar{position:fixed;top:20px;right:20px;display:flex;gap:6px;z-index:10}
.toolbar button{width:36px;height:36px;border-radius:10px;border:1px solid var(--border);background:var(--surface);color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:15px;transition:all .2s}
.toolbar button:hover{border-color:var(--primary);color:var(--primary)}
.login-page{width:100%;max-width:380px;padding:0 20px}
.login-card{background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:44px 36px 36px;position:relative;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)}
.login-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--primary)}
.brand{text-align:center;margin-bottom:36px}
.brand svg{margin-bottom:20px}
.brand h1{font-size:20px;font-weight:700;color:var(--text);letter-spacing:-0.02em}
.brand p{font-size:12px;color:var(--text3);margin-top:6px;font-weight:500;letter-spacing:0.04em;text-transform:uppercase}
.form-group{margin-bottom:20px}
.form-group label{display:block;font-size:12px;font-weight:600;color:var(--text2);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.04em}
.form-group input{width:100%;padding:11px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:14px;font-family:inherit;outline:none;transition:all .2s}
.form-group input:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow)}
.form-group input::placeholder{color:var(--text3)}
.login-btn{width:100%;padding:12px;background:var(--primary);border:none;border-radius:10px;color:#fff;font-size:14px;font-weight:600;font-family:inherit;cursor:pointer;transition:all .2s;letter-spacing:0.01em}
.login-btn:hover{filter:brightness(1.1);transform:translateY(-1px)}
.error-msg{background:var(--error-bg);border:1px solid rgba(255,77,106,0.15);color:var(--error);padding:10px 14px;border-radius:10px;font-size:13px;display:none;margin-bottom:20px;text-align:center;font-weight:500}
.error-msg.show{display:block}
</style>
</head>
<body>
<div class="toolbar">
  <button id="lang-toggle" onclick="cycleLang()" title="Language">EN</button>
  <button id="theme-toggle" onclick="toggleTheme()" title="Theme">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
  </button>
</div>
<div class="login-page">
  <div class="login-card">
    <div class="brand">
      <svg width="56" height="56" viewBox="0 0 56 56" fill="none">
        <rect width="56" height="56" rx="14" fill="url(#logo-grad)"/>
        <circle cx="28" cy="28" r="14" stroke="#fff" stroke-width="1.5" opacity="0.3"/>
        <circle cx="28" cy="18" r="3.5" fill="#fff"/>
        <circle cx="19" cy="33" r="3.5" fill="#fff"/>
        <circle cx="37" cy="33" r="3.5" fill="#fff"/>
        <line x1="28" y1="21.5" x2="21" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <line x1="28" y1="21.5" x2="35" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <line x1="22.5" y1="33" x2="33.5" y2="33" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <circle cx="28" cy="28" r="2" fill="#fff" opacity="0.9"/>
        <defs><linearGradient id="logo-grad" x1="0" y1="0" x2="56" y2="56"><stop stop-color="#dc2626"/><stop offset="1" stop-color="#991b1b"/></linearGradient></defs>
      </svg>
      <h1>REN</h1>
      <p>v2.0 · XHTTP</p>
    </div>
    <div class="error-msg" id="err-box"></div>
    <form id="login-form">
      <div class="form-group">
        <label data-en="Password" data-fa="رمز عبور">Password</label>
        <input type="password" id="password" placeholder="Enter password" autofocus>
      </div>
      <button type="submit" class="login-btn" data-en="Sign In" data-fa="ورود">Sign In</button>
    </form>
  </div>
</div>
<script>
let lang=localStorage.getItem('ren_lang')||'en';
let theme=localStorage.getItem('ren_theme')||'dark';
function setLang(l){lang=l;document.body.dir=l==='fa'?'rtl':'ltr';document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v});document.getElementById('lang-toggle').textContent=l.toUpperCase();localStorage.setItem('ren_lang',l)}
function cycleLang(){setLang(lang==='en'?'fa':'en')}
function applyTheme(t){theme=t;document.documentElement.setAttribute('data-theme',t);localStorage.setItem('ren_theme',t)}
function toggleTheme(){applyTheme(theme==='dark'?'light':'dark')}
applyTheme(theme);setLang(lang);
document.getElementById('login-form').addEventListener('submit',async e=>{
  e.preventDefault();const err=document.getElementById('err-box');err.classList.remove('show');
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('password').value})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Failed');}
    location.href='/dashboard';
  }catch(e){err.textContent=e.message;err.classList.add('show')}
});
</script>
</body>
</html>"""


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REN</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html[data-theme="dark"]{--bg:#0a0a0a;--surface:#141414;--surface2:#1c1c1c;--surface3:#2a2a2a;--border:rgba(255,255,255,0.06);--border2:rgba(255,255,255,0.1);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#dc2626;--primary-glow:rgba(220,38,38,0.15);--primary-dim:rgba(220,38,38,0.1);--accent:#991b1b;--green:#22c55e;--green-dim:rgba(34,197,94,0.1);--red:#ef4444;--red-dim:rgba(239,68,68,0.08);--yellow:#fbbf24;--sidebar-bg:#0f0f0f;--shadow:0 1px 3px rgba(0,0,0,0.4)}
html[data-theme="light"]{--bg:#ffffff;--surface:#ffffff;--surface2:#f9fafb;--surface3:#f3f4f6;--border:rgba(0,0,0,0.06);--border2:rgba(0,0,0,0.1);--text:rgba(0,0,0,0.88);--text2:rgba(0,0,0,0.5);--text3:rgba(0,0,0,0.25);--primary:#16a34a;--primary-glow:rgba(22,163,74,0.1);--primary-dim:rgba(22,163,74,0.06);--accent:#15803d;--green:#16a34a;--green-dim:rgba(22,163,74,0.06);--red:#dc2626;--red-dim:rgba(220,38,38,0.06);--yellow:#d97706;--sidebar-bg:#ffffff;--shadow:0 1px 3px rgba(0,0,0,0.06)}
html,body{height:100%}
body{font-family:'Inter','Vazirmatn',-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;transition:background .3s,color .3s}
body[dir="rtl"]{direction:rtl;text-align:right}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
.sidebar{width:220px;background:var(--sidebar-bg);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;transition:background .3s}
.sidebar-brand{padding:16px 16px 14px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border)}
.sidebar-brand-left{display:flex;align-items:center;gap:10px}
.sidebar-brand-left .brand-name{font-size:15px;font-weight:700;color:var(--text);letter-spacing:-0.02em}
.sidebar-brand-right{display:flex;gap:4px}
.sidebar-brand-right button{width:28px;height:28px;border-radius:7px;border:1px solid var(--border);background:var(--surface);color:var(--text3);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:12px;transition:all .2s}
.sidebar-brand-right button:hover{border-color:var(--primary);color:var(--primary)}
.sidebar-nav{flex:1;padding:8px;overflow-y:auto}
.nav-section{font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.08em;padding:14px 12px 6px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 12px;margin:1px 0;border-radius:8px;color:var(--text2);font-size:13px;font-weight:500;cursor:pointer;transition:all .15s;text-decoration:none;border:none;background:none;width:100%;text-align:left}
.nav-item:hover{background:var(--primary-dim);color:var(--text)}
.nav-item.active{background:var(--primary-dim);color:var(--primary);font-weight:600}
.nav-icon{width:18px;height:18px;flex-shrink:0;opacity:0.7}
.nav-item.active .nav-icon{opacity:1}
.nav-badge{margin-left:auto;background:var(--surface3);color:var(--text3);font-size:10px;padding:2px 7px;border-radius:8px;font-weight:600}
.sidebar-footer{padding:12px;border-top:1px solid var(--border)}
.sidebar-footer .footer-row{display:flex;gap:4px;margin-bottom:8px}
.sidebar-footer .footer-btn{flex:1;padding:6px;border:1px solid var(--border);border-radius:7px;background:var(--surface);color:var(--text3);font-family:inherit;font-size:11px;font-weight:600;cursor:pointer;transition:all .2s;text-align:center}
.sidebar-footer .footer-btn.active{background:var(--primary);color:#fff;border-color:var(--primary)}
.sidebar-footer .footer-btn:hover:not(.active){border-color:var(--border2);color:var(--text2)}
.sidebar-footer .logout-btn{width:100%;padding:7px;border:1px solid var(--border);border-radius:7px;background:none;color:var(--text3);font-family:inherit;font-size:11px;font-weight:600;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:6px}
.sidebar-footer .logout-btn:hover{background:var(--red-dim);border-color:rgba(255,77,106,0.2);color:var(--red)}
.sidebar-footer .version{text-align:center;font-size:10px;color:var(--text3);margin-top:8px;letter-spacing:0.02em}
.main{margin-left:220px;flex:1;padding:24px 28px 48px;min-height:100vh}
.page{display:none}.page.active{display:block}
.page-header{margin-bottom:20px;display:flex;align-items:center;justify-content:space-between}
.page-title{font-size:18px;font-weight:700;color:var(--text);letter-spacing:-0.01em}
.page-sub{font-size:12px;color:var(--text3);margin-top:3px}
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 18px}
.stat-label{font-size:11px;color:var(--text3);font-weight:600;text-transform:uppercase;letter-spacing:0.04em;margin-bottom:8px}
.stat-value{font-size:22px;font-weight:700;color:var(--text);letter-spacing:-0.02em}
.stat-unit{font-size:12px;font-weight:400;color:var(--text3)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:12px}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.card-title{font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px;color:var(--text)}
.btn{font-family:inherit;font-size:12px;font-weight:600;border-radius:8px;padding:7px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:all .15s}
.btn-primary{background:var(--primary);color:#fff}
.btn-primary:hover{filter:brightness(1.1)}
.btn-secondary{background:var(--surface3);color:var(--text2);border:1px solid var(--border)}
.btn-secondary:hover{border-color:var(--primary);color:var(--primary)}
.btn-danger{background:var(--red-dim);color:var(--red);border:1px solid rgba(255,77,106,0.12)}
.btn-danger:hover{background:rgba(255,77,106,0.15)}
.btn-sm{padding:5px 10px;font-size:11px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.table-wrap{overflow-x:auto}
.table{width:100%;border-collapse:collapse}
.table th{text-align:left;font-size:11px;font-weight:600;color:var(--text3);padding:10px 12px;text-transform:uppercase;letter-spacing:0.04em;border-bottom:1px solid var(--border);background:var(--surface2)}
.table td{padding:10px 12px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:middle}
.table tr:last-child td{border-bottom:none}
.table tbody tr:hover td{background:var(--primary-dim)}
.tag{display:inline-flex;align-items:center;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;letter-spacing:0.03em;text-transform:uppercase}
.tag-vless{background:var(--primary-dim);color:var(--primary)}
.tag-xhttp{background:rgba(59,130,246,0.12);color:#3b82f6}
.tag-active{background:var(--green-dim);color:var(--green)}
.tag-disabled{background:var(--red-dim);color:var(--red)}
.usage-pill{display:flex;align-items:center;gap:8px;padding:3px 10px;border-radius:999px;background:var(--surface3);font-size:11px;color:var(--text2)}
.usage-pill .used{color:var(--text);font-weight:600}
.usage-pill .bar{flex:1;height:4px;background:var(--bg);border-radius:2px;min-width:50px}
.usage-pill .fill{height:100%;border-radius:2px;transition:width .3s}
.usage-pill .limit{color:var(--text3)}
.toggle{width:34px;height:18px;border-radius:10px;background:var(--surface3);position:relative;cursor:pointer;transition:all .2s;border:1px solid var(--border)}
.toggle::after{content:'';position:absolute;width:12px;height:12px;border-radius:50%;background:var(--text3);top:2px;left:2px;transition:all .2s}
.toggle.on{background:var(--green);border-color:var(--green)}
.toggle.on::after{left:18px;background:#fff}
.sys-bar{height:6px;background:var(--surface3);border-radius:3px;overflow:hidden}
.sys-bar-fill{height:100%;border-radius:3px;transition:width .4s}
.status-item{display:flex;align-items:center;justify-content:space-between;padding:11px 0;border-bottom:1px solid var(--border)}
.status-item:last-child{border-bottom:none}
.status-key{color:var(--text2);font-size:12px;display:flex;align-items:center;gap:8px}
.status-val{color:var(--text);font-weight:600;font-size:12px}
.form-group{display:flex;flex-direction:column;gap:5px;margin-bottom:12px}
.form-label{font-size:11px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:0.04em}
.form-input,.form-select{padding:8px 12px;border-radius:8px;border:1px solid var(--border);font-family:inherit;font-size:13px;outline:none;color:var(--text);background:var(--surface2);transition:all .2s}
.form-input:focus,.form-select:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow)}
.form-row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.form-row .form-group{margin-bottom:0;flex:1;min-width:100px}
.empty{text-align:center;padding:40px 16px;color:var(--text3)}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(20px);background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:10px;padding:10px 20px;font-size:12px;font-weight:500;opacity:0;transition:all .25s;z-index:999;display:flex;align-items:center;gap:8px;box-shadow:0 8px 24px rgba(0,0,0,0.2)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.error{border-color:var(--red-dim);color:var(--red)}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(6px)}
.modal-overlay.show{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;width:100%;max-width:460px;position:relative;box-shadow:0 20px 60px rgba(0,0,0,0.3);transform:scale(0.9);opacity:0;transition:all .3s cubic-bezier(0.34,1.56,0.64,1)}
.modal-overlay.show .modal{transform:scale(1);opacity:1}
.modal-title{font-size:15px;font-weight:700;margin-bottom:18px;color:var(--text)}
.modal-close{position:absolute;top:12px;left:12px;background:var(--surface3);border:1px solid var(--border);color:var(--text3);width:28px;height:28px;border-radius:7px;cursor:pointer;font-size:12px;display:flex;align-items:center;justify-content:center;transition:all .2s}
.modal-close:hover{background:var(--red-dim);color:var(--red);border-color:rgba(255,77,106,0.2)}
.qr-box{text-align:center;padding:24px;background:var(--surface2);border-radius:14px;margin-top:14px;border:1px solid var(--border)}
.qr-box img{max-width:220px;border-radius:10px;border:3px solid var(--surface)}
.detail-label{font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:5px}
.detail-value{padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;font-size:12px;color:var(--text2);word-break:break-all;font-family:'SF Mono',Monaco,Consolas,monospace;line-height:1.6}
.detail-row{display:flex;gap:12px;margin-bottom:12px}
.detail-row .detail-col{flex:1}
.detail-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:14px}
.inbounds-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.search-box{flex:1;min-width:180px;position:relative}
.search-box input{width:100%;padding:8px 12px 8px 32px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;font-family:inherit;outline:none;transition:all .2s}
.search-box input:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow)}
.search-box svg{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--text3)}
.filter-chips{display:flex;gap:3px;padding:3px 5px;background:var(--surface2);border:1px solid var(--border);border-radius:8px}
.chip{padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;color:var(--text3);cursor:pointer;border:none;background:none;transition:all .2s;font-family:inherit}
.chip.active{background:var(--primary);color:#fff}
.chip:hover:not(.active){background:var(--surface3);color:var(--text2)}
.inbound-cards{display:none;flex-direction:column;gap:8px;padding:0 4px}
.inbound-card{border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--surface2);display:flex;flex-direction:column;gap:8px}
.inbound-card-header{display:flex;align-items:center;justify-content:space-between}
.inbound-card-id{font-size:10px;color:var(--text3);font-weight:600}
.inbound-card-name{font-size:13px;font-weight:600;color:var(--text)}
.inbound-card-actions{display:flex;gap:4px;justify-content:flex-end}
.mobile-header{display:none;position:fixed;top:0;left:0;right:0;height:44px;background:var(--sidebar-bg);border-bottom:1px solid var(--border);z-index:90;align-items:center;justify-content:space-between;padding:0 14px}
.menu-toggle{width:32px;height:32px;border-radius:8px;border:1px solid var(--border);background:var(--surface);color:var(--text2);display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:14px}
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:99}
.sidebar-overlay.show{display:block}
.btn-copy{background:var(--primary-dim);color:var(--primary);border:1px solid rgba(220,38,38,0.15);font-family:inherit;font-size:11px;font-weight:600;border-radius:8px;padding:5px 10px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;transition:all .2s}
.btn-copy:hover{background:var(--primary);color:#fff}
.btn-qr{background:var(--green-dim);color:var(--green);border:1px solid rgba(34,197,94,0.15);font-family:inherit;font-size:11px;font-weight:600;border-radius:8px;padding:5px 10px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;transition:all .2s}
.btn-qr:hover{background:var(--green);color:#fff}
@media(max-width:768px){
  .sidebar{transform:translateX(-100%);width:220px;z-index:200}
  .sidebar.open{transform:translateX(0);box-shadow:4px 0 20px rgba(0,0,0,0.4)}
  .main{margin-left:0;padding-top:60px;padding-left:12px;padding-right:12px}
  .mobile-header{display:flex}
  .stats-row{grid-template-columns:1fr 1fr}
  .grid-2{grid-template-columns:1fr}
  .table-wrap{display:none}
  .inbound-cards{display:flex}
}
@media(max-width:480px){.stats-row{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="toast" id="toast"></div>
<div class="mobile-header">
  <span style="font-weight:700;font-size:13px">REN</span>
  <button class="menu-toggle" onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebar-overlay').classList.toggle('show')">&#9776;</button>
</div>
<div class="sidebar-overlay" id="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('show')"></div>
<aside class="sidebar" id="sidebar">
  <div class="sidebar-brand">
    <div class="sidebar-brand-left">
      <svg width="28" height="28" viewBox="0 0 56 56" fill="none">
        <rect width="56" height="56" rx="14" fill="url(#lg)"/>
        <circle cx="28" cy="28" r="14" stroke="#fff" stroke-width="1.5" opacity="0.3"/>
        <circle cx="28" cy="18" r="3.5" fill="#fff"/>
        <circle cx="19" cy="33" r="3.5" fill="#fff"/>
        <circle cx="37" cy="33" r="3.5" fill="#fff"/>
        <line x1="28" y1="21.5" x2="21" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <line x1="28" y1="21.5" x2="35" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <line x1="22.5" y1="33" x2="33.5" y2="33" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <circle cx="28" cy="28" r="2" fill="#fff" opacity="0.9"/>
        <defs><linearGradient id="lg" x1="0" y1="0" x2="56" y2="56"><stop stop-color="#dc2626"/><stop offset="1" stop-color="#991b1b"/></linearGradient></defs>
      </svg>
      <span class="brand-name">REN</span>
    </div>
    <div class="sidebar-brand-right">
      <button onclick="toggleTheme()" id="theme-btn" title="Toggle theme">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
      </button>
    </div>
  </div>
  <nav class="sidebar-nav">
    <div class="nav-section">Main</div>
    <button class="nav-item active" data-page="dashboard">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
      <span data-en="Dashboard" data-fa="داشبورد">Dashboard</span>
    </button>
    <button class="nav-item" data-page="inbounds">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
      <span data-en="Inbounds" data-fa="اینباندها">Inbounds</span>
      <span class="nav-badge" id="links-badge">0</span>
    </button>
    <button class="nav-item" data-page="traffic">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      <span data-en="Traffic" data-fa="ترافیک">Traffic</span>
    </button>
    <div class="nav-section">System</div>
    <button class="nav-item" data-page="security">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
      <span data-en="Security" data-fa="امنیت">Security</span>
    </button>
  </nav>
  <div class="sidebar-footer">
    <div class="footer-row">
      <button class="footer-btn active" onclick="setLang('en')" id="lang-en">EN</button>
      <button class="footer-btn" onclick="setLang('fa')" id="lang-fa">FA</button>
    </div>
    <button class="logout-btn" onclick="fetch('/api/logout',{method:'POST'}).then(()=>location.href='/login')">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      <span data-en="Logout" data-fa="خروج">Logout</span>
    </button>
    <div class="version">v2.0 · XHTTP Transport</div>
  </div>
</aside>
<main class="main">
  <section class="page active" id="page-dashboard">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div>
        <div class="page-sub" id="last-update">Updated: --</div>
      </div>
      <div style="display:flex;gap:6px">
        <button class="btn btn-secondary" onclick="quickCreate(0.5,'GB')">+ 0.5 GB</button>
        <button class="btn btn-primary" onclick="quickCreate(1,'GB')">+ 1 GB</button>
      </div>
    </div>
    <div class="stats-row">
      <div class="stat-card">
        <div class="stat-label" data-en="Traffic" data-fa="ترافیک">Traffic</div>
        <div class="stat-value" id="s-traffic">--<span class="stat-unit"> MB</span></div>
      </div>
      <div class="stat-card">
        <div class="stat-label" data-en="Inbounds" data-fa="اینباندها">Inbounds</div>
        <div class="stat-value" id="s-links">--</div>
      </div>
      <div class="stat-card">
        <div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime</div>
        <div class="stat-value" id="s-uptime" style="font-size:16px">--</div>
      </div>
      <div class="stat-card">
        <div class="stat-label" data-en="Domain" data-fa="دامنه">Domain</div>
        <div class="stat-value" id="s-domain" style="font-size:11px;word-break:break-all;font-weight:500">--</div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-header"><div class="card-title">CPU</div><span id="s-cpu-val" style="font-size:18px;font-weight:700;color:var(--primary)">--%</span></div>
        <div class="sys-bar"><div class="sys-bar-fill" id="s-cpu-bar" style="width:0%;background:var(--primary)"></div></div>
      </div>
      <div class="card">
        <div class="card-header"><div class="card-title">Memory</div><span id="s-mem-val" style="font-size:18px;font-weight:700;color:var(--green)">--%</span></div>
        <div class="sys-bar"><div class="sys-bar-fill" id="s-mem-bar" style="width:0%;background:var(--green)"></div></div>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title">Hourly Traffic</div></div>
      <div style="height:180px"><canvas id="trafficChart"></canvas></div>
    </div>
  </section>
  <section class="page" id="page-inbounds">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Inbounds" data-fa="اینباندها">Inbounds</div>
        <div class="page-sub">VLESS · XHTTP Transport · TLS</div>
      </div>
      <button class="btn btn-primary" onclick="showAddModal()">+ Add</button>
    </div>
    <div class="inbounds-toolbar">
      <div class="search-box">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input id="inbound-search" placeholder="Search by name or UUID..." oninput="filterInbounds()">
      </div>
      <div class="filter-chips">
        <button class="chip active" onclick="setFilter('all',this)">All</button>
        <button class="chip" onclick="setFilter('active',this)">Active</button>
        <button class="chip" onclick="setFilter('disabled',this)">Disabled</button>
      </div>
    </div>
    <div class="card" style="border-radius:12px;overflow:hidden;padding:0">
      <div class="table-wrap">
        <table class="table">
          <thead><tr>
            <th style="width:32px">#</th>
            <th>Remark</th>
            <th style="width:80px">Transport</th>
            <th>Traffic</th>
            <th style="width:64px">Status</th>
            <th style="width:120px">Actions</th>
          </tr></thead>
          <tbody id="links-tbody"></tbody>
        </table>
      </div>
      <div class="inbound-cards" id="inbound-cards"></div>
      <div class="empty" id="links-empty" style="display:none">
        <div style="font-size:32px;margin-bottom:10px;opacity:0.3">○</div>
        <div>No inbounds found</div>
      </div>
    </div>
  </section>
  <section class="page" id="page-traffic">
    <div class="page-header"><div><div class="page-title">Traffic</div><div class="page-sub">Traffic statistics</div></div></div>
    <div class="card">
      <div class="card-header"><div class="card-title">Overview</div></div>
      <div class="status-item"><span class="status-key">Total Traffic</span><span class="status-val" id="t-traffic">-- MB</span></div>
      <div class="status-item"><span class="status-key">Total Requests</span><span class="status-val" id="t-reqs">--</span></div>
      <div class="status-item"><span class="status-key">Uptime</span><span class="status-val" id="t-uptime">--</span></div>
    </div>
  </section>
  <section class="page" id="page-security">
    <div class="page-header"><div><div class="page-title">Security</div><div class="page-sub">Change panel password</div></div></div>
    <div class="card" style="max-width:400px">
      <div class="form-group">
        <label class="form-label">Current Password</label>
        <input class="form-input" type="password" id="cur-pw" placeholder="Enter current password">
      </div>
      <div class="form-group">
        <label class="form-label">New Password</label>
        <input class="form-input" type="password" id="new-pw" placeholder="Min 4 characters">
      </div>
      <button class="btn btn-primary" onclick="changePassword()" style="margin-top:4px">Update Password</button>
    </div>
  </section>
</main>

<div class="modal-overlay" id="add-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="position:relative">
    <button class="modal-close" onclick="document.querySelector('#add-modal').classList.remove('show')">x</button>
    <div class="modal-title">Add Inbound</div>
    <div class="form-group">
      <label class="form-label">Remark</label>
      <input class="form-input" id="new-label" placeholder="e.g. User 1">
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1">
        <label class="form-label">Traffic Limit</label>
        <input class="form-input" id="new-limit" type="number" min="0" step="0.1" placeholder="0 = Unlimited">
      </div>
      <div class="form-group" style="min-width:80px;max-width:100px">
        <label class="form-label">Unit</label>
        <select class="form-select" id="new-unit"><option value="GB">GB</option></select>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label" style="display:flex;align-items:center;justify-content:space-between">
        <span>UUID <span style="font-weight:400;color:var(--text3);text-transform:none;font-size:10px">(optional)</span></span>
        <button type="button" onclick="generateAndFillUUID()" style="background:none;border:1px solid var(--border);border-radius:6px;color:var(--text2);font-size:10px;padding:2px 8px;cursor:pointer;letter-spacing:0;text-transform:none;font-family:inherit">Generate</button>
      </label>
      <input class="form-input" id="new-uuid" placeholder="Leave empty to auto-generate" style="font-family:monospace;font-size:12px" oninput="validateUUIDInput(this)">
      <div id="uuid-error" style="color:var(--red);font-size:11px;margin-top:4px;display:none">Invalid format. Expected: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx</div>
    </div>
    <button class="btn btn-primary" onclick="createLink()" style="width:100%;margin-top:8px;justify-content:center">Create</button>
  </div>
</div>

<div class="modal-overlay" id="detail-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="position:relative;max-width:540px">
    <button class="modal-close" onclick="document.querySelector('#detail-modal').classList.remove('show')">x</button>
    <div class="modal-title" id="detail-title">Inbound Details</div>
    <div id="detail-content"></div>
  </div>
</div>

<div class="modal-overlay" id="qr-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="position:relative">
    <button class="modal-close" onclick="document.querySelector('#qr-modal').classList.remove('show')">x</button>
    <div class="modal-title">QR Code</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR"></div>
    <div style="margin-top:14px;text-align:center;display:flex;gap:8px;justify-content:center">
      <button class="btn btn-primary btn-sm" onclick="downloadQR()" style="padding:8px 20px">Download</button>
      <button class="btn btn-secondary btn-sm" onclick="document.querySelector('#qr-modal').classList.remove('show')" style="padding:8px 20px">Close</button>
    </div>
  </div>
</div>

<script>
let lang=localStorage.getItem('ren_lang')||'en';
let theme=localStorage.getItem('ren_theme')||'dark';
let allLinks=[];let currentFilter='all';let statsData={};let trafficChart=null;

function setLang(l){lang=l;document.getElementById('lang-en').classList.toggle('active',l==='en');document.getElementById('lang-fa').classList.toggle('active',l==='fa');document.body.dir=l==='fa'?'rtl':'ltr';document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v});localStorage.setItem('ren_lang',l)}
function applyTheme(t){theme=t;document.documentElement.setAttribute('data-theme',t);localStorage.setItem('ren_theme',t)}
function toggleTheme(){applyTheme(theme==='dark'?'light':'dark')}
function showAddModal(){document.querySelector('#add-modal').classList.add('show')}
function setFilter(f,el){currentFilter=f;document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));el.classList.add('active');filterInbounds()}
function filterInbounds(){const q=(document.querySelector('#inbound-search')?.value||'').toLowerCase();let filtered=allLinks;if(currentFilter==='active')filtered=filtered.filter(l=>l.active);if(currentFilter==='disabled')filtered=filtered.filter(l=>!l.active);if(q)filtered=filtered.filter(l=>l.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));renderLinks(filtered)}
function fmtBytes(b){return b>1073741824?(b/1073741824).toFixed(2)+' GB':b>1048576?(b/1048576).toFixed(2)+' MB':(b/1024).toFixed(1)+' KB'}
function fmtLimit(b){if(b===0)return'Unlimited';const gb=b/1073741824;return(gb%1===0?gb.toFixed(0):gb.toFixed(1))+' GB'}
function esc(s){return String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function toast(msg,err=false){const t=document.querySelector('#toast');t.textContent=msg;t.className='toast'+(err?' error':'')+' show';setTimeout(()=>t.classList.remove('show'),3000)}

document.querySelectorAll('.nav-item').forEach(el=>el.addEventListener('click',()=>switchPage(el.dataset.page)));
function switchPage(id){document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));document.querySelector(`#page-${id}`)?.classList.add('active');document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===id));document.getElementById('sidebar').classList.remove('open');document.getElementById('sidebar-overlay').classList.remove('show')}

async function loadStats(){
  try{
    const r=await fetch('/stats');if(!r.ok)throw new Error();statsData=await r.json();
    document.querySelector('#s-traffic').innerHTML=statsData.total_traffic_mb+'<span class="stat-unit"> MB</span>';
    document.querySelector('#s-links').textContent=statsData.links_count;
    document.querySelector('#s-uptime').textContent=statsData.uptime;
    document.querySelector('#s-domain').textContent=statsData.domain;
    document.querySelector('#links-badge').textContent=statsData.links_count;
    document.querySelector('#last-update').textContent='Updated: '+new Date().toLocaleTimeString();
    if(document.querySelector('#t-traffic'))document.querySelector('#t-traffic').textContent=statsData.total_traffic_mb+' MB';
    if(document.querySelector('#t-reqs'))document.querySelector('#t-reqs').textContent=statsData.total_requests.toLocaleString();
    if(document.querySelector('#t-uptime'))document.querySelector('#t-uptime').textContent=statsData.uptime;
    if(statsData.cpu_percent!==undefined){const c=statsData.cpu_percent;const cc=c>80?'var(--red)':c>50?'var(--yellow)':'var(--primary)';document.querySelector('#s-cpu-val').textContent=c.toFixed(1)+'%';document.querySelector('#s-cpu-val').style.color=cc;document.querySelector('#s-cpu-bar').style.width=c+'%';document.querySelector('#s-cpu-bar').style.background=cc}
    if(statsData.memory_percent!==undefined){const m=statsData.memory_percent;const mc=m>80?'var(--red)':m>50?'var(--yellow)':'var(--green)';document.querySelector('#s-mem-val').textContent=m.toFixed(1)+'%';document.querySelector('#s-mem-val').style.color=mc;document.querySelector('#s-mem-bar').style.width=m+'%';document.querySelector('#s-mem-bar').style.background=mc}
    updateChart();
  }catch(e){}
}

async function loadLinks(){try{const r=await fetch('/api/links');if(!r.ok)throw new Error();const d=await r.json();allLinks=d.links||[];filterInbounds();}catch(e){}}

function renderLinks(links){
  const tbody=document.querySelector('#links-tbody');const empty=document.querySelector('#links-empty');const cards=document.querySelector('#inbound-cards');
  if(!links.length){tbody.innerHTML='';cards.innerHTML='';empty.style.display='block';return;}
  empty.style.display='none';
  let idx=links.length;
  const rows=links.map(l=>{
    const u=l.used_bytes,lim=l.limit_bytes;
    const uF=fmtBytes(u);const lF=fmtLimit(lim);
    const pct=lim>0?Math.min(100,(u/lim)*100):0;
    const col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';
    const i=idx--;
    return {l,uF,lF,pct,col,i};
  });
  tbody.innerHTML=rows.map(r=>`<tr>
    <td style="color:var(--text3);font-size:11px">${r.i}</td>
    <td style="font-weight:600;font-size:13px">${esc(r.l.label)}</td>
    <td><span class="tag tag-xhttp">XHTTP</span></td>
    <td><div class="usage-pill"><span class="used">${r.uF}</span><div class="bar"><div class="fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="limit">${r.lF}</span></div></td>
    <td><span class="tag ${r.l.active?'tag-active':'tag-disabled'}">${r.l.active?'On':'Off'}</span></td>
    <td><div style="display:flex;gap:3px;align-items:center">
      <button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)" title="Toggle"></button>
      <button class="btn btn-secondary btn-sm" onclick="showDetail('${r.l.uuid}')">i</button>
      <button class="btn-copy" onclick="copyLinkText('${esc(r.l.vless_link)}')">c</button>
      <button class="btn-qr" onclick="showQRText('${esc(r.l.vless_link)}')">qr</button>
      <button class="btn btn-danger btn-sm" onclick="deleteLink('${r.l.uuid}')">x</button>
    </div></td>
  </tr>`).join('');
  cards.innerHTML=rows.map(r=>`<div class="inbound-card">
    <div class="inbound-card-header">
      <div style="display:flex;align-items:center;gap:8px">
        <span class="inbound-card-id">#${r.i}</span>
        <span class="inbound-card-name">${esc(r.l.label)}</span>
        <span class="tag tag-xhttp">XHTTP</span>
      </div>
      <button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)"></button>
    </div>
    <div class="usage-pill"><span class="used">${r.uF}</span><div class="bar"><div class="fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="limit">${r.lF}</span></div>
    <div class="inbound-card-actions">
      <button class="btn btn-secondary btn-sm" onclick="showDetail('${r.l.uuid}')">i</button>
      <button class="btn-copy" onclick="copyLinkText('${esc(r.l.vless_link)}')">c</button>
      <button class="btn-qr" onclick="showQRText('${esc(r.l.vless_link)}')">qr</button>
      <button class="btn btn-secondary btn-sm" onclick="resetUsage('${r.l.uuid}')">r</button>
      <button class="btn btn-danger btn-sm" onclick="deleteLink('${r.l.uuid}')">x</button>
    </div>
  </div>`).join('');
}

async function toggleLink(el){
  const uid=el.dataset.uid;const link=allLinks.find(l=>l.uuid===uid);if(!link)return;
  const newActive=!link.active;
  try{await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:newActive})});link.active=newActive;filterInbounds();loadStats();}catch(e){}
}

async function quickCreate(limit,unit){
  const names=['Ali','Sara','Reza','Nima','Mina','Arash','Yalda','Dariush','Cyrus','Shirin'];
  const name=names[Math.floor(Math.random()*names.length)]+'-'+Math.floor(Math.random()*100);
  try{const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:name,limit_value:limit,limit_unit:unit})});if(!r.ok)throw new Error();toast('Created: '+name);await loadLinks();await loadStats();}catch(e){toast('Error',true)}
}

function generateUUIDv4(){return'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,c=>{const r=Math.random()*16|0;return(c==='x'?r:(r&0x3|0x8)).toString(16)});}
function generateAndFillUUID(){document.querySelector('#new-uuid').value=generateUUIDv4();document.querySelector('#uuid-error').style.display='none';}
function validateUUIDInput(el){const v=el.value.trim();const errEl=document.querySelector('#uuid-error');if(v===''){errEl.style.display='none';return;}const ok=/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);errEl.style.display=ok?'none':'block';}

async function createLink(){
  const label=document.querySelector('#new-label').value.trim()||'New Link';const val=parseFloat(document.querySelector('#new-limit').value)||0;
  if(!/^[a-zA-Z0-9\-_. ]+$/.test(label)){toast('Only English letters allowed',true);return;}
  const customUuid=document.querySelector('#new-uuid').value.trim();
  if(customUuid&&!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(customUuid)){toast('Invalid UUID format',true);return;}
  try{
    const body={label,limit_value:val,limit_unit:'GB'};
    if(customUuid)body.custom_uuid=customUuid;
    const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!r.ok){const err=await r.json().catch(()=>({}));toast(err.detail||'Error',true);return;}
    toast('Created');document.querySelector('#new-label').value='';document.querySelector('#new-limit').value='';document.querySelector('#new-uuid').value='';document.querySelector('#uuid-error').style.display='none';document.querySelector('#add-modal').classList.remove('show');await loadLinks();await loadStats();
  }catch(e){toast('Error',true)}
}

async function resetUsage(uid){try{await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});toast('Reset');await loadLinks();}catch(e){}}
async function deleteLink(uid){if(!confirm('Delete this inbound?'))return;try{await fetch(`/api/links/${uid}`,{method:'DELETE'});toast('Deleted');await loadLinks();await loadStats();}catch(e){}}

function showDetail(uid){
  const l=allLinks.find(x=>x.uuid===uid);if(!l)return;
  const u=l.used_bytes,lim=l.limit_bytes;const uF=fmtBytes(u);const lF=fmtLimit(lim);
  const pct=lim>0?Math.min(100,(u/lim)*100):0;const col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';
  const created=l.created_at?new Date(l.created_at).toLocaleString():'--';
  document.querySelector('#detail-title').textContent=l.label;
  document.querySelector('#detail-content').innerHTML=`
    <div class="detail-row">
      <div class="detail-col"><div class="detail-label">Protocol</div><div class="detail-value" style="font-family:inherit"><span class="tag tag-vless">VLESS</span></div></div>
      <div class="detail-col"><div class="detail-label">Transport</div><div class="detail-value" style="font-family:inherit"><span class="tag tag-xhttp">XHTTP</span></div></div>
      <div class="detail-col"><div class="detail-label">Status</div><div class="detail-value" style="font-family:inherit"><span class="tag ${l.active?'tag-active':'tag-disabled'}">${l.active?'Active':'Disabled'}</span></div></div>
    </div>
    <div style="margin-bottom:12px"><div class="detail-label">UUID</div><div class="detail-value">${l.uuid}</div></div>
    <div class="detail-row">
      <div class="detail-col"><div class="detail-label">Used</div><div class="detail-value">${uF}</div></div>
      <div class="detail-col"><div class="detail-label">Limit</div><div class="detail-value">${lF}</div></div>
      <div class="detail-col"><div class="detail-label">Usage</div><div class="detail-value">${pct.toFixed(1)}%</div></div>
    </div>
    <div class="sys-bar" style="margin-bottom:12px"><div class="sys-bar-fill" style="width:${pct}%;background:${col}"></div></div>
    <div style="margin-bottom:12px"><div class="detail-label">Created</div><div class="detail-value" style="font-family:inherit">${created}</div></div>
    <div style="margin-bottom:0"><div class="detail-label">VLESS Link (XHTTP)</div><div class="detail-value">${esc(l.vless_link)}</div></div>
    <div class="detail-actions">
      <button class="btn-copy" onclick="copyLinkText('${esc(l.vless_link)}');document.querySelector('#detail-modal').classList.remove('show')" style="padding:8px 18px;font-size:12px">Copy</button>
      <button class="btn-qr" onclick="showQRText('${esc(l.vless_link)}');document.querySelector('#detail-modal').classList.remove('show')" style="padding:8px 18px;font-size:12px">QR Code</button>
      <button class="btn btn-secondary btn-sm" onclick="resetUsage('${l.uuid}');document.querySelector('#detail-modal').classList.remove('show')" style="padding:8px 18px">Reset Traffic</button>
    </div>`;
  document.querySelector('#detail-modal').classList.add('show');
}

function copyLinkText(txt){navigator.clipboard.writeText(txt).then(()=>toast('Copied to clipboard')).catch(()=>toast('Failed to copy',true))}
function showQRText(txt){if(!txt)return;document.querySelector('#qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=300x300&data='+encodeURIComponent(txt);document.querySelector('#qr-modal').classList.add('show')}
function downloadQR(){const img=document.querySelector('#qr-img');if(!img.src)return;const a=document.createElement('a');a.href=img.src;a.download='ren-xhttp-qr.png';a.click()}

async function changePassword(){
  const cur=document.querySelector('#cur-pw').value;const nw=document.querySelector('#new-pw').value;
  if(!cur||!nw){toast('Fill all fields',true);return;}
  try{const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Error');}toast('Updated');document.querySelector('#cur-pw').value='';document.querySelector('#new-pw').value='';}catch(e){toast(e.message,true)}
}

applyTheme(theme);setLang(lang);
loadStats();loadLinks();
setInterval(()=>{loadStats()},10000);

function initChart(){
  const ctx=document.getElementById('trafficChart');if(!ctx)return;
  trafficChart=new Chart(ctx,{type:'bar',data:{labels:[],datasets:[{label:'MB',data:[],backgroundColor:'rgba(220,38,38,0.7)',borderColor:'#dc2626',borderWidth:1,borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:'rgba(255,255,255,0.3)',font:{size:10}}},y:{grid:{color:'rgba(255,255,255,0.05)'},ticks:{color:'rgba(255,255,255,0.3)',font:{size:10},callback:v=>v+' MB'},beginAtZero:true}}}});
}
initChart();
function updateChart(){
  if(!trafficChart||!statsData.hourly_traffic)return;
  const ht=statsData.hourly_traffic;
  const sorted=Object.entries(ht).sort((a,b)=>a[0].localeCompare(b[0])).slice(-12);
  trafficChart.data.labels=sorted.map(e=>e[0]);
  trafficChart.data.datasets[0].data=sorted.map(e=>Math.round(e[1]/1048576));
  trafficChart.update();
}
</script>
</body>
</html>"""


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
