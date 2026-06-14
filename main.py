"""
RVG Gateway v2 · Render Edition
قابلیت‌ها:
  - VLESS WebSocket proxy
  - پنل مدیریت فارسی
  - ربات تلگرام کامل
  - نوتیف اتصال جدید + IP + کشور
  - Anti-sleep (هر ۱۰ دقیقه ping)
  - ذخیره لینک‌ها در JSON
  - تاریخ انقضای لینک
  - محدودیت دستگاه همزمان
  - آمار روزانه خودکار
  - Subscription link
  - بلاک IP
  - آمار روزانه
"""

import asyncio
import hashlib
import json
import logging
import os
import secrets
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("RVG-v2")

app = FastAPI(title="RVG Gateway v2", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

# ───────── Config ─────────
SECRET_KEY     = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "123456")
PORT           = int(os.environ.get("PORT", 8000))
BOT_TOKEN      = os.environ.get("BOT_TOKEN", "")
ADMIN_CHAT_IDS = set(os.environ.get("ADMIN_CHAT_IDS", "").split(",")) - {""}
BOT_PASSWORD   = os.environ.get("BOT_PASSWORD", "admin123")
RENDER_URL     = os.environ.get("RENDER_EXTERNAL_URL", "")
DATA_FILE      = Path("/tmp/gateway_data.json")
BLOCKED_IPS_FILE = Path("/tmp/blocked_ips.json")

def get_host() -> str:
    h = os.environ.get("RENDER_EXTERNAL_HOSTNAME", "")
    if h: return h
    return os.environ.get("HOST", "localhost")

# ───────── State ─────────
LINKS: dict = {}
SESSIONS: dict = {}
BLOCKED_IPS: set = set()
BOT_AUTHED: set = set()

stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
    "daily_connections": defaultdict(int),
    "daily_traffic": defaultdict(int),
    "daily_countries": defaultdict(lambda: defaultdict(int)),
    # IP های یکتا هر روز (set) - برای گزارش روزانه
    "daily_unique_ips": defaultdict(set),
}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
# uid -> set of connection ids
active_link_conns: dict = defaultdict(set)
# connection_id -> info
active_connections: dict = {}

SESSION_COOKIE = "rvg_session"
SESSION_TTL    = 60 * 60 * 24 * 7

# ───────── IP Deduplication Cache ─────────
# کلید: (uid, ip) → زمان اولین اتصال
# هدف: جلوگیری از ارسال پیام تکراری برای reconnect های سریع
_notified_connections: dict = {}   # (uid, ip) -> timestamp
_NOTIF_COOLDOWN = 300              # ۵ دقیقه - بعد از این مدت دوباره نوتیف بده

# ───────── IP Traffic Tracking ─────────
# ip -> {"upload": int, "download": int, "total": int, "country_code": str, "country": str}
ip_traffic: dict = defaultdict(lambda: {"upload": 0, "download": 0, "total": 0, "country_code": "", "country": ""})

# ip -> deque of (domain, port, timestamp) — آخرین ۵۰ دامنه بازدیدشده
ip_domains: dict = defaultdict(lambda: deque(maxlen=50))

# uid -> set of unique IPs (IP های یکتا نه session ها)
active_link_ips: dict = defaultdict(set)

# ───────── Persistence ─────────
def save_data():
    try:
        data = {
            "links": LINKS,
            "blocked_ips": list(BLOCKED_IPS),
        }
        DATA_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    except Exception as e:
        logger.error(f"Save error: {e}")

def load_data():
    global LINKS, BLOCKED_IPS
    try:
        if DATA_FILE.exists():
            data = json.loads(DATA_FILE.read_text())
            LINKS = data.get("links", {})
            BLOCKED_IPS = set(data.get("blocked_ips", []))
            logger.info(f"✅ Loaded {len(LINKS)} links, {len(BLOCKED_IPS)} blocked IPs")
    except Exception as e:
        logger.error(f"Load error: {e}")

# ───────── Auth ─────────
def hash_pw(pw: str) -> str:
    return hashlib.sha256(f"{pw}{SECRET_KEY}".encode()).hexdigest()

auth = {"hash": hash_pw(ADMIN_PASSWORD)}

def new_session() -> str:
    t = secrets.token_urlsafe(32)
    SESSIONS[t] = time.time() + SESSION_TTL
    return t

def valid_session(token: str | None) -> bool:
    if not token: return False
    exp = SESSIONS.get(token)
    if not exp: return False
    if exp < time.time(): SESSIONS.pop(token, None); return False
    return True

async def require_auth(request: Request):
    if not valid_session(request.cookies.get(SESSION_COOKIE)):
        raise HTTPException(401, "unauthorized")

# ───────── Helpers ─────────
def uptime() -> str:
    s = int(time.time() - stats["start_time"])
    return f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"

def now_hour() -> str:
    return datetime.now().strftime("%H:00")

def today() -> str:
    return datetime.now().strftime("%Y-%m-%d")

def parse_bytes(v: float, u: str) -> int:
    u = u.upper()
    if u == "GB": return int(v * 1024**3)
    if u == "MB": return int(v * 1024**2)
    return int(v * 1024)

def fmt_bytes(b: int) -> str:
    if not b: return "نامحدود ♾️"
    if b >= 1024**3: return f"{b/1024**3:.1f} GB"
    if b >= 1024**2: return f"{b/1024**2:.1f} MB"
    return f"{b/1024:.1f} KB"

def flag(code: str) -> str:
    if not code or len(code) != 2: return "🌐"
    return chr(0x1F1E6 + ord(code[0].upper()) - 65) + chr(0x1F1E6 + ord(code[1].upper()) - 65)

def vless_link(uid: str, label: str = "") -> str:
    host = get_host()
    params = (f"encryption=none&security=tls&type=ws"
              f"&host={host}&path=%2Fws%2F{uid}&sni={host}&fp=chrome&alpn=http%2F1.1")
    return f"vless://{uid}@{host}:443?{params}#{quote(label or 'RVG-Gateway')}"

def sub_link(uid: str) -> str:
    host = get_host()
    return f"https://{host}/sub/{uid}"

def is_expired(link: dict) -> bool:
    exp = link.get("expires_at")
    if not exp: return False
    return datetime.fromisoformat(exp) < datetime.now()

def check_quota(uid: str) -> bool:
    link = LINKS.get(uid)
    if not link: return False
    if not link.get("active"): return False
    if is_expired(link): return False
    if link.get("limit_bytes") and link["used_bytes"] >= link["limit_bytes"]: return False
    max_dev = link.get("max_devices", 0)
    if max_dev and len(active_link_conns.get(uid, set())) >= max_dev: return False
    return True

# ───────── IP Info ─────────
_ip_cache: dict = {}

async def get_ip_info(ip: str) -> dict:
    if ip in _ip_cache:
        return _ip_cache[ip]
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,proxy,hosting")
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    _ip_cache[ip] = data
                    return data
    except Exception:
        pass
    return {}

# ───────── Telegram Bot ─────────
tg_app = None

async def tg_send(chat_id: str | int, text: str, reply_markup=None):
    if not BOT_TOKEN: return
    try:
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
        if reply_markup:
            payload["reply_markup"] = json.dumps(reply_markup)
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", json=payload)
    except Exception as e:
        logger.error(f"TG send error: {e}")

async def tg_notify_all(text: str):
    for cid in ADMIN_CHAT_IDS:
        await tg_send(cid, text)

async def notify_new_connection(uid: str, ip: str, conn_id: str):
    """
    ارسال نوتیف اتصال جدید - با جلوگیری از ارسال تکراری برای یک IP.
    اگر همان IP در ۵ دقیقه اخیر نوتیف گرفته، فقط آمار IP های فعال آپدیت می‌شود.
    """
    if not BOT_TOKEN or not ADMIN_CHAT_IDS:
        return

    link = LINKS.get(uid, {})
    label = link.get("label", "نامشخص")
    info = await get_ip_info(ip)
    country = info.get("country", "نامشخص")
    country_code = info.get("countryCode", "")
    city = info.get("city", "نامشخص")
    isp = info.get("isp", "نامشخص")
    is_proxy = "⚠️ VPN/Proxy" if info.get("proxy") or info.get("hosting") else "✅ مستقیم"

    # ذخیره اطلاعات کشور IP در ip_traffic
    if country_code:
        ip_traffic[ip]["country_code"] = country_code
        ip_traffic[ip]["country"] = country

    # شمارش IP های یکتا فعال این لینک
    active_unique_ips = len(active_link_ips.get(uid, set()))

    # بررسی deduplication - اگر این IP اخیراً نوتیف گرفته، پیام جدید نفرست
    cache_key = (uid, ip)
    now_ts = time.time()
    last_notif = _notified_connections.get(cache_key, 0)

    if now_ts - last_notif < _NOTIF_COOLDOWN:
        # فقط لاگ بزن - پیام تلگرام نفرست
        logger.info(f"🔁 IP {ip} reconnect (no notification, cooldown active)")
        return

    # ثبت زمان نوتیف برای این IP
    _notified_connections[cache_key] = now_ts

    # اطلاعات مصرف این IP
    ip_data = ip_traffic.get(ip, {})
    up_bytes = ip_data.get("upload", 0)
    down_bytes = ip_data.get("download", 0)
    total_bytes = ip_data.get("total", 0)

    msg = (
        f"🔌 *اتصال جدید!*\n"
        f"{'─' * 28}\n"
        f"🏷 لینک: `{label}`\n"
        f"🌐 IP: `{ip}`\n"
        f"🏳️ کشور: {flag(country_code)} {country}\n"
        f"🏙 شهر: {city}\n"
        f"📡 ISP: {isp}\n"
        f"🔍 نوع: {is_proxy}\n"
        f"\n"
        f"👥 IP فعال این لینک: `{active_unique_ips}`\n"
        f"\n"
        f"📦 مصرف:\n"
        f"  ⬆️ Upload: `{fmt_bytes(up_bytes)}`\n"
        f"  ⬇️ Download: `{fmt_bytes(down_bytes)}`\n"
        f"  📊 مجموع: `{fmt_bytes(total_bytes)}`\n"
        f"\n"
        f"⏰ زمان: `{datetime.now().strftime('%H:%M:%S')}`"
    )
    kb = {"inline_keyboard": [[
        {"text": "🚫 بلاک IP", "callback_data": f"block_ip_{ip}"},
        {"text": "⏸ غیرفعال لینک", "callback_data": f"disable_link_{uid}"},
    ]]}
    for cid in ADMIN_CHAT_IDS:
        await tg_send(cid, msg, kb)

async def notify_service_wake():
    if not ADMIN_CHAT_IDS: return
    msg = (
        f"🟢 *سرویس بیدار شد!*\n"
        f"⏰ زمان: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
        f"🔗 لینک‌های فعال: {sum(1 for l in LINKS.values() if l.get('active'))}"
    )
    await tg_notify_all(msg)

async def send_daily_report():
    """گزارش روزانه با IP های یکتا و ۱۰ IP پرمصرف"""
    if not ADMIN_CHAT_IDS:
        return

    d = today()
    traffic = stats["daily_traffic"].get(d, 0)

    # شمارش IP های یکتا روزانه (نه تعداد session)
    unique_ips_today = stats["daily_unique_ips"].get(d, set())
    unique_ip_count = len(unique_ips_today)

    # آمار کشورها بر اساس IP یکتا
    countries = stats["daily_countries"].get(d, {})
    top_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]
    top_str = "\n".join([f"  {flag(c)} {c}: {n} IP" for c, n in top_countries]) or "  هیچ اتصالی"

    # ۱۰ IP پرمصرف روز
    # فقط IP هایی که امروز فعال بودند
    today_ips = []
    for ip in unique_ips_today:
        data = ip_traffic.get(ip)
        if data:
            today_ips.append((ip, data))

    top_ips = sorted(today_ips, key=lambda x: x[1].get("total", 0), reverse=True)[:10]

    if top_ips:
        top_ips_lines = []
        for i, (ip, data) in enumerate(top_ips, 1):
            cc = data.get("country_code", "")
            country_name = data.get("country", "نامشخص")
            total = data.get("total", 0)
            flag_emoji = flag(cc)
            top_ips_lines.append(f"  {i}) `{ip}` 📦 {fmt_bytes(total)} {flag_emoji} {country_name}")
        top_ips_str = "\n".join(top_ips_lines)
    else:
        top_ips_str = "  هنوز اطلاعاتی ثبت نشده"

    msg = (
        f"📊 *گزارش روزانه · {d}*\n"
        f"{'─' * 28}\n"
        f"👥 IP های فعال: `{unique_ip_count}`\n"
        f"📦 ترافیک: `{fmt_bytes(traffic)}`\n"
        f"🌍 کشورهای برتر:\n{top_str}\n"
        f"{'─' * 28}\n"
        f"🔥 ۱۰ IP پرمصرف روز:\n{top_ips_str}\n"
        f"{'─' * 28}\n"
        f"🔗 کل لینک‌ها: {len(LINKS)}\n"
        f"⏱ آپتایم: `{uptime()}`"
    )
    await tg_notify_all(msg)

# ───────── Anti-Sleep Ping ─────────
async def anti_sleep_ping():
    if not RENDER_URL: return
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.get(f"{RENDER_URL}/health")
            logger.info("💓 Anti-sleep ping sent")
    except Exception as e:
        logger.error(f"Ping error: {e}")

# ───────── Scheduler ─────────
async def scheduler_loop():
    ping_interval = 10 * 60  # 10 min
    report_hour   = 23       # ساعت گزارش روزانه
    last_ping = 0
    last_report_day = ""

    while True:
        await asyncio.sleep(60)
        now = datetime.now()

        # Anti-sleep ping
        if time.time() - last_ping >= ping_interval:
            await anti_sleep_ping()
            last_ping = time.time()

        # Daily report at 23:00
        if now.hour == report_hour and today() != last_report_day:
            await send_daily_report()
            last_report_day = today()

        # Check expired links
        for uid, link in list(LINKS.items()):
            if is_expired(link) and link.get("active"):
                link["active"] = False
                save_data()
                label = link.get("label", uid[:8])
                await tg_notify_all(f"⏰ لینک *{label}* منقضی و غیرفعال شد.")

        # پاکسازی cache نوتیف‌های قدیمی (بیشتر از ۱ ساعت)
        expired_notif_keys = [
            k for k, t in list(_notified_connections.items())
            if now_ts - t > 3600
        ]
        for k in expired_notif_keys:
            _notified_connections.pop(k, None)

        # پاکسازی cache کشور tracking قدیمی (کلیدهای دیروز)
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        stale_country_keys = [
            k for k in list(_ip_cache.keys())
            if k.startswith(f"_country_tracked_{yesterday}_")
        ]
        for k in stale_country_keys:
            _ip_cache.pop(k, None)

# ───────── Telegram Polling ─────────
async def tg_process_update(update: dict):
    # Callback queries
    if "callback_query" in update:
        cq = update["callback_query"]
        cid = cq["message"]["chat"]["id"]
        data = cq.get("data", "")

        if str(cid) not in ADMIN_CHAT_IDS and cid not in BOT_AUTHED:
            return

        if data.startswith("block_ip_"):
            ip = data[9:]
            BLOCKED_IPS.add(ip)
            save_data()
            await tg_send(cid, f"🚫 IP `{ip}` بلاک شد.")

        elif data.startswith("disable_link_"):
            uid = data[13:]
            if uid in LINKS:
                LINKS[uid]["active"] = False
                save_data()
                await tg_send(cid, f"⏸ لینک `{LINKS[uid]['label']}` غیرفعال شد.")

        elif data.startswith("toggle_"):
            uid = data[7:]
            if uid in LINKS:
                LINKS[uid]["active"] = not LINKS[uid]["active"]
                save_data()
                status = "فعال ✅" if LINKS[uid]["active"] else "غیرفعال ❌"
                await tg_send(cid, f"لینک *{LINKS[uid]['label']}* اکنون {status} است.")

        elif data.startswith("delete_"):
            uid = data[7:]
            if uid in LINKS:
                label = LINKS[uid]["label"]
                del LINKS[uid]
                save_data()
                await tg_send(cid, f"🗑 لینک *{label}* حذف شد.")

        elif data.startswith("show_"):
            uid = data[5:]
            await tg_show_link(cid, uid)

        elif data == "refresh_stats":
            await tg_send_stats(cid)

        elif data == "restart_confirm":
            await tg_send(cid, "♻️ در حال ریستارت...")

        # Answer callback
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(
                    f"https://api.telegram.org/bot{BOT_TOKEN}/answerCallbackQuery",
                    json={"callback_query_id": cq["id"]}
                )
        except: pass
        return

    # Messages
    msg = update.get("message", {})
    if not msg: return
    cid = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()

    # Auth check
    if str(cid) not in ADMIN_CHAT_IDS and cid not in BOT_AUTHED:
        if text == BOT_PASSWORD:
            BOT_AUTHED.add(cid)
            kb = tg_main_kb()
            await tg_send(cid, "✅ *ورود موفق!*\nخوش آمدید 👋", kb)
        else:
            await tg_send(cid, "🔒 رمز عبور را وارد کنید:")
        return

    # Commands & menu
    if text in ("/start", "🏠 خانه"):
        kb = tg_main_kb()
        await tg_send(cid, f"👋 سلام!\n🛡 *RVG Gateway v2*\nاز منو استفاده کن 👇", kb)

    elif text in ("/links", "📋 لینک‌ها"):
        await tg_send_links(cid)

    elif text in ("/stats", "📊 آمار"):
        await tg_send_stats(cid)

    elif text in ("/new", "➕ لینک جدید"):
        await tg_send(cid,
            "➕ *ساخت لینک جدید*\n\n"
            "فرمت:\n`/create عنوان | سهمیه | روزهای انقضا | حداکثر دستگاه`\n\n"
            "مثال:\n`/create برای علی | 10 GB | 30 | 2`\n\n"
            "برای نامحدود: `0` بذار\n"
            "`/create برای همه | 0 | 0 | 0`"
        )

    elif text.startswith("/create "):
        await tg_create_link(cid, text[8:])

    elif text in ("/blocked", "🚫 IP های بلاک"):
        await tg_show_blocked(cid)

    elif text.startswith("/unblock "):
        ip = text[9:].strip()
        BLOCKED_IPS.discard(ip)
        save_data()
        await tg_send(cid, f"✅ IP `{ip}` آنبلاک شد.")

    elif text.startswith("/block "):
        ip = text[7:].strip()
        BLOCKED_IPS.add(ip)
        save_data()
        await tg_send(cid, f"🚫 IP `{ip}` بلاک شد.")

    elif text in ("/report", "📈 گزارش امروز"):
        await send_daily_report()

    elif text.startswith("/domains "):
        ip = text[9:].strip()
        await tg_show_domains(cid, ip)

    elif text in ("/help", "❓ راهنما"):
        await tg_send(cid,
            "❓ *راهنمای دستورات*\n\n"
            "`/create` — ساخت لینک جدید\n"
            "`/links` — لیست لینک‌ها\n"
            "`/stats` — آمار سرور\n"
            "`/block IP` — بلاک کردن IP\n"
            "`/unblock IP` — آنبلاک IP\n"
            "`/blocked` — لیست IP های بلاک\n"
            "`/report` — گزارش امروز\n"
            "`/domains IP` — سایت‌های بازدیدشده توسط IP\n"
        )
    else:
        await tg_send(cid, "❓ دستور نامشخص. /help بزن.")

def tg_main_kb():
    return {"keyboard": [
        [{"text": "📋 لینک‌ها"}, {"text": "➕ لینک جدید"}],
        [{"text": "📊 آمار"},    {"text": "🚫 IP های بلاک"}],
        [{"text": "📈 گزارش امروز"}, {"text": "❓ راهنما"}],
        [{"text": "🏠 خانه"}],
    ], "resize_keyboard": True}

async def tg_send_stats(cid):
    active_conns = len(active_connections)
    active_links = sum(1 for l in LINKS.values() if l.get("active") and not is_expired(l))
    total_used = sum(l.get("used_bytes", 0) for l in LINKS.values())
    kb = {"inline_keyboard": [[
        {"text": "🔄 بروزرسانی", "callback_data": "refresh_stats"}
    ]]}
    msg = (
        f"📊 *آمار سرور*\n"
        f"{'─' * 28}\n"
        f"🔌 اتصالات فعال: `{active_conns}`\n"
        f"🔗 لینک‌های فعال: `{active_links}/{len(LINKS)}`\n"
        f"📦 کل ترافیک: `{fmt_bytes(total_used)}`\n"
        f"🚫 IP های بلاک: `{len(BLOCKED_IPS)}`\n"
        f"⏱ آپتایم: `{uptime()}`\n"
        f"🌐 هاست: `{get_host()}`\n"
        f"{'─' * 28}\n"
        f"🕐 `{datetime.now().strftime('%H:%M:%S')}`"
    )
    await tg_send(cid, msg, kb)

async def tg_send_links(cid):
    if not LINKS:
        await tg_send(cid, "هیچ لینکی وجود ندارد. با /new بساز.")
        return
    buttons = []
    for uid, d in list(LINKS.items()):
        exp = " ⏰" if is_expired(d) else ""
        status = "✅" if d.get("active") and not is_expired(d) else "❌"
        used = fmt_bytes(d.get("used_bytes", 0))
        limit = fmt_bytes(d.get("limit_bytes", 0))
        buttons.append([{"text": f"{status} {d['label']}{exp} | {used}/{limit}",
                         "callback_data": f"show_{uid}"}])
    kb = {"inline_keyboard": buttons}
    await tg_send(cid, f"🔗 *لیست لینک‌ها* ({len(LINKS)} عدد):", kb)

async def tg_show_link(cid, uid):
    link = LINKS.get(uid)
    if not link:
        await tg_send(cid, "❌ لینک یافت نشد.")
        return
    vl = vless_link(uid, link["label"])
    sl = sub_link(uid)
    exp_str = link.get("expires_at", "—")[:10] if link.get("expires_at") else "نامحدود"
    active_dev = len(active_link_conns.get(uid, set()))
    max_dev = link.get("max_devices", 0)
    pct = ""
    if link.get("limit_bytes"):
        p = min(100, round(link["used_bytes"] / link["limit_bytes"] * 100))
        bar = "█" * (p // 10) + "░" * (10 - p // 10)
        pct = f"\n📊 `[{bar}] {p}%`"

    msg = (
        f"🔗 *{link['label']}*\n"
        f"{'─' * 26}\n"
        f"{'✅ فعال' if link.get('active') and not is_expired(link) else '❌ غیرفعال'}\n"
        f"📦 سهمیه: `{fmt_bytes(link.get('limit_bytes',0))}`\n"
        f"📥 مصرف: `{fmt_bytes(link.get('used_bytes',0))}`{pct}\n"
        f"📅 انقضا: `{exp_str}`\n"
        f"👥 دستگاه: `{active_dev}/{max_dev or '∞'}`\n\n"
        f"🔑 VLESS:\n`{vl}`\n\n"
        f"📡 Subscription:\n`{sl}`"
    )
    kb = {"inline_keyboard": [
        [{"text": "⏸/▶️ تغییر وضعیت", "callback_data": f"toggle_{uid}"},
         {"text": "🗑 حذف", "callback_data": f"delete_{uid}"}],
    ]}
    await tg_send(cid, msg, kb)

async def tg_create_link(cid, raw: str):
    parts = [p.strip() for p in raw.split("|")]
    label = parts[0] if parts else "لینک جدید"
    limit_bytes = 0
    expires_at = None
    max_devices = 0

    if len(parts) >= 2 and parts[1] not in ("0", ""):
        import re
        m = re.match(r"([\d.]+)\s*(gb|mb|kb)?", parts[1].lower())
        if m:
            v = float(m.group(1))
            u = (m.group(2) or "gb").upper()
            limit_bytes = parse_bytes(v, u)

    if len(parts) >= 3 and parts[2] not in ("0", ""):
        days = int(parts[2])
        if days > 0:
            expires_at = (datetime.now() + timedelta(days=days)).isoformat()

    if len(parts) >= 4 and parts[3] not in ("0", ""):
        max_devices = int(parts[3])

    uid = str(uuid.uuid4())
    LINKS[uid] = {
        "label": label,
        "limit_bytes": limit_bytes,
        "used_bytes": 0,
        "created_at": datetime.now().isoformat(),
        "expires_at": expires_at,
        "max_devices": max_devices,
        "active": True,
    }
    save_data()

    exp_str = expires_at[:10] if expires_at else "نامحدود"
    vl = vless_link(uid, label)
    sl = sub_link(uid)
    await tg_send(cid,
        f"✅ *لینک ساخته شد!*\n\n"
        f"🏷 عنوان: `{label}`\n"
        f"📦 سهمیه: `{fmt_bytes(limit_bytes)}`\n"
        f"📅 انقضا: `{exp_str}`\n"
        f"👥 حداکثر دستگاه: `{max_devices or '∞'}`\n\n"
        f"🔑 VLESS:\n`{vl}`\n\n"
        f"📡 Subscription:\n`{sl}`"
    )

async def tg_show_blocked(cid):
    if not BLOCKED_IPS:
        await tg_send(cid, "✅ هیچ IP بلاکی وجود ندارد.")
        return
    ips = "\n".join([f"`{ip}`" for ip in list(BLOCKED_IPS)[:20]])
    await tg_send(cid, f"🚫 *IP های بلاک شده:*\n\n{ips}\n\nبرای آنبلاک: `/unblock IP`")

async def tg_show_domains(cid, ip: str):
    domains = list(ip_domains.get(ip, []))
    if not domains:
        await tg_send(cid, f"📭 هیچ دامنه‌ای برای IP `{ip}` ثبت نشده.\n\nممکنه این IP فعال نبوده یا سرور ری‌استارت شده.")
        return
    lines = []
    for i, entry in enumerate(domains[:30], 1):
        port = entry["port"]
        proto = "🔒 HTTPS" if port == 443 else f"🌐 HTTP" if port == 80 else f"🔌 :{port}"
        lines.append(f"{i}) `{entry['domain']}` — {proto} — ⏰ {entry['time']}")
    msg = (
        f"🌍 *سایت‌های بازدیدشده توسط:*\n"
        f"`{ip}`\n"
        f"{'─' * 28}\n"
        + "\n".join(lines) +
        f"\n{'─' * 28}\n"
        f"📊 مجموع ثبت‌شده: `{len(domains)}`"
    )
    await tg_send(cid, msg)

async def tg_polling_loop():
    if not BOT_TOKEN:
        logger.warning("BOT_TOKEN تنظیم نشده — ربات غیرفعال")
        return
    offset = 0
    logger.info("🤖 Telegram bot polling started")
    while True:
        try:
            async with httpx.AsyncClient(timeout=35) as client:
                r = await client.get(
                    f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates",
                    params={"offset": offset, "timeout": 30, "allowed_updates": ["message", "callback_query"]}
                )
                data = r.json()
                if data.get("ok"):
                    for upd in data.get("result", []):
                        offset = upd["update_id"] + 1
                        asyncio.create_task(tg_process_update(upd))
        except Exception as e:
            logger.error(f"Polling error: {e}")
            await asyncio.sleep(5)

# ───────── Ensure Default Link ─────────
async def ensure_default():
    if not LINKS:
        uid = str(uuid.uuid4())
        LINKS[uid] = {
            "label": "پیش‌فرض",
            "limit_bytes": 0,
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "expires_at": None,
            "max_devices": 0,
            "active": True,
        }
        save_data()
        logger.info(f"✅ Default link: {uid}")

# ───────── Startup ─────────
@app.on_event("startup")
async def startup():
    load_data()
    await ensure_default()
    asyncio.create_task(tg_polling_loop())
    asyncio.create_task(scheduler_loop())
    await notify_service_wake()
    logger.info(f"🚀 RVG Gateway v2 started on :{PORT}")

# ───────── WebSocket VLESS ─────────
@app.websocket("/ws/{uid}")
async def ws_vless(ws: WebSocket, uid: str, request: Request = None):
    await ws.accept()
    conn_id = secrets.token_hex(8)

    # Get client IP
    client_ip = ws.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if not client_ip:
        client_ip = ws.client.host if ws.client else "unknown"

    # Check blocked IP
    if client_ip in BLOCKED_IPS:
        await ws.close(1008, "blocked")
        return

    # Check link validity
    if not check_quota(uid):
        await ws.close(1008, "invalid or quota exceeded")
        return

    # Register connection
    active_connections[conn_id] = {
        "uid": uid, "ip": client_ip,
        "connected_at": datetime.now().isoformat(), "bytes": 0,
        "upload": 0, "download": 0,
    }
    active_link_conns[uid].add(conn_id)

    # ثبت IP یکتا برای این لینک
    active_link_ips[uid].add(client_ip)

    # ثبت IP یکتا در آمار روزانه
    stats["daily_unique_ips"][today()].add(client_ip)

    stats["total_requests"] += 1
    stats["daily_connections"][today()] = stats["daily_connections"].get(today(), 0) + 1

    logger.info(f"🔌 WS [{conn_id}] uid={uid[:8]} ip={client_ip}")

    # Notify telegram (async, don't block)
    asyncio.create_task(notify_new_connection(uid, client_ip, conn_id))

    try:
        # Parse VLESS header from first message
        first = await asyncio.wait_for(ws.receive_bytes(), timeout=15)

        if len(first) < 24:
            await ws.close(1002, "invalid")
            return

        pos = 1  # skip version
        pos += 16  # UUID
        addon_len = first[pos]; pos += 1
        pos += addon_len
        command = first[pos]; pos += 1
        port = (first[pos] << 8) | first[pos+1]; pos += 2
        addr_type = first[pos]; pos += 1

        address = ""
        if addr_type == 1:
            address = ".".join(str(b) for b in first[pos:pos+4]); pos += 4
        elif addr_type == 2:
            dlen = first[pos]; pos += 1
            address = first[pos:pos+dlen].decode(); pos += dlen
        elif addr_type == 3:
            ab = first[pos:pos+16]; pos += 16
            address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))

        payload = first[pos:]

        # ثبت دامنه بازدیدشده برای این IP
        if address:
            ip_domains[client_ip].appendleft({
                "domain": address,
                "port": port,
                "time": datetime.now().strftime("%H:%M:%S"),
            })

        # Track country stats
        asyncio.create_task(_track_country(client_ip))

        # Connect to target
        tcp = await asyncio.open_connection(address, port)
        reader, writer = tcp

        # VLESS response
        await ws.send_bytes(bytes([0, 0]))

        if payload:
            writer.write(payload)
            await writer.drain()

        # Relay
        async def ws_to_tcp():
            """کلاینت → سرور = Upload"""
            try:
                while True:
                    data = await ws.receive_bytes()
                    writer.write(data)
                    await writer.drain()
                    n = len(data)
                    stats["total_bytes"] += n
                    stats["daily_traffic"][today()] = stats["daily_traffic"].get(today(), 0) + n
                    hourly_traffic[now_hour()] += n
                    if uid in LINKS: LINKS[uid]["used_bytes"] += n
                    active_connections[conn_id]["bytes"] += n
                    active_connections[conn_id]["upload"] += n
                    # ثبت upload برای IP
                    ip_traffic[client_ip]["upload"] += n
                    ip_traffic[client_ip]["total"] += n
                    # Check quota mid-connection
                    if LINKS.get(uid, {}).get("limit_bytes"):
                        if LINKS[uid]["used_bytes"] >= LINKS[uid]["limit_bytes"]:
                            break
            except: pass
            finally: writer.close()

        async def tcp_to_ws():
            """سرور → کلاینت = Download"""
            try:
                while True:
                    data = await reader.read(65536)
                    if not data: break
                    await ws.send_bytes(data)
                    n = len(data)
                    stats["total_bytes"] += n
                    stats["daily_traffic"][today()] = stats["daily_traffic"].get(today(), 0) + n
                    hourly_traffic[now_hour()] += n
                    if uid in LINKS: LINKS[uid]["used_bytes"] += n
                    active_connections[conn_id]["bytes"] += n
                    active_connections[conn_id]["download"] += n
                    # ثبت download برای IP
                    ip_traffic[client_ip]["download"] += n
                    ip_traffic[client_ip]["total"] += n
            except: pass

        await asyncio.gather(ws_to_tcp(), tcp_to_ws())

    except Exception as e:
        stats["total_errors"] += 1
        error_logs.append({"error": str(e), "time": datetime.now().isoformat()})
    finally:
        active_connections.pop(conn_id, None)
        active_link_conns[uid].discard(conn_id)

        # بررسی: آیا session دیگری از همین IP روی همین لینک هست؟
        # اگر نه، IP را از active_link_ips حذف کن
        other_sessions_same_ip = any(
            info.get("ip") == client_ip and info.get("uid") == uid
            for info in active_connections.values()
        )
        if not other_sessions_same_ip:
            active_link_ips[uid].discard(client_ip)
            # پاک کردن cache نوتیف بعد از timeout واقعی (نه فوری)
            # این اجازه می‌دهد بعد از cooldown دوباره نوتیف بده

        try: await ws.close()
        except: pass
        save_data()
        logger.info(f"🔌 WS [{conn_id}] closed ip={client_ip}")

async def _track_country(ip: str):
    """
    ردیابی کشور بر اساس IP یکتا.
    اگر این IP امروز قبلاً شمرده شده، دوباره شمارش نشود.
    """
    info = await get_ip_info(ip)
    cc = info.get("countryCode", "XX")
    country_name = info.get("country", "نامشخص")
    d = today()

    # ذخیره اطلاعات کشور در ip_traffic
    if cc and cc != "XX":
        ip_traffic[ip]["country_code"] = cc
        ip_traffic[ip]["country"] = country_name

    # فقط اگر این IP امروز قبلاً برای این کشور شمرده نشده
    if d not in stats["daily_countries"]:
        stats["daily_countries"][d] = defaultdict(int)

    # بررسی اینکه آیا این IP قبلاً در daily_unique_ips ثبت بوده
    # (ثبت در daily_unique_ips در WebSocket handler انجام می‌شه)
    # اینجا فقط کشور را برای IP های جدید ثبت می‌کنیم
    already_counted_key = f"_country_tracked_{d}_{ip}"
    if not _ip_cache.get(already_counted_key):
        stats["daily_countries"][d][cc] += 1
        _ip_cache[already_counted_key] = True  # استفاده از ip_cache برای tracking

# ───────── Subscription Endpoint ─────────
@app.get("/sub/{uid}")
async def subscription(uid: str):
    link = LINKS.get(uid)
    if not link or not link.get("active") or is_expired(link):
        raise HTTPException(404, "link not found or inactive")
    vl = vless_link(uid, link["label"])
    import base64
    encoded = base64.b64encode(vl.encode()).decode()
    return PlainTextResponse(encoded, headers={
        "Content-Disposition": f"attachment; filename=sub.txt",
        "Profile-Title": link["label"],
        "Subscription-Userinfo": f"upload=0; download={link.get('used_bytes',0)}; total={link.get('limit_bytes',0)}; expire=0",
    })

# ───────── API Endpoints ─────────
@app.get("/")
async def root(request: Request):
    return RedirectResponse("/dashboard" if valid_session(request.cookies.get(SESSION_COOKIE)) else "/login")

@app.get("/health")
async def health():
    return {"status": "ok", "uptime": uptime(), "links": len(LINKS), "connections": len(active_connections)}

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    if hash_pw(str(body.get("password", ""))) != auth["hash"]:
        raise HTTPException(401, "رمز عبور اشتباه است")
    token = new_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    SESSIONS.pop(request.cookies.get(SESSION_COOKIE), None)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.post("/api/change-password")
async def api_change_pw(request: Request, _=Depends(require_auth)):
    body = await request.json()
    if hash_pw(str(body.get("current_password", ""))) != auth["hash"]:
        raise HTTPException(400, "رمز فعلی اشتباه است")
    nw = str(body.get("new_password", ""))
    if len(nw) < 4: raise HTTPException(400, "رمز جدید باید حداقل ۴ کاراکتر باشد")
    auth["hash"] = hash_pw(nw)
    cur = request.cookies.get(SESSION_COOKIE)
    for t in list(SESSIONS):
        if t != cur: SESSIONS.pop(t)
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    return {
        "active_connections": len(active_connections),
        "total_traffic_mb": round(stats["total_bytes"] / 1024**2, 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "hourly": dict(hourly_traffic),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "blocked_ips_count": len(BLOCKED_IPS),
        "connections_detail": list(active_connections.values())[:20],
    }

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = str(body.get("label") or "لینک جدید").strip()[:60]
    lv = float(body.get("limit_value") or 0)
    lu = str(body.get("limit_unit") or "GB")
    limit_bytes = 0 if lv <= 0 else parse_bytes(lv, lu)
    days = int(body.get("expires_days") or 0)
    expires_at = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
    max_devices = int(body.get("max_devices") or 0)
    uid = str(uuid.uuid4())
    LINKS[uid] = {
        "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
        "created_at": datetime.now().isoformat(), "expires_at": expires_at,
        "max_devices": max_devices, "active": True,
    }
    save_data()
    return {
        "uuid": uid, "label": label, "active": True,
        "vless_link": vless_link(uid, label), "sub_link": sub_link(uid),
        **LINKS[uid]
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    for uid, d in LINKS.items():
        result.append({
            "uuid": uid, **d,
            "vless_link": vless_link(uid, d["label"]),
            "sub_link": sub_link(uid),
            "active_devices": len(active_link_conns.get(uid, set())),
            "expired": is_expired(d),
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def patch_link(uid: str, request: Request, _=Depends(require_auth)):
    if uid not in LINKS: raise HTTPException(404, "not found")
    body = await request.json()
    link = LINKS[uid]
    if "active" in body: link["active"] = bool(body["active"])
    if "limit_value" in body:
        lv = float(body.get("limit_value") or 0)
        link["limit_bytes"] = 0 if lv <= 0 else parse_bytes(lv, str(body.get("limit_unit", "GB")))
    if body.get("reset_usage"): link["used_bytes"] = 0
    if "label" in body: link["label"] = str(body["label"])[:60]
    if "expires_days" in body:
        days = int(body["expires_days"] or 0)
        link["expires_at"] = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
    if "max_devices" in body: link["max_devices"] = int(body["max_devices"] or 0)
    save_data()
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    LINKS.pop(uid, None)
    save_data()
    return {"ok": True}

@app.get("/api/blocked")
async def get_blocked(_=Depends(require_auth)):
    return {"blocked_ips": list(BLOCKED_IPS)}

@app.post("/api/blocked")
async def block_ip(request: Request, _=Depends(require_auth)):
    body = await request.json()
    ip = str(body.get("ip", "")).strip()
    if not ip: raise HTTPException(400, "IP required")
    BLOCKED_IPS.add(ip)
    save_data()
    return {"ok": True}

@app.delete("/api/blocked/{ip}")
async def unblock_ip(ip: str, _=Depends(require_auth)):
    BLOCKED_IPS.discard(ip)
    save_data()
    return {"ok": True}

@app.get("/api/domains/{ip}")
async def get_domains(ip: str, _=Depends(require_auth)):
    domains = list(ip_domains.get(ip, []))
    return {"ip": ip, "domains": domains}

# ───────── Pages ─────────
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/dashboard")
    return HTMLResponse(LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    await ensure_default()
    if not valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/login")
    return HTMLResponse(DASHBOARD_HTML)

# ───────── HTML Templates ─────────
LOGIN_HTML = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ورود · RVG Gateway v2</title>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Vazirmatn',sans-serif;min-height:100vh;display:flex;align-items:center;
  justify-content:center;background:linear-gradient(135deg,#042C53,#06335e,#11518F);padding:20px}
.card{background:#fff;border-radius:18px;padding:36px 30px;width:100%;max-width:380px;
  box-shadow:0 20px 60px rgba(4,44,83,.4)}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:24px}
.logo-icon{width:48px;height:48px;border-radius:13px;background:linear-gradient(135deg,#2570C2,#042C53);
  display:flex;align-items:center;justify-content:center;color:#fff;font-size:24px}
.logo-name{font-size:16px;font-weight:700;color:#042C53}
.logo-sub{font-size:11px;color:#378ADD;margin-top:2px}
h2{font-size:18px;font-weight:700;color:#042C53;margin-bottom:5px}
.sub{font-size:12.5px;color:#378ADD;margin-bottom:22px}
.group{margin-bottom:16px}
label{display:block;font-size:12px;font-weight:600;color:#11518F;margin-bottom:7px}
input{width:100%;padding:12px 14px;border-radius:10px;border:1.5px solid #CFE3F7;
  font-family:inherit;font-size:14px;outline:none;background:#EEF5FE;color:#042C53;transition:.15s}
input:focus{border-color:#378ADD;background:#fff}
.btn{width:100%;padding:13px;border-radius:10px;border:none;cursor:pointer;
  background:#185FA5;color:#fff;font-family:inherit;font-size:14px;font-weight:600;
  display:flex;align-items:center;justify-content:center;gap:8px;transition:.15s;margin-top:4px}
.btn:hover{background:#11518F}.btn:disabled{opacity:.6;cursor:not-allowed}
.err{background:#FCEBEB;color:#A32D2D;font-size:12.5px;padding:10px 13px;border-radius:9px;
  margin-bottom:14px;display:none;align-items:center;gap:8px}
.err.show{display:flex}
.hint{font-size:11.5px;color:#999;text-align:center;margin-top:10px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon"><i class="ti ti-shield-lock"></i></div>
    <div><div class="logo-name">RVG Gateway v2</div>
    <div class="logo-sub">Render · VLESS · ربات تلگرام</div></div>
  </div>
  <h2>ورود به پنل مدیریت</h2>
  <div class="sub">رمز عبور را وارد کنید</div>
  <div class="err" id="err"><i class="ti ti-alert-circle"></i><span id="err-t"></span></div>
  <div class="group">
    <label>رمز عبور</label>
    <input type="password" id="pw" placeholder="••••••••" autofocus>
  </div>
  <button class="btn" id="btn" onclick="login()"><i class="ti ti-login-2"></i> ورود</button>
  <div class="hint">رمز پیش‌فرض: 123456</div>
</div>
<script>
async function login(){
  const pw=document.getElementById('pw').value;
  const btn=document.getElementById('btn');
  const err=document.getElementById('err');
  err.classList.remove('show');
  btn.disabled=true;btn.innerHTML='<i class="ti ti-loader-2"></i> صبر کنید...';
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:pw})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'خطا');}
    location.href='/dashboard';
  }catch(e){
    document.getElementById('err-t').textContent=e.message;
    err.classList.add('show');
    btn.disabled=false;btn.innerHTML='<i class="ti ti-login-2"></i> ورود';
  }
}
document.getElementById('pw').addEventListener('keydown',e=>e.key==='Enter'&&login());
</script>
</body></html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RVG Gateway v2 · داشبورد</title>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--b50:#E6F1FB;--b100:#B5D4F4;--b400:#378ADD;--b500:#2570C2;--b600:#185FA5;
  --b700:#11518F;--b900:#042C53;--border:#CFE3F7;--bg:#EEF5FE;--sb:#0C1E35}
html,body{height:100%;font-family:'Vazirmatn',sans-serif}
.layout{display:flex;height:100vh;overflow:hidden}
.sb{width:215px;background:var(--sb);display:flex;flex-direction:column;
  border-left:1px solid rgba(255,255,255,.07);flex-shrink:0}
.sb-logo{padding:18px 14px 14px;border-bottom:1px solid rgba(255,255,255,.07)}
.sb-row{display:flex;align-items:center;gap:10px}
.sb-icon{width:36px;height:36px;border-radius:10px;
  background:linear-gradient(135deg,var(--b500),var(--b900));
  display:flex;align-items:center;justify-content:center;color:#fff;font-size:17px;flex-shrink:0}
.sb-name{font-size:14px;font-weight:700;color:#fff}
.sb-sub{font-size:10px;color:var(--b400);margin-top:1px}
.sb-nav{padding:10px 7px;flex:1;overflow-y:auto}
.ni{display:flex;align-items:center;gap:9px;padding:9px 11px;border-radius:9px;
  cursor:pointer;color:#93B8DD;font-size:12.5px;font-weight:500;transition:.15s;margin-bottom:2px}
.ni:hover{background:rgba(255,255,255,.07);color:#fff}
.ni.active{background:rgba(55,138,221,.18);color:#B5D4F4}
.ni i{font-size:16px;width:18px;text-align:center}
.sb-foot{padding:10px 7px;border-top:1px solid rgba(255,255,255,.07)}
.logout{display:flex;align-items:center;gap:8px;padding:8px 11px;border-radius:9px;
  cursor:pointer;color:#E24B4A;font-size:12px;font-weight:500;transition:.15s}
.logout:hover{background:rgba(226,75,74,.1)}
.main{flex:1;overflow-y:auto;background:var(--bg)}
.page{display:none;padding:22px;min-height:100%}.page.active{display:block}
.topbar{display:flex;align-items:flex-start;justify-content:space-between;
  margin-bottom:18px;gap:12px;flex-wrap:wrap}
.topbar-t{font-size:19px;font-weight:700;color:var(--b900)}
.topbar-s{font-size:12px;color:var(--b400);margin-top:3px}
.card{background:#fff;border-radius:13px;padding:17px;border:1px solid var(--border);margin-bottom:14px}
.card-t{font-size:13px;font-weight:700;color:var(--b700);margin-bottom:13px;
  display:flex;align-items:center;gap:6px}
.card-t i{color:var(--b400)}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:14px}
.metric{background:#fff;border-radius:13px;padding:14px;border:1px solid var(--border);text-align:center}
.m-label{font-size:11px;color:var(--b400);margin-bottom:6px;display:flex;align-items:center;justify-content:center;gap:4px}
.m-val{font-size:22px;font-weight:700;color:var(--b900);line-height:1}
.m-unit{font-size:11px;color:var(--b400);margin-right:1px}
.m-sub{font-size:10px;color:var(--b400);margin-top:4px}
.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:20px;font-size:11px;font-weight:600}
.bg{background:#EAF3DE;color:#3B6D11}.br{background:#FCEBEB;color:#A32D2D}
.bb{background:var(--b50);color:var(--b600)}.ba{background:#FAEEDA;color:#854F0B}
.btn{display:inline-flex;align-items:center;gap:5px;padding:8px 14px;border-radius:8px;
  border:none;cursor:pointer;font-family:inherit;font-size:12.5px;font-weight:600;transition:.15s}
.bp{background:var(--b600);color:#fff}.bp:hover{background:var(--b700)}
.bo{background:transparent;color:var(--b600);border:1px solid var(--b100)}.bo:hover{background:var(--b50)}
.bd{background:transparent;color:#A32D2D;border:1px solid #FCBEBE}.bd:hover{background:#FCEBEB}
.btn-sm{padding:5px 10px;font-size:11.5px}
.cfgbox{background:var(--bg);border:1px solid var(--border);border-radius:9px;padding:12px;margin-bottom:10px}
.cfg-lbl{font-size:10.5px;font-weight:700;color:var(--b500);margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px}
.cfg-link{font-size:10.5px;color:var(--b700);word-break:break-all;font-family:monospace;
  background:#fff;padding:7px 9px;border-radius:6px;border:1px solid var(--border);line-height:1.6}
.cfg-acts{display:flex;gap:6px;margin-top:7px;flex-wrap:wrap}
.form-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.fg{display:flex;flex-direction:column;gap:5px}
.fl{font-size:11.5px;font-weight:600;color:var(--b700)}
.fi,.fs{padding:9px 12px;border-radius:8px;border:1px solid var(--border);
  font-family:inherit;font-size:12.5px;background:var(--bg);color:var(--b900);outline:none;transition:.15s}
.fi:focus,.fs:focus{border-color:var(--b400);background:#fff}
.link-card{background:#fff;border:1px solid var(--border);border-radius:11px;padding:15px;margin-bottom:11px}
.lk-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:9px;flex-wrap:wrap;gap:7px}
.lk-name{font-size:13.5px;font-weight:700;color:var(--b900)}
.lk-meta{font-size:11px;color:var(--b400);margin-top:2px}
.usage-bar{height:5px;background:var(--b50);border-radius:3px;margin:7px 0}
.usage-fill{height:100%;border-radius:3px;transition:.3s}
.srow{display:flex;justify-content:space-between;align-items:center;padding:7px 0;
  border-bottom:1px solid var(--bg);font-size:12px}
.srow:last-child{border-bottom:none}
.skey{color:var(--b500);display:flex;align-items:center;gap:5px}
.sval{font-weight:600;color:var(--b900)}
.chart-wrap{height:150px;position:relative}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;
  align-items:center;justify-content:center;z-index:100}
.modal-bg.show{display:flex}
.modal{background:#fff;border-radius:15px;padding:22px;max-width:340px;width:90%;text-align:center}
.modal h3{font-size:14px;font-weight:700;color:var(--b900);margin-bottom:14px}
.toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);
  background:#042C53;color:#fff;padding:9px 18px;border-radius:9px;
  font-size:12.5px;z-index:200;opacity:0;transition:.3s;pointer-events:none;white-space:nowrap}
.toast.show{opacity:1}
.ip-list{max-height:200px;overflow-y:auto}
.ip-item{display:flex;justify-content:space-between;align-items:center;padding:6px 0;
  border-bottom:1px solid var(--bg);font-size:12px}
.ip-item:last-child{border-bottom:none}
@media(max-width:580px){.sb{display:none}.metrics{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="layout">
  <div class="sb">
    <div class="sb-logo">
      <div class="sb-row">
        <div class="sb-icon"><i class="ti ti-shield-lock"></i></div>
        <div><div class="sb-name">RVG Gateway v2</div><div class="sb-sub">Render · VLESS · Bot</div></div>
      </div>
    </div>
    <div class="sb-nav">
      <div class="ni active" onclick="go('overview')" id="nav-overview"><i class="ti ti-layout-dashboard"></i> داشبورد</div>
      <div class="ni" onclick="go('links')" id="nav-links"><i class="ti ti-link"></i> مدیریت لینک‌ها</div>
      <div class="ni" onclick="go('blocked')" id="nav-blocked"><i class="ti ti-ban"></i> IP های بلاک</div>
      <div class="ni" onclick="go('settings')" id="nav-settings"><i class="ti ti-settings"></i> تنظیمات</div>
    </div>
    <div class="sb-foot">
      <div class="logout" onclick="logout()"><i class="ti ti-logout"></i> خروج</div>
    </div>
  </div>

  <div class="main">

    <!-- Overview -->
    <div class="page active" id="page-overview">
      <div class="topbar">
        <div><div class="topbar-t">داشبورد</div><div class="topbar-s">وضعیت کلی RVG Gateway v2</div></div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <span class="badge bb" id="uptime-badge">⏱ —</span>
        </div>
      </div>
      <div class="metrics">
        <div class="metric"><div class="m-label"><i class="ti ti-wifi"></i> اتصالات</div>
          <div class="m-val" id="m-conn">—</div><div class="m-sub">فعال</div></div>
        <div class="metric"><div class="m-label"><i class="ti ti-transfer"></i> ترافیک</div>
          <div class="m-val" id="m-traffic">—<span class="m-unit">MB</span></div><div class="m-sub">کل</div></div>
        <div class="metric"><div class="m-label"><i class="ti ti-link"></i> لینک‌ها</div>
          <div class="m-val" id="m-links">—</div><div class="m-sub">فعال</div></div>
        <div class="metric"><div class="m-label"><i class="ti ti-ban"></i> بلاک</div>
          <div class="m-val" id="m-blocked">—</div><div class="m-sub">IP بلاک</div></div>
      </div>
      <div class="card">
        <div class="card-t"><i class="ti ti-key"></i> کانفیگ پیش‌فرض</div>
        <div id="def-cfg">در حال بارگذاری...</div>
      </div>
      <div class="card">
        <div class="card-t"><i class="ti ti-chart-area"></i> ترافیک ساعتی (MB)</div>
        <div class="chart-wrap"><canvas id="chart"></canvas></div>
      </div>
      <div class="card">
        <div class="card-t"><i class="ti ti-wifi"></i> اتصالات فعال</div>
        <div id="conn-list"><div style="color:var(--b400);font-size:12px">هیچ اتصالی فعال نیست</div></div>
      </div>
    </div>

    <!-- Links -->
    <div class="page" id="page-links">
      <div class="topbar">
        <div><div class="topbar-t">مدیریت لینک‌ها</div><div class="topbar-s">ساخت و مدیریت کانفیگ‌های VLESS</div></div>
        <span class="badge bb" id="links-count">۰ لینک</span>
      </div>
      <div class="card">
        <div class="card-t"><i class="ti ti-plus"></i> لینک جدید</div>
        <div class="form-row">
          <div class="fg" style="flex:2;min-width:150px">
            <label class="fl">عنوان</label>
            <input class="fi" id="nl-label" placeholder="مثلاً: برای علی">
          </div>
          <div class="fg">
            <label class="fl">سهمیه</label>
            <div style="display:flex;gap:5px">
              <input class="fi" id="nl-limit" type="number" placeholder="0=∞" style="width:80px">
              <select class="fs" id="nl-unit" style="width:65px">
                <option value="GB">GB</option><option value="MB">MB</option>
              </select>
            </div>
          </div>
          <div class="fg">
            <label class="fl">انقضا (روز)</label>
            <input class="fi" id="nl-days" type="number" placeholder="0=∞" style="width:80px">
          </div>
          <div class="fg">
            <label class="fl">حداکثر دستگاه</label>
            <input class="fi" id="nl-devices" type="number" placeholder="0=∞" style="width:90px">
          </div>
          <div class="fg" style="justify-content:flex-end">
            <label class="fl">&nbsp;</label>
            <button class="btn bp" onclick="createLink()"><i class="ti ti-plus"></i> ساخت</button>
          </div>
        </div>
      </div>
      <div id="links-list"></div>
    </div>

    <!-- Blocked IPs -->
    <div class="page" id="page-blocked">
      <div class="topbar">
        <div><div class="topbar-t">IP های بلاک</div><div class="topbar-s">مدیریت IP های مسدود</div></div>
      </div>
      <div class="card">
        <div class="card-t"><i class="ti ti-ban"></i> بلاک IP جدید</div>
        <div style="display:flex;gap:10px">
          <input class="fi" id="new-ip" placeholder="مثلاً: 1.2.3.4" style="flex:1">
          <button class="btn bp" onclick="blockIP()"><i class="ti ti-ban"></i> بلاک</button>
        </div>
      </div>
      <div class="card">
        <div class="card-t"><i class="ti ti-list"></i> لیست IP های بلاک</div>
        <div id="blocked-list" class="ip-list"></div>
      </div>
    </div>

    <!-- Settings -->
    <div class="page" id="page-settings">
      <div class="topbar">
        <div><div class="topbar-t">تنظیمات</div><div class="topbar-s">تنظیمات پنل</div></div>
      </div>
      <div class="card">
        <div class="card-t"><i class="ti ti-lock"></i> تغییر رمز عبور</div>
        <div class="form-row">
          <div class="fg" style="flex:1;min-width:150px">
            <label class="fl">رمز فعلی</label>
            <input class="fi" type="password" id="cur-pw">
          </div>
          <div class="fg" style="flex:1;min-width:150px">
            <label class="fl">رمز جدید</label>
            <input class="fi" type="password" id="new-pw">
          </div>
          <div class="fg" style="justify-content:flex-end">
            <label class="fl">&nbsp;</label>
            <button class="btn bp" onclick="changePw()"><i class="ti ti-check"></i> ذخیره</button>
          </div>
        </div>
        <div id="pw-msg" style="font-size:12px;margin-top:6px"></div>
      </div>
      <div class="card">
        <div class="card-t"><i class="ti ti-info-circle"></i> اطلاعات سرور</div>
        <div class="srow"><span class="skey">پروتکل</span><span class="sval">VLESS WebSocket TLS</span></div>
        <div class="srow"><span class="skey">پلتفرم</span><span class="sval">Render.com</span></div>
        <div class="srow"><span class="skey">Anti-sleep</span><span class="sval">✅ هر ۱۰ دقیقه</span></div>
        <div class="srow"><span class="skey">ذخیره‌سازی</span><span class="sval">JSON (پایدار)</span></div>
        <div class="srow"><span class="skey">اپ پیشنهادی</span><span class="sval">Nekobox · Hiddify · v2rayNG</span></div>
      </div>
    </div>

  </div>
</div>

<!-- Domains Modal -->
<div class="modal-bg" id="domains-modal" style="align-items:center">
  <div class="modal" style="max-width:460px;width:95%;text-align:right">
    <h3 id="domains-title" style="text-align:right">🌍 سایت‌های بازدیدشده</h3>
    <div id="domains-list" style="max-height:320px;overflow-y:auto;margin:12px 0;font-size:12px"></div>
    <button class="btn bo" style="width:100%;margin-top:6px" onclick="document.getElementById('domains-modal').classList.remove('show')"><i class="ti ti-x"></i> بستن</button>
  </div>
</div>

<!-- QR Modal -->
<div class="modal-bg" id="qr-modal">
  <div class="modal">
    <h3 id="qr-title">QR کد</h3>
    <div id="qr-container" style="display:flex;justify-content:center"></div>
    <button class="btn bo" style="width:100%;margin-top:14px" onclick="closeQr()"><i class="ti ti-x"></i> بستن</button>
  </div>
</div>
<div class="toast" id="toast"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<script>
// Nav
function go(name){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.ni').forEach(n=>n.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  document.getElementById('nav-'+name).classList.add('active');
  if(name==='links') loadLinks();
  if(name==='blocked') loadBlocked();
}
function toast(msg,d=2400){
  const t=document.getElementById('toast');
  t.textContent=msg;t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),d);
}
function copy(txt){navigator.clipboard.writeText(txt).then(()=>toast('کپی شد ✓'))}
let qrObj=null;
function showQr(txt,title){
  document.getElementById('qr-title').textContent=title||'QR';
  const c=document.getElementById('qr-container');c.innerHTML='';
  qrObj=new QRCode(c,{text:txt,width:220,height:220,correctLevel:QRCode.CorrectLevel.M});
  document.getElementById('qr-modal').classList.add('show');
}
function closeQr(){document.getElementById('qr-modal').classList.remove('show')}

// Stats
let chart=null;
async function loadStats(){
  try{
    const d=await fetch('/stats').then(r=>r.json());
    document.getElementById('m-conn').textContent=d.active_connections;
    document.getElementById('m-traffic').innerHTML=d.total_traffic_mb+'<span class="m-unit">MB</span>';
    document.getElementById('m-links').textContent=d.links_count;
    document.getElementById('m-blocked').textContent=d.blocked_ips_count;
    document.getElementById('uptime-badge').textContent='⏱ '+d.uptime;
    // Chart
    const hours=Array.from({length:24},(_,i)=>String(i).padStart(2,'0')+':00');
    const vals=hours.map(h=>(d.hourly[h]||0)/1024/1024);
    if(!chart){
      chart=new Chart(document.getElementById('chart').getContext('2d'),{
        type:'line',data:{labels:hours,datasets:[{label:'MB',data:vals,borderColor:'#2570C2',
          backgroundColor:'rgba(37,112,194,.1)',fill:true,tension:.4,pointRadius:2}]},
        options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
          scales:{x:{ticks:{font:{size:9},maxTicksLimit:8}},y:{ticks:{font:{size:9}}}}}
      });
    } else {chart.data.datasets[0].data=vals;chart.update();}
    // Active connections
    const cl=document.getElementById('conn-list');
    if(!d.connections_detail||!d.connections_detail.length){
      cl.innerHTML='<div style="color:var(--b400);font-size:12px">هیچ اتصالی فعال نیست</div>';
    } else {
      cl.innerHTML=d.connections_detail.map(c=>`
        <div class="srow">
          <span class="skey"><i class="ti ti-wifi"></i> ${c.ip||'—'}</span>
          <span class="sval" style="display:flex;align-items:center;gap:8px">
            ${fmtBytes(c.bytes||0)}
            <button class="btn bo btn-sm" onclick="showDomains('${c.ip}')"><i class="ti ti-world"></i> سایت‌ها</button>
          </span>
        </div>`).join('');
    }
  }catch(e){}
}

// Default config
async function loadDefCfg(){
  try{
    const d=await fetch('/api/links').then(r=>r.json());
    const lnk=d.links.find(l=>l.label==='پیش‌فرض')||d.links[0];
    if(!lnk){document.getElementById('def-cfg').textContent='هیچ لینکی یافت نشد';return;}
    document.getElementById('def-cfg').innerHTML=`
      <div class="cfgbox">
        <div class="cfg-lbl"><i class="ti ti-key"></i> VLESS Link</div>
        <div class="cfg-link">${lnk.vless_link}</div>
        <div class="cfg-acts">
          <button class="btn bp btn-sm" onclick="copy('${lnk.vless_link}')"><i class="ti ti-copy"></i> کپی</button>
          <button class="btn bo btn-sm" onclick="showQr('${lnk.vless_link}','QR · VLESS')"><i class="ti ti-qrcode"></i> QR</button>
          <button class="btn bo btn-sm" onclick="copy('${lnk.sub_link}')"><i class="ti ti-rss"></i> Sub Link</button>
        </div>
      </div>`;
  }catch(e){}
}

// Format
function fmtBytes(b){
  if(!b||b===0)return'نامحدود ♾️';
  if(b>=1024**3)return(b/1024**3).toFixed(1)+' GB';
  if(b>=1024**2)return(b/1024**2).toFixed(1)+' MB';
  return(b/1024).toFixed(1)+' KB';
}

// Links
async function loadLinks(){
  try{
    const d=await fetch('/api/links').then(r=>r.json());
    document.getElementById('links-count').textContent=d.links.length+' لینک';
    const el=document.getElementById('links-list');
    if(!d.links.length){el.innerHTML='<div style="text-align:center;padding:40px;color:var(--b400)">هیچ لینکی وجود ندارد</div>';return;}
    el.innerHTML=d.links.map(l=>{
      const pct=l.limit_bytes>0?Math.min(100,Math.round(l.used_bytes/l.limit_bytes*100)):0;
      const barClr=pct>90?'#E24B4A':pct>70?'#D99A2B':'#2570C2';
      const expBadge=l.expired?'<span class="badge br">⏰ منقضی</span>':'';
      const expDate=l.expires_at?l.expires_at.slice(0,10):'نامحدود';
      return`<div class="link-card">
        <div class="lk-head">
          <div>
            <div class="lk-name">${l.label} ${expBadge}</div>
            <div class="lk-meta">ساخته شده: ${l.created_at.slice(0,10)} · انقضا: ${expDate} · دستگاه: ${l.active_devices}/${l.max_devices||'∞'}</div>
          </div>
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
            <span class="badge ${l.active&&!l.expired?'bg':'br'}">${l.active&&!l.expired?'● فعال':'● غیرفعال'}</span>
            <div style="display:flex;gap:5px">
              <button class="btn bo btn-sm" onclick="toggleLink('${l.uuid}',${!l.active})"><i class="ti ti-${l.active?'pause':'play'}"></i></button>
              <button class="btn bo btn-sm" onclick="resetUsage('${l.uuid}')"><i class="ti ti-refresh"></i></button>
              <button class="btn bd btn-sm" onclick="delLink('${l.uuid}')"><i class="ti ti-trash"></i></button>
            </div>
          </div>
        </div>
        <div style="font-size:11px;color:var(--b400);margin-bottom:5px">
          مصرف: ${fmtBytes(l.used_bytes)} از ${fmtBytes(l.limit_bytes)}
          ${l.limit_bytes>0?`(${pct}%)`:''}
        </div>
        ${l.limit_bytes>0?`<div class="usage-bar"><div class="usage-fill" style="width:${pct}%;background:${barClr}"></div></div>`:''}
        <div class="cfgbox" style="margin-top:8px">
          <div class="cfg-lbl">VLESS Link</div>
          <div class="cfg-link">${l.vless_link}</div>
          <div class="cfg-acts">
            <button class="btn bp btn-sm" onclick="copy('${l.vless_link}')"><i class="ti ti-copy"></i> کپی</button>
            <button class="btn bo btn-sm" onclick="showQr('${l.vless_link}','QR · ${l.label}')"><i class="ti ti-qrcode"></i> QR</button>
            <button class="btn bo btn-sm" onclick="copy('${l.sub_link}')"><i class="ti ti-rss"></i> Sub</button>
          </div>
        </div>
      </div>`;
    }).join('');
  }catch(e){}
}

async function createLink(){
  const label=document.getElementById('nl-label').value.trim()||'لینک جدید';
  const limit=parseFloat(document.getElementById('nl-limit').value)||0;
  const unit=document.getElementById('nl-unit').value;
  const days=parseInt(document.getElementById('nl-days').value)||0;
  const devices=parseInt(document.getElementById('nl-devices').value)||0;
  try{
    const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label,limit_value:limit,limit_unit:unit,expires_days:days,max_devices:devices})});
    if(!r.ok)throw new Error();
    toast('لینک ساخته شد ✓');
    document.getElementById('nl-label').value='';
    document.getElementById('nl-limit').value='';
    document.getElementById('nl-days').value='';
    document.getElementById('nl-devices').value='';
    loadLinks();loadDefCfg();
  }catch(e){toast('خطا در ساخت لینک');}
}
async function toggleLink(uid,active){
  await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active})});
  loadLinks();toast(active?'فعال شد':'غیرفعال شد');
}
async function resetUsage(uid){
  await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});
  loadLinks();toast('مصرف ریست شد');
}
async function delLink(uid){
  if(!confirm('حذف شود؟'))return;
  await fetch(`/api/links/${uid}`,{method:'DELETE'});
  loadLinks();toast('حذف شد');
}

// Blocked IPs
async function loadBlocked(){
  try{
    const d=await fetch('/api/blocked').then(r=>r.json());
    const el=document.getElementById('blocked-list');
    if(!d.blocked_ips.length){
      el.innerHTML='<div style="color:var(--b400);font-size:12px;padding:10px 0">هیچ IP بلاکی وجود ندارد</div>';
      return;
    }
    el.innerHTML=d.blocked_ips.map(ip=>`
      <div class="ip-item">
        <span style="font-family:monospace;font-size:12px">${ip}</span>
        <button class="btn bd btn-sm" onclick="unblockIP('${ip}')"><i class="ti ti-x"></i> آنبلاک</button>
      </div>`).join('');
  }catch(e){}
}
async function blockIP(){
  const ip=document.getElementById('new-ip').value.trim();
  if(!ip)return;
  await fetch('/api/blocked',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
  document.getElementById('new-ip').value='';
  loadBlocked();toast('IP بلاک شد');
}
async function unblockIP(ip){
  await fetch(`/api/blocked/${ip}`,{method:'DELETE'});
  loadBlocked();toast('IP آنبلاک شد');
}

// Password
async function changePw(){
  const cur=document.getElementById('cur-pw').value;
  const nw=document.getElementById('new-pw').value;
  const msg=document.getElementById('pw-msg');
  try{
    const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({current_password:cur,new_password:nw})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.detail);
    msg.style.color='#3B6D11';msg.textContent='رمز تغییر کرد ✓';
    document.getElementById('cur-pw').value='';document.getElementById('new-pw').value='';
  }catch(e){msg.style.color='#A32D2D';msg.textContent=e.message;}
}
async function logout(){
  await fetch('/api/logout',{method:'POST'});location.href='/login';
}

// Domains
async function showDomains(ip){
  document.getElementById('domains-title').textContent='🌍 سایت‌های '+ip;
  const el=document.getElementById('domains-list');
  el.innerHTML='<div style="color:var(--b400)">در حال بارگذاری...</div>';
  document.getElementById('domains-modal').classList.add('show');
  try{
    const d=await fetch('/api/domains/'+ip).then(r=>r.json());
    if(!d.domains||!d.domains.length){
      el.innerHTML='<div style="color:var(--b400);padding:10px 0">هیچ دامنه‌ای ثبت نشده</div>';
      return;
    }
    el.innerHTML=d.domains.map((e,i)=>{
      const proto=e.port===443?'🔒':e.port===80?'🌐':'🔌';
      return`<div class="srow">
        <span class="skey">${i+1}. ${proto} <span style="font-family:monospace">${e.domain}</span></span>
        <span style="color:var(--b400);font-size:11px">⏰${e.time} :${e.port}</span>
      </div>`;
    }).join('');
  }catch(e){el.innerHTML='<div style="color:#A32D2D">خطا در بارگذاری</div>';}
}

// Init
loadStats();loadDefCfg();
setInterval(loadStats,15000);
</script>
</body></html>"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, log_level="info", workers=1)