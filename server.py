#!/usr/bin/env python3
"""PackScan local server (Python fallback if Node is not installed)."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import gzip
import json
import mimetypes
import os
import re
import secrets
import sys
import threading
import time
import uuid
import urllib.parse
import urllib.request
import urllib.error

PORT = int(os.environ.get("PORT", "8787"))
API_VERSION = os.environ.get("SHOPIFY_API_VERSION", "2026-07")
ROOT = os.path.dirname(os.path.abspath(__file__))
SHOP_RE = re.compile(r"^[a-z0-9][a-z0-9-]*\.myshopify\.com$")
HOST = (os.environ.get("HOST") or os.environ.get("APP_URL") or "").rstrip("/")
API_KEY = os.environ.get("SHOPIFY_API_KEY") or os.environ.get("SHOPIFY_CLIENT_ID") or ""
API_SECRET = os.environ.get("SHOPIFY_API_SECRET") or os.environ.get("SHOPIFY_CLIENT_SECRET") or ""
SCOPES = os.environ.get(
    "SHOPIFY_SCOPES",
    "read_orders,write_orders,read_products,read_locations,read_merchant_managed_fulfillment_orders,write_merchant_managed_fulfillment_orders,write_fulfillments",
)
HOSTED = bool(API_KEY and API_SECRET and HOST)
ENVIRONMENT = os.environ.get("PACKSCAN_ENV", "").strip().lower()
HOSTED_PRODUCTION = HOSTED and (
    ENVIRONMENT == "production" or (HOST.startswith("https://") and ENVIRONMENT != "development")
)
SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
if not SESSION_SECRET:
    if HOSTED_PRODUCTION:
        raise RuntimeError("SESSION_SECRET must be explicitly configured for a hosted production app")
    SESSION_SECRET = secrets.token_urlsafe(32)
try:
    SESSION_TTL_SECONDS = max(300, min(int(os.environ.get("SESSION_TTL_SECONDS", "2592000")), 2592000))
except ValueError:
    SESSION_TTL_SECONDS = 2592000
SHOPS_PATH = os.path.join(ROOT, "data", "shops.json")
OAUTH_STATE_TTL_SECONDS = 600
SHOPIFY_LAUNCH_TTL_SECONDS = 300
OAUTH_STATES = {}
OAUTH_STATES_LOCK = threading.Lock()
STATIC_ASSETS = {
    "/": "index.html",
    "/index.html": "index.html",
    "/privacy": "privacy.html",
    "/privacy.html": "privacy.html",
    "/css/app.css": os.path.join("css", "app.css"),
    "/logo.png": "logo.png",
}


def load_shops():
    try:
        with open(SHOPS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_shops(data):
    os.makedirs(os.path.dirname(SHOPS_PATH), exist_ok=True)
    tmp = SHOPS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, SHOPS_PATH)


def sign_session(shop, expires_at):
    import hashlib, hmac
    value = "%s|%s" % (shop, expires_at)
    sig = hmac.new(SESSION_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    return value + "|" + sig


def read_session(cookie_header):
    import hmac
    if not cookie_header:
        return None
    parts = {}
    for piece in cookie_header.split(";"):
        if "=" in piece:
            k, v = piece.strip().split("=", 1)
            parts[k] = v
    raw = urllib.parse.unquote(parts.get("packscan_session") or "")
    if raw.count("|") != 2:
        return None
    shop, expires_at, sig = raw.rsplit("|", 2)
    try:
        expires_at = int(expires_at)
    except ValueError:
        return None
    if expires_at <= int(time.time()):
        return None
    expect = sign_session(shop, expires_at).rsplit("|", 1)[1]
    if not hmac.compare_digest(sig, expect):
        return None
    return shop if SHOP_RE.match(shop) else None


def verify_webhook_hmac(raw_bytes, header_hmac):
    import hashlib, hmac, base64
    if not API_SECRET or not header_hmac:
        return False
    digest = hmac.new(API_SECRET.encode("utf-8"), raw_bytes, hashlib.sha256).digest()
    computed = base64.b64encode(digest).decode("utf-8")
    return hmac.compare_digest(computed, header_hmac.strip())


def append_compliance_log(entry):
    path = os.path.join(ROOT, "data", "compliance.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rows = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            rows = json.load(f)
            if not isinstance(rows, list):
                rows = []
    except Exception:
        rows = []
    rows.append(entry)
    rows = rows[-500:]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    os.replace(tmp, path)


def handle_compliance_payload(topic, payload):
    shop = safe_shop((payload.get("shop_domain") or payload.get("shop") or ""))
    now = int(time.time())
    if topic == "shop/redact" or topic == "app/uninstalled":
        shops = load_shops()
        if shop and shop in shops:
            del shops[shop]
            save_shops(shops)
    append_compliance_log({
        "at": now,
        "topic": topic,
        "shop": shop,
        "customer_id": ((payload.get("customer") or {}).get("id")),
        "shop_id": payload.get("shop_id"),
    })
    return True


WEBHOOK_PATH_TOPICS = {
    "/webhooks/customers/data_request": "customers/data_request",
    "/webhooks/customers/redact": "customers/redact",
    "/webhooks/shop/redact": "shop/redact",
    "/webhooks/app/uninstalled": "app/uninstalled",
}
WEBHOOK_TOPICS = set(WEBHOOK_PATH_TOPICS.values())


def verify_hmac(qs):
    import hashlib, hmac
    params = urllib.parse.parse_qs(qs, keep_blank_values=True)
    flat = {k: v[0] for k, v in params.items()}
    digest = flat.pop("hmac", "")
    message = "&".join("%s=%s" % (k, flat[k]) for k in sorted(flat))
    calc = hmac.new(API_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc, digest)


def verify_shopify_launch(qs, now=None):
    params = urllib.parse.parse_qs(qs, keep_blank_values=True)
    shop = safe_shop((params.get("shop") or [""])[0])
    timestamp = (params.get("timestamp") or [""])[0]
    if not shop or not timestamp or not verify_hmac(qs):
        return None
    try:
        requested_at = int(timestamp)
    except ValueError:
        return None
    current_time = int(time.time() if now is None else now)
    if abs(current_time - requested_at) > SHOPIFY_LAUNCH_TTL_SECONDS:
        return None
    return shop if shop in load_shops() else None


def create_oauth_state(shop, browser):
    now = time.time()
    state = secrets.token_urlsafe(32)
    with OAUTH_STATES_LOCK:
        expired = [key for key, value in OAUTH_STATES.items() if value["expires_at"] <= now]
        for key in expired:
            del OAUTH_STATES[key]
        OAUTH_STATES[state] = {
            "shop": shop,
            "browser": browser,
            "expires_at": now + OAUTH_STATE_TTL_SECONDS,
        }
    return state


def consume_oauth_state(state, shop, browser):
    with OAUTH_STATES_LOCK:
        saved = OAUTH_STATES.pop(state, None)
    return bool(
        saved
        and saved["expires_at"] > time.time()
        and secrets.compare_digest(saved["shop"], shop)
        and secrets.compare_digest(saved["browser"], browser)
    )


def _oauth_post(shop, fields):
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        "https://%s/admin/oauth/access_token" % shop,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            err = json.loads(raw)
        except Exception:
            err = {"error": raw[:300]}
        raise RuntimeError(err.get("error_description") or err.get("error") or raw[:200])


def store_shop_tokens(shop, data, extra=None):
    shops = load_shops()
    rec = shops.get(shop) or {}
    rec.update(extra or {})
    rec["access_token"] = data.get("access_token") or rec.get("access_token")
    if data.get("refresh_token"):
        rec["refresh_token"] = data["refresh_token"]
    if data.get("scope"):
        rec["scope"] = data["scope"]
    rec["installed_at"] = rec.get("installed_at") or int(time.time())
    rec["updated_at"] = int(time.time())
    expires_in = int(data.get("expires_in") or 0)
    rec["expires_at"] = int(time.time()) + expires_in if expires_in else rec.get("expires_at")
    r_exp = int(data.get("refresh_token_expires_in") or 0)
    rec["refresh_expires_at"] = int(time.time()) + r_exp if r_exp else rec.get("refresh_expires_at")
    shops[shop] = rec
    save_shops(shops)
    return rec.get("access_token")


def refresh_offline_token(shop, rec):
    refresh = (rec or {}).get("refresh_token")
    if not refresh or not API_KEY or not API_SECRET:
        return None
    data = _oauth_post(shop, {
        "client_id": API_KEY,
        "client_secret": API_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh,
    })
    return store_shop_tokens(shop, data)


def migrate_expiring_token(shop, old_token):
    if not old_token or not API_KEY or not API_SECRET:
        return None
    data = _oauth_post(shop, {
        "client_id": API_KEY,
        "client_secret": API_SECRET,
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": old_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "requested_token_type": "urn:shopify:params:oauth:token-type:offline-access-token",
        "expiring": "1",
    })
    return store_shop_tokens(shop, data)


def shop_access_token(shop):
    rec = load_shops().get(shop) or {}
    token = rec.get("access_token")
    if not token:
        return None
    exp = rec.get("expires_at")
    if rec.get("refresh_token") and (not exp or exp < time.time() + 120):
        try:
            token = refresh_offline_token(shop, rec) or token
        except Exception as e:
            print("TOKEN REFRESH FAILED", shop, e)
    return token


def exchange_oauth_code(shop, code):
    data = _oauth_post(shop, {
        "client_id": API_KEY,
        "client_secret": API_SECRET,
        "code": code,
        "expiring": "1",
    })
    token = data.get("access_token")
    if not token:
        raise RuntimeError("OAuth exchange failed")
    store_shop_tokens(shop, data)
    return token


LABEL_HISTORY_PATH = os.path.join(ROOT, "data", "label_history.json")
LABEL_HISTORY_LOCK = None


def _label_history_lock():
    global LABEL_HISTORY_LOCK
    if LABEL_HISTORY_LOCK is None:
        import threading
        LABEL_HISTORY_LOCK = threading.Lock()
    return LABEL_HISTORY_LOCK


def load_label_history():
    try:
        with open(LABEL_HISTORY_PATH, "r", encoding="utf-8") as f:
            rows = json.load(f)
            return rows if isinstance(rows, list) else []
    except Exception:
        return []


def save_label_history(rows):
    os.makedirs(os.path.dirname(LABEL_HISTORY_PATH), exist_ok=True)
    tmp = LABEL_HISTORY_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    os.replace(tmp, LABEL_HISTORY_PATH)


def add_label_history(entry):
    with _label_history_lock():
        rows = load_label_history()
        entry["id"] = uuid.uuid4().hex
        entry["createdAt"] = int(time.time())
        entry["voided"] = False
        rows.append(entry)
        cutoff = time.time() - 7 * 86400
        rows = [r for r in rows if r.get("createdAt", 0) >= cutoff]
        save_label_history(rows)
        return entry


def update_label_history(label_id, **fields):
    with _label_history_lock():
        rows = load_label_history()
        found = None
        for r in rows:
            if r.get("id") == label_id:
                r.update(fields)
                found = r
                break
        if found is not None:
            save_label_history(rows)
        return found


def recent_label_history(hours=24):
    cutoff = time.time() - hours * 3600
    rows = [r for r in load_label_history() if r.get("createdAt", 0) >= cutoff]
    rows.sort(key=lambda r: r.get("createdAt", 0), reverse=True)
    return rows


def safe_shop(raw):
    if not raw:
        return None
    s = raw.strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0]
    if "." not in s:
        s = s + ".myshopify.com"
    return s if SHOP_RE.match(s) else None


class Handler(SimpleHTTPRequestHandler):
    def _evidence(self, label, value=None):
        path = os.environ.get("PACKSCAN_EVIDENCE_LOG", "").strip()
        if not path:
            return
        line = label
        if value is not None:
            line += " " + json.dumps(value, ensure_ascii=True)
        with open(path, "a", encoding="utf-8") as evidence:
            evidence.write(line + "\n")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def _cookie(self, name):
        cookie_header = self.headers.get("Cookie") or ""
        for piece in cookie_header.split(";"):
            if "=" in piece:
                key, value = piece.strip().split("=", 1)
                if key == name:
                    return urllib.parse.unquote(value)
        return ""

    def _cookie_value(self, name, value, max_age):
        same_site = "None" if HOST.startswith("https://") else "Lax"
        cookie = "%s=%s; Path=/; HttpOnly; SameSite=%s; Max-Age=%s" % (
            name,
            urllib.parse.quote(value),
            same_site,
            max_age,
        )
        if HOST.startswith("https://"):
            cookie += "; Secure; Partitioned"
        return cookie

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.end_headers()

    def _serve_asset(self, path, send_body=True):
        relative_path = STATIC_ASSETS.get(path)
        if not relative_path:
            return False
        asset_path = os.path.join(ROOT, relative_path)
        try:
            size = os.path.getsize(asset_path)
            content_type = mimetypes.guess_type(asset_path)[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(size))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if send_body:
                with open(asset_path, "rb") as asset:
                    self.wfile.write(asset.read())
        except OSError:
            self._json(404, {"error": "Asset not found"})
        return True

    def do_HEAD(self):
        parsed = urllib.parse.urlparse(self.path)
        if self._serve_asset(parsed.path, send_body=False):
            return
        self.send_error(404)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = parsed.query
        params = urllib.parse.parse_qs(qs)

        if path == "/api/health":
            return self._json(200, {"ok": True, "server": "python", "hosted": HOSTED, "ups": True, "fedex": True, "stamps": True})

        if path in ("/", "/index.html") and params.get("hmac"):
            shop = verify_shopify_launch(qs)
            if not shop:
                return self._json(401, {"error": "Invalid or expired Shopify app launch"})
            expires_at = int(time.time()) + SESSION_TTL_SECONDS
            self.send_response(302)
            self.send_header("Set-Cookie", self._cookie_value("packscan_session", sign_session(shop, expires_at), SESSION_TTL_SECONDS))
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/api/labels/history":
            hours = 24
            try:
                hours = float((params.get("hours") or ["24"])[0])
            except Exception:
                hours = 24
            return self._json(200, {"labels": recent_label_history(hours)})

        if path == "/api/me":
            shop = read_session(self.headers.get("Cookie"))
            installed = bool(shop and shop in load_shops())
            return self._json(200, {"hosted": HOSTED, "shop": shop, "installed": installed})

        if path == "/auth":
            shop = safe_shop((params.get("shop") or [""])[0])
            if not shop or not HOSTED:
                return self._json(400, {"error": "Set HOST, SHOPIFY_API_KEY, and SHOPIFY_API_SECRET, and pass ?shop=store.myshopify.com"})
            browser = self._cookie("packscan_oauth_browser")
            new_browser = not browser
            if not browser:
                browser = secrets.token_urlsafe(32)
            state = create_oauth_state(shop, browser)
            redir = HOST + "/auth/callback"
            url = (
                "https://%s/admin/oauth/authorize?client_id=%s&scope=%s&redirect_uri=%s&state=%s"
                % (shop, API_KEY, urllib.parse.quote(SCOPES), urllib.parse.quote(redir, safe=""), urllib.parse.quote(state, safe=""))
            )
            self.send_response(302)
            if new_browser:
                self.send_header("Set-Cookie", self._cookie_value("packscan_oauth_browser", browser, OAUTH_STATE_TTL_SECONDS))
            self.send_header("Location", url)
            self.end_headers()
            return

        if path == "/auth/callback":
            if not verify_hmac(qs):
                return self._json(401, {"error": "Invalid HMAC"})
            shop = safe_shop((params.get("shop") or [""])[0])
            code = (params.get("code") or [""])[0]
            state = (params.get("state") or [""])[0]
            browser = self._cookie("packscan_oauth_browser")
            if not shop or not code or not state or not browser:
                return self._json(400, {"error": "Missing OAuth callback parameters"})
            if not consume_oauth_state(state, shop, browser):
                return self._json(401, {"error": "Invalid or expired OAuth state"})
            try:
                exchange_oauth_code(shop, code)
            except Exception as e:
                return self._json(401, {"error": str(e)})
            expires_at = int(time.time()) + SESSION_TTL_SECONDS
            cookie = self._cookie_value("packscan_session", sign_session(shop, expires_at), SESSION_TTL_SECONDS)
            self.send_response(302)
            self.send_header("Set-Cookie", cookie)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/config.js":
            shop = read_session(self.headers.get("Cookie")) or ""
            demo_mode = os.environ.get("PACKSCAN_DEMO_MODE", "") == "1"
            demo_fedex_available = all(
                os.environ.get(name, "").strip()
                for name in (
                    "PACKSCAN_DEMO_FEDEX_KEY",
                    "PACKSCAN_DEMO_FEDEX_SECRET",
                    "PACKSCAN_DEMO_FEDEX_ACCOUNT",
                )
            )
            body = (
                "window.PACKSCAN_HOSTED = %s; window.PACKSCAN_SHOP = %s; "
                "window.PACKSCAN_DEMO_MODE = %s; window.PACKSCAN_DEMO_FEDEX_AVAILABLE = %s;\n"
                % (
                    "true" if HOSTED else "false",
                    json.dumps(shop),
                    "true" if demo_mode else "false",
                    "true" if demo_fedex_available else "false",
                )
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode())
            return

        if self._serve_asset(path):
            return
        return self._json(404, {"error": "Not found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/webhooks" or path.startswith("/webhooks/"):
            return self._compliance_webhook(path)
        if path == "/api/fedex/label":
            return self._fedex_label()
        if path == "/api/fedex/rates":
            return self._fedex_rates()
        if path == "/api/ups/rates":
            return self._safe("UPS rates", self._ups_rates)
        if path == "/api/ups/label":
            return self._safe("UPS label", self._ups_label)
        if path in ("/api/usps/rates", "/api/stamps/rates"):
            return self._safe("Stamps rates", self._stamps_rates)
        if path in ("/api/usps/label", "/api/stamps/label"):
            return self._safe("Stamps label", self._stamps_label)
        if path == "/api/labels/void":
            return self._safe("Void label", self._void_label)
        if path == "/api/labels/record":
            return self._safe("Record label", self._record_label)
        if path != "/api/shopify":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            payload = json.loads(raw or "{}")
        except json.JSONDecodeError:
            return self._json(400, {"error": "Invalid JSON"})

        if not isinstance(payload, dict) or not payload.get("query"):
            return self._json(400, {"error": "Missing GraphQL query"})
        shop = read_session(self.headers.get("Cookie"))
        token = shop_access_token(shop) if shop else None
        if not token:
            return self._json(401, {"error": "Install PackScan from Shopify Admin to connect this browser"})

        try:
            status, data = self._admin(shop, token, payload)
            raw = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
            if status in (401, 403) and "Non-expiring access tokens" in raw:
                try:
                    token = migrate_expiring_token(shop, token) or token
                    status, data = self._admin(shop, token, payload)
                except Exception as e:
                    print("TOKEN MIGRATE FAILED", shop, e)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self._json(500, {"error": str(e)})

    def _admin(self, shop, token, payload):
        body = json.dumps({"query": payload["query"], "variables": payload.get("variables") or {}}).encode()
        req = urllib.request.Request(
            "https://%s/admin/api/%s/graphql.json" % (shop, API_VERSION),
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Shopify-Access-Token": token,
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read() or json.dumps({"error": str(e)}).encode()

    def _http_json(self, url, data=None, headers=None, form=False, method="POST"):
        raw = urllib.parse.urlencode(data).encode() if form else json.dumps(data or {}).encode()
        hdrs = {"Accept": "application/json", "Accept-Encoding": "identity"}
        hdrs.update(headers or {})
        if form:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=raw, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                return resp.status, self._decode_body(resp.read())
        except urllib.error.HTTPError as e:
            parsed = self._decode_body(e.read())
            parsed.setdefault("httpStatus", e.code)
            parsed.setdefault("httpReason", getattr(e, "reason", ""))
            return e.code, parsed

    def _fedex_label(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            p = json.loads(raw or "{}")
        except json.JSONDecodeError:
            return self._json(400, {"error": "Invalid JSON"})

        if os.environ.get("PACKSCAN_EVIDENCE_LOG"):
            request_summary = {
                "thermal": bool(p.get("thermal")),
                "imageType": p.get("imageType"),
                "labelStock": p.get("labelStock"),
                "serviceType": p.get("serviceType"),
            }
            print("FEDEX LABEL REQUEST RECEIVED", json.dumps(request_summary))
            self._evidence("FEDEX LABEL REQUEST RECEIVED", request_summary)
        key, secret, account, sandbox = self._fedex_credentials(p)
        if not key or not secret or not account:
            if p.get("useServerSandbox"):
                return self._json(503, {"error": "FedEx sandbox credentials are not configured on this PackScan server"})
            return self._json(400, {"error": "FedEx API key, secret key, and account number are required"})

        base = "https://apis-sandbox.fedex.com" if sandbox else "https://apis.fedex.com"
        status, tok = self._http_json(
            base + "/oauth/token",
            {"grant_type": "client_credentials", "client_id": key, "client_secret": secret},
            form=True,
        )
        token = tok.get("access_token")
        if status >= 400 or not token:
            return self._json(401, {"error": self._fedex_err(tok, "FedEx login failed"), "details": tok})

        shipper = p.get("shipper") or {}
        recip = p.get("recipient") or {}
        weight = float(p.get("weight") or 1)
        service = p.get("serviceType") or "FEDEX_GROUND"
        residential = bool(p.get("residential")) or service == "GROUND_HOME_DELIVERY"
        thermal = bool(p.get("thermal")) or str(p.get("imageType") or "").upper() == "ZPLII"
        payload = {
            "labelResponseOptions": "LABEL",
            "accountNumber": {"value": account},
            "requestedShipment": {
                "shipDatestamp": time.strftime("%Y-%m-%d"),
                "pickupType": p.get("pickupType") or "DROPOFF_AT_FEDEX_LOCATION",
                "serviceType": service,
                "packagingType": "YOUR_PACKAGING",
                "blockInsightVisibility": False,
                "shippingChargesPayment": {"paymentType": "SENDER"},
                "labelSpecification": {
                    "imageType": "ZPLII" if thermal else (p.get("imageType") or "PNG"),
                    "labelStockType": "STOCK_4X6" if thermal else (p.get("labelStock") or "PAPER_4X6"),
                },
                "shipper": {
                    "contact": {
                        "personName": (shipper.get("name") or "Shipper")[:70],
                        "phoneNumber": self._phone(shipper.get("phone")),
                    },
                    "address": {
                        "streetLines": [x for x in [shipper.get("address1"), shipper.get("address2")] if x] or ["."],
                        "city": shipper.get("city") or "",
                        "stateOrProvinceCode": str(shipper.get("province") or "").upper()[:2],
                        "postalCode": str(shipper.get("zip") or "").split("-")[0].strip(),
                        "countryCode": (shipper.get("country") or "US")[:2].upper(),
                    },
                },
                "recipients": [
                    {
                        "contact": {
                            "personName": (recip.get("name") or "Customer")[:70],
                            **({"companyName": recip["company"][:35]} if recip.get("company") else {}),
                            "phoneNumber": self._phone(recip.get("phone") or shipper.get("phone")),
                        },
                        "address": {
                            "streetLines": [x for x in [recip.get("address1"), recip.get("address2")] if x] or ["."],
                            "city": recip.get("city") or "",
                            "stateOrProvinceCode": str(recip.get("province") or "").upper()[:2],
                            "postalCode": str(recip.get("zip") or "").split("-")[0].strip(),
                            "countryCode": (recip.get("country") or "US")[:2].upper(),
                            "residential": residential,
                        },
                    }
                ],
                "requestedPackageLineItems": [
                    {
                        "weight": {"units": "LB", "value": max(0.1, weight)},
                    }
                ],
            },
        }
        dims = p.get("dimensions") or {}
        if dims.get("l") and dims.get("w") and dims.get("h"):
            payload["requestedShipment"]["requestedPackageLineItems"][0]["dimensions"] = {
                "length": int(float(dims["l"])),
                "width": int(float(dims["w"])),
                "height": int(float(dims["h"])),
                "units": "IN",
            }

        status, data = self._http_json(
            base + "/ship/v1/shipments",
            payload,
            headers={
                "Authorization": "Bearer " + token,
                "x-locale": "en_US",
                "x-customer-transaction-id": str(uuid.uuid4()),
            },
        )
        if thermal and os.environ.get("PACKSCAN_EVIDENCE_LOG"):
            label_spec = payload["requestedShipment"]["labelSpecification"]
            print("FEDEX ZPL REQUEST LABEL SPEC", json.dumps(label_spec))
            print("FEDEX ZPL RAW RESPONSE", json.dumps(data))
            self._evidence("FEDEX ZPL REQUEST LABEL SPEC", label_spec)
            self._evidence("FEDEX ZPL RAW RESPONSE", data)
        if status >= 400:
            msg = self._fedex_err(data, "FedEx shipment failed")
            print("FEDEX SHIP ERROR", status)
            try:
                print(json.dumps(data, indent=2)[:4000])
            except Exception:
                print(data)
            if status == 403 and msg == "FedEx shipment failed":
                msg = (
                    "FedEx 403 forbidden. Usually: sandbox box doesn’t match the keys, "
                    "Ship API is not added to the FedEx project, production keys are not approved yet, "
                    "or the account number doesn’t belong to those API keys."
                )
            return self._json(status, {"error": msg, "details": data})

        tracking = ""
        encoded = ""
        try:
            pieces = data["output"]["transactionShipments"][0]["pieceResponses"]
            tracking = pieces[0].get("trackingNumber") or data["output"]["transactionShipments"][0].get("masterTrackingNumber") or ""
            docs = pieces[0].get("packageDocuments") or []
            if docs:
                encoded = docs[0].get("encodedLabel") or ""
        except Exception:
            pass
        result = {"trackingNumber": tracking, "raw": data if not encoded else None}
        if thermal:
            result["labelZplBase64"] = encoded
        else:
            result["labelPdfBase64"] = encoded
        return self._json(200, result)

    def _fedex_rates(self):
        try:
            return self._fedex_rates_inner()
        except Exception as e:
            print("FEDEX RATE CRASH", e)
            return self._json(500, {"error": str(e)})

    def _fedex_rates_inner(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            p = json.loads(raw or "{}")
        except json.JSONDecodeError:
            return self._json(400, {"error": "Invalid JSON"})
        key, secret, account, sandbox = self._fedex_credentials(p)
        if not key or not secret or not account:
            if p.get("useServerSandbox"):
                return self._json(503, {"error": "FedEx sandbox credentials are not configured on this PackScan server"})
            return self._json(400, {"error": "FedEx API key, secret key, and account number are required"})
        base = "https://apis-sandbox.fedex.com" if sandbox else "https://apis.fedex.com"
        status, tok = self._http_json(
            base + "/oauth/token",
            {"grant_type": "client_credentials", "client_id": key, "client_secret": secret},
            form=True,
        )
        token = tok.get("access_token")
        if status >= 400 or not token:
            return self._json(401, {"error": self._fedex_err(tok, "FedEx login failed"), "details": tok})
        shipper = p.get("shipper") or {}
        recip = p.get("recipient") or {}
        weight = float(p.get("weight") or 1)
        pkg = {"weight": {"units": "LB", "value": max(0.1, weight)}}
        dims = p.get("dimensions") or {}
        if dims.get("l") and dims.get("w") and dims.get("h"):
            pkg["dimensions"] = {
                "length": int(float(dims["l"])),
                "width": int(float(dims["w"])),
                "height": int(float(dims["h"])),
                "units": "IN",
            }
        payload = {
            "accountNumber": {"value": account},
            "requestedShipment": {
                "pickupType": p.get("pickupType") or "DROPOFF_AT_FEDEX_LOCATION",
                "rateRequestType": ["ACCOUNT", "LIST"],
                "shipper": {
                    "address": {
                        "streetLines": [x for x in [shipper.get("address1"), shipper.get("address2")] if x] or ["."],
                        "city": shipper.get("city") or "",
                        "stateOrProvinceCode": str(shipper.get("province") or "").upper()[:2],
                        "postalCode": str(shipper.get("zip") or "").split("-")[0].strip(),
                        "countryCode": (shipper.get("country") or "US")[:2].upper(),
                    }
                },
                "recipient": {
                    "address": {
                        "streetLines": [x for x in [recip.get("address1"), recip.get("address2")] if x] or ["."],
                        "city": recip.get("city") or "",
                        "stateOrProvinceCode": str(recip.get("province") or "").upper()[:2],
                        "postalCode": str(recip.get("zip") or "").split("-")[0].strip(),
                        "countryCode": (recip.get("country") or "US")[:2].upper(),
                        "residential": bool(p.get("residential")),
                    }
                },
                "requestedPackageLineItems": [pkg],
            },
        }
        status, data = self._http_json(
            base + "/rate/v1/rates/quotes",
            payload,
            headers={
                "Authorization": "Bearer " + token,
                "x-locale": "en_US",
                "x-customer-transaction-id": str(uuid.uuid4()),
            },
        )
        if status >= 400:
            print("FEDEX RATE ERROR", status)
            try:
                print(json.dumps(data, indent=2)[:3000])
            except Exception:
                print(data)
            return self._json(status, {"error": self._fedex_err(data, "FedEx rate failed"), "details": data})
        rates = []
        output = data.get("output") if isinstance(data, dict) else {}
        rows = output.get("rateReplyDetails") if isinstance(output, dict) else None
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            money = None
            for d in row.get("ratedShipmentDetails") or []:
                if not isinstance(d, dict):
                    amt, currency = self._fedex_money(d)
                else:
                    amt, currency = self._fedex_money(d.get("totalNetCharge") if "totalNetCharge" in d else d.get("totalNetFedExCharge"))
                if amt is None:
                    continue
                rtype = d.get("rateType") if isinstance(d, dict) else ""
                money = {"amount": amt, "currency": currency, "type": rtype}
                if str(rtype or "").upper().endswith("ACCOUNT"):
                    break
            commit = row.get("commit") if isinstance(row.get("commit"), dict) else {}
            date_detail = commit.get("dateDetail") if isinstance(commit.get("dateDetail"), dict) else {}
            ops = row.get("operationalDetail") if isinstance(row.get("operationalDetail"), dict) else {}
            rates.append({
                "serviceType": row.get("serviceType"),
                "serviceName": row.get("serviceName") or row.get("serviceType"),
                "transit": date_detail.get("dayFormat") or ops.get("transitTime"),
                "amount": None if not money else money["amount"],
                "currency": None if not money else money["currency"],
            })
        rates = [r for r in rates if r.get("amount") is not None]
        rates.sort(key=lambda r: float(r["amount"]))
        return self._json(200, {"rates": rates})

    def _compliance_webhook(self, path):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        header = (
            self.headers.get("X-Shopify-Hmac-Sha256")
            or self.headers.get("X-Shopify-Hmac-SHA256")
            or ""
        )
        if not verify_webhook_hmac(raw, header):
            return self._json(401, {"error": "Invalid webhook HMAC"})
        topic = (self.headers.get("X-Shopify-Topic") or "").strip()
        expected_topic = WEBHOOK_PATH_TOPICS.get(path.rstrip("/"))
        if expected_topic:
            if topic and topic != expected_topic:
                return self._json(400, {"error": "Webhook topic does not match endpoint"})
            topic = expected_topic
        if topic not in WEBHOOK_TOPICS:
            return self._json(400, {"error": "Unsupported webhook topic"})
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return self._json(400, {"error": "Invalid webhook JSON"})
        if not isinstance(payload, dict):
            return self._json(400, {"error": "Webhook payload must be an object"})
        handle_compliance_payload(topic, payload)
        print("COMPLIANCE WEBHOOK", topic, payload.get("shop_domain"))
        return self._json(200, {"ok": True, "topic": topic})

    def _safe(self, name, fn):
        try:
            return fn()
        except json.JSONDecodeError as e:
            return self._json(400, {"error": str(e)})
        except RuntimeError as e:
            message = str(e)
            if "required" in message.lower():
                return self._json(400, {"error": message})
            print(name, "ERROR", message)
            return self._json(502, {"error": message})
        except Exception as e:
            print(name, "CRASH", e)
            return self._json(500, {"error": str(e)})

    def _body(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        return json.loads(raw or "{}")

    def _record_label(self):
        p = self._body()
        entry = {
            "carrier": (p.get("carrier") or "").lower(),
            "orderId": p.get("orderId") or "",
            "orderName": p.get("orderName") or "",
            "customerName": p.get("customerName") or "",
            "company": p.get("company") or "",
            "trackingNumber": p.get("trackingNumber") or "",
            "stampsTxId": p.get("stampsTxId") or "",
            "sandbox": bool(p.get("sandbox")),
        }
        record = add_label_history(entry)
        return self._json(200, {"ok": True, "label": record})

    def _void_label(self):
        p = self._body()
        label_id = p.get("id")
        rows = load_label_history()
        record = next((r for r in rows if r.get("id") == label_id), None)
        if not record:
            return self._json(404, {"error": "Label not found in history"})
        if record.get("voided"):
            return self._json(200, {"ok": True, "already": True, "label": record})

        carrier = (record.get("carrier") or "").lower()
        tracking = record.get("trackingNumber") or ""
        try:
            if carrier == "fedex":
                key, secret, account, sandbox = self._fedex_credentials(p)
                if not key or not secret or not account:
                    if p.get("useServerSandbox"):
                        return self._json(503, {"error": "FedEx sandbox credentials are not configured on this PackScan server"})
                    return self._json(400, {"error": "FedEx API key, secret key, and account number are required to void"})
                base = "https://apis-sandbox.fedex.com" if sandbox else "https://apis.fedex.com"
                status, tok = self._http_json(
                    base + "/oauth/token",
                    {"grant_type": "client_credentials", "client_id": key, "client_secret": secret},
                    form=True,
                )
                token = tok.get("access_token")
                if status >= 400 or not token:
                    return self._json(401, {"error": self._fedex_err(tok, "FedEx login failed"), "details": tok})
                status, data = self._http_json(
                    base + "/ship/v1/shipments/cancel",
                    {"accountNumber": {"value": account}, "trackingNumber": tracking, "deletionControl": "DELETE_ALL_PACKAGES"},
                    headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
                    method="PUT",
                )
                if status >= 400:
                    return self._json(status, {"error": self._fedex_err(data, "FedEx void failed"), "details": data})
            elif carrier == "ups":
                base, token = self._ups_token(p)
                req = urllib.request.Request(
                    base + "/api/shipments/v2403/void/cancel/" + urllib.parse.quote(tracking),
                    headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
                    method="DELETE",
                )
                try:
                    with urllib.request.urlopen(req, timeout=45) as resp:
                        data = self._decode_body(resp.read())
                        status = resp.status
                except urllib.error.HTTPError as e:
                    status = e.code
                    data = self._decode_body(e.read())
                if status >= 400:
                    return self._json(status, {"error": self._fedex_err(data, "UPS void failed"), "details": data})
            elif carrier in ("usps", "stamps"):
                sandbox = bool(p.get("sandbox"))
                url = self._stamps_endpoint(sandbox)
                creds_xml = self._stamps_creds_xml(p)
                stamps_id = record.get("stampsTxId") or record.get("trackingNumber")
                body_xml = (
                    '<CancelIndicium xmlns="%s">%s<StampsTxID>%s</StampsTxID></CancelIndicium>'
                ) % (self._stamps_ns(), creds_xml, self._xml_esc(stamps_id))
                status, xml_text = self._stamps_soap(url, self._stamps_ns() + "/CancelIndicium", body_xml)
                if status >= 400 or "<CancelIndiciumResult" not in xml_text:
                    return self._json(status if status >= 400 else 502, {"error": self._stamps_fault(xml_text)})
            else:
                return self._json(400, {"error": "Unknown carrier for this label"})
        except Exception as e:
            return self._json(500, {"error": str(e)})

        updated = update_label_history(label_id, voided=True, voidedAt=int(time.time()))
        return self._json(200, {"ok": True, "label": updated})

    def _ups_token(self, p):
        cid = (p.get("clientId") or "").strip()
        secret = (p.get("clientSecret") or "").strip()
        if not cid or not secret:
            raise RuntimeError("UPS Client ID and secret are required")
        base = "https://wwwcie.ups.com" if p.get("sandbox") else "https://onlinetools.ups.com"
        raw = ("%s:%s" % (cid, secret)).encode()
        import base64
        basic = base64.b64encode(raw).decode()
        status, tok = self._http_json(
            base + "/security/v1/oauth/token",
            {"grant_type": "client_credentials"},
            headers={"Authorization": "Basic " + basic},
            form=True,
        )
        token = tok.get("access_token")
        if status >= 400 or not token:
            raise RuntimeError(self._fedex_err(tok, "UPS login failed"))
        return base, token

    def _ups_addr(self, who):
        return {
            "AddressLine": [x for x in [who.get("address1"), who.get("address2")] if x] or ["."],
            "City": who.get("city") or "",
            "StateProvinceCode": str(who.get("province") or "").upper()[:2],
            "PostalCode": str(who.get("zip") or "").split("-")[0].strip(),
            "CountryCode": (who.get("country") or "US")[:2].upper(),
        }

    def _ups_service_code(self, service):
        return {
            "UPS_GROUND": "03",
            "UPS_3DAY": "12",
            "UPS_2DAY": "02",
            "UPS_NEXT": "01",
            "03": "03",
            "02": "02",
            "01": "01",
            "12": "12",
        }.get(service, "03")

    def _ups_rates(self):
        p = self._body()
        base, token = self._ups_token(p)
        shipper = p.get("shipper") or {}
        recip = p.get("recipient") or {}
        account = str(p.get("accountNumber") or "").strip()
        weight = max(0.1, float(p.get("weight") or 1))
        dims = p.get("dimensions") or {}
        pkg = {
            "PackagingType": {"Code": "02"},
            "PackageWeight": {"UnitOfMeasurement": {"Code": "LBS"}, "Weight": str(round(weight, 1))},
        }
        if dims.get("l") and dims.get("w") and dims.get("h"):
            pkg["Dimensions"] = {
                "UnitOfMeasurement": {"Code": "IN"},
                "Length": str(int(float(dims["l"]))),
                "Width": str(int(float(dims["w"]))),
                "Height": str(int(float(dims["h"]))),
            }
        payload = {
            "RateRequest": {
                "Request": {"RequestOption": "Shop"},
                "Shipment": {
                    "Shipper": {"Name": shipper.get("name") or "Shipper", "ShipperNumber": account, "Address": self._ups_addr(shipper)},
                    "ShipTo": {"Name": recip.get("name") or "Customer", "Address": self._ups_addr(recip)},
                    "ShipFrom": {"Name": shipper.get("name") or "Shipper", "Address": self._ups_addr(shipper)},
                    "PaymentDetails": {"ShipmentCharge": {"Type": "01", "BillShipper": {"AccountNumber": account}}},
                    "Package": pkg,
                },
            }
        }
        status, data = self._http_json(
            base + "/api/rating/v1/shop",
            payload,
            headers={"Authorization": "Bearer " + token, "transId": str(uuid.uuid4()), "transactionSrc": "packscan"},
        )
        if status >= 400:
            return self._json(status, {"error": self._fedex_err(data, "UPS rate failed"), "details": data})
        rates = []
        rated = (((data.get("RateResponse") or {}).get("RatedShipment")) or [])
        if isinstance(rated, dict):
            rated = [rated]
        for row in rated:
            svc = (row.get("Service") or {}).get("Code")
            name = {"03": "UPS Ground", "12": "UPS 3 Day Select", "02": "UPS 2nd Day Air", "01": "UPS Next Day Air"}.get(svc, "UPS " + str(svc))
            charge = row.get("TotalCharges") or row.get("NegotiatedRateCharges", {}).get("TotalCharge") or {}
            amt = charge.get("MonetaryValue") if isinstance(charge, dict) else charge
            if amt is None:
                continue
            rates.append({"serviceType": svc, "serviceName": name, "transit": "", "amount": float(amt), "currency": (charge.get("CurrencyCode") if isinstance(charge, dict) else "USD")})
        rates.sort(key=lambda r: r["amount"])
        return self._json(200, {"rates": rates})

    def _ups_label(self):
        p = self._body()
        base, token = self._ups_token(p)
        shipper = p.get("shipper") or {}
        recip = p.get("recipient") or {}
        account = str(p.get("accountNumber") or "").strip()
        weight = max(0.1, float(p.get("weight") or 1))
        code = self._ups_service_code(p.get("serviceType"))
        dims = p.get("dimensions") or {}
        pkg = {
            "Packaging": {"Code": "02"},
            "PackageWeight": {"UnitOfMeasurement": {"Code": "LBS"}, "Weight": str(round(weight, 1))},
        }
        if dims.get("l") and dims.get("w") and dims.get("h"):
            pkg["Dimensions"] = {
                "UnitOfMeasurement": {"Code": "IN"},
                "Length": str(int(float(dims["l"]))),
                "Width": str(int(float(dims["w"]))),
                "Height": str(int(float(dims["h"]))),
            }
        payload = {
            "ShipmentRequest": {
                "Request": {"RequestOption": "nonvalidate"},
                "Shipment": {
                    "Shipper": {
                        "Name": shipper.get("name") or "Shipper",
                        "AttentionName": shipper.get("name") or "Shipper",
                        "Phone": {"Number": self._phone(shipper.get("phone"))},
                        "ShipperNumber": account,
                        "Address": self._ups_addr(shipper),
                    },
                    "ShipTo": {
                        "Name": recip.get("company") or recip.get("name") or "Customer",
                        "AttentionName": recip.get("name") or "Customer",
                        "Phone": {"Number": self._phone(recip.get("phone") or shipper.get("phone"))},
                        "Address": self._ups_addr(recip),
                    },
                    "PaymentInformation": {"ShipmentCharge": {"Type": "01", "BillShipper": {"AccountNumber": account}}},
                    "Service": {"Code": code},
                    "Package": pkg,
                },
                "LabelSpecification": {
                    "LabelImageFormat": {"Code": "PNG"},
                    "LabelStockSize": {"Height": "6", "Width": "4"},
                },
            }
        }
        status, data = self._http_json(
            base + "/api/shipments/v2403/ship",
            payload,
            headers={"Authorization": "Bearer " + token, "transId": str(uuid.uuid4()), "transactionSrc": "packscan"},
        )
        if status >= 400:
            print("UPS SHIP ERROR", json.dumps(data)[:2000])
            return self._json(status, {"error": self._fedex_err(data, "UPS shipment failed"), "details": data})
        results = ((data.get("ShipmentResponse") or {}).get("ShipmentResults") or {})
        tracking = results.get("ShipmentIdentificationNumber") or ""
        pkg_res = results.get("PackageResults") or {}
        if isinstance(pkg_res, list):
            pkg_res = pkg_res[0] if pkg_res else {}
        if not tracking:
            tracking = pkg_res.get("TrackingNumber") or ""
        label = ((pkg_res.get("ShippingLabel") or {}).get("GraphicImage")) or ""
        return self._json(200, {"trackingNumber": tracking, "labelPdfBase64": label})

    def _usps_token(self, p):
        key = (p.get("consumerKey") or "").strip()
        secret = (p.get("consumerSecret") or "").strip()
        if not key or not secret:
            raise RuntimeError("USPS consumer key and secret are required")
        base = "https://apis-tem.usps.com" if p.get("sandbox") else "https://apis.usps.com"
        status, tok = self._http_json(
            base + "/oauth2/v3/token",
            {"grant_type": "client_credentials", "client_id": key, "client_secret": secret},
            form=True,
        )
        token = tok.get("access_token")
        if status >= 400 or not token:
            raise RuntimeError(self._fedex_err(tok, "USPS login failed"))
        return base, token

    def _usps_mail_class(self, service):
        return {
            "USPS_GA": "USPS_GROUND_ADVANTAGE",
            "USPS_PRIORITY": "PRIORITY_MAIL",
            "USPS_EXPRESS": "PRIORITY_MAIL_EXPRESS",
            "USPS_GROUND_ADVANTAGE": "USPS_GROUND_ADVANTAGE",
            "PRIORITY_MAIL": "PRIORITY_MAIL",
            "PRIORITY_MAIL_EXPRESS": "PRIORITY_MAIL_EXPRESS",
        }.get(service, "USPS_GROUND_ADVANTAGE")

    def _usps_rates(self):
        p = self._body()
        base, token = self._usps_token(p)
        shipper = p.get("shipper") or {}
        recip = p.get("recipient") or {}
        weight = max(1, int(round(float(p.get("weight") or 1) * 16)))
        dims = p.get("dimensions") or {}
        payload = {
            "originZIPCode": str(shipper.get("zip") or "").split("-")[0].strip(),
            "destinationZIPCode": str(recip.get("zip") or "").split("-")[0].strip(),
            "weight": weight,
            "length": int(float(dims.get("l") or 6)),
            "width": int(float(dims.get("w") or 6)),
            "height": int(float(dims.get("h") or 4)),
            "mailClass": "ALL",
            "priceType": "COMMERCIAL",
        }
        status, data = self._http_json(
            base + "/prices/v3/base-rates/search",
            payload,
            headers={"Authorization": "Bearer " + token},
        )
        if status >= 400:
            return self._json(status, {"error": self._fedex_err(data, "USPS rate failed"), "details": data})
        rates = []
        rows = data if isinstance(data, list) else data.get("rateOptions") or data.get("rates") or [data]
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = row.get("mailClass") or row.get("productName") or row.get("description") or "USPS"
            amt = row.get("price") or row.get("totalPrice") or row.get("amount")
            if amt is None and isinstance(row.get("rate"), dict):
                amt = row["rate"].get("price")
            if amt is None:
                continue
            rates.append({"serviceType": name, "serviceName": str(name).replace("_", " ").title(), "transit": row.get("commitmentName") or "", "amount": float(amt), "currency": "USD"})
        rates.sort(key=lambda r: r["amount"])
        return self._json(200, {"rates": rates})

    def _usps_label(self):
        p = self._body()
        base, token = self._usps_token(p)
        shipper = p.get("shipper") or {}
        recip = p.get("recipient") or {}
        weight = max(1, int(round(float(p.get("weight") or 1) * 16)))
        dims = p.get("dimensions") or {}
        mail = self._usps_mail_class(p.get("serviceType"))
        payload = {
            "imageInfo": {"imageType": "PNG", "labelType": "4X6LABEL"},
            "toAddress": {
                "firstName": (recip.get("name") or "Customer").split(" ")[0],
                "lastName": " ".join((recip.get("name") or "Customer").split(" ")[1:]) or "Customer",
                **({"firm": recip["company"]} if recip.get("company") else {}),
                "streetAddress": recip.get("address1") or "",
                "secondaryAddress": recip.get("address2") or "",
                "city": recip.get("city") or "",
                "state": str(recip.get("province") or "").upper()[:2],
                "ZIPCode": str(recip.get("zip") or "").split("-")[0].strip(),
            },
            "fromAddress": {
                "firstName": (shipper.get("name") or "Shipper").split(" ")[0],
                "lastName": " ".join((shipper.get("name") or "Shipper").split(" ")[1:]) or "Shipper",
                "streetAddress": shipper.get("address1") or "",
                "city": shipper.get("city") or "",
                "state": str(shipper.get("province") or "").upper()[:2],
                "ZIPCode": str(shipper.get("zip") or "").split("-")[0].strip(),
            },
            "packageDescription": {
                "mailClass": mail,
                "weightUOM": "lb",
                "weight": float(p.get("weight") or 1),
                "dimensionsUOM": "in",
                "length": float(dims.get("l") or 6),
                "width": float(dims.get("w") or 6),
                "height": float(dims.get("h") or 4),
            },
        }
        if p.get("crid"):
            payload["CRID"] = p.get("crid")
        if p.get("mid"):
            payload["MID"] = p.get("mid")
        status, data = self._http_json(
            base + "/labels/v3/label",
            payload,
            headers={"Authorization": "Bearer " + token},
        )
        if status >= 400:
            print("USPS LABEL ERROR", json.dumps(data)[:2000])
            return self._json(status, {"error": self._fedex_err(data, "USPS label failed"), "details": data})
        tracking = data.get("trackingNumber") or data.get("trackingNumber") or ""
        label = data.get("labelImage") or data.get("image") or ""
        if isinstance(label, dict):
            label = label.get("imageData") or label.get("base64") or ""
        return self._json(200, {"trackingNumber": tracking, "labelPdfBase64": label})

    def _stamps_endpoint(self, sandbox):
        host = "swsim.testing.stamps.com" if sandbox else "swsim.stamps.com"
        return "https://%s/swsim/swsimv135.asmx" % host

    def _stamps_ns(self):
        return "http://stamps.com/xml/namespace/2023/05/swsim/SwsimV135"

    def _xml_text(self, el):
        return (el.text or "").strip() if el is not None else ""

    def _stamps_soap(self, url, action, body_xml):
        envelope = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            "<soap:Body>%s</soap:Body></soap:Envelope>"
        ) % body_xml
        req = urllib.request.Request(
            url,
            data=envelope.encode("utf-8"),
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": '"%s"' % action,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    def _stamps_fault(self, xml_text):
        low = xml_text or ""
        m = re.search(r"<faultstring[^>]*>([^<]+)</faultstring>", low, re.I)
        if m:
            return m.group(1)
        m = re.search(r"<Message[^>]*>([^<]+)</Message>", low, re.I)
        if m:
            return m.group(1)
        return "Stamps.com request failed"

    def _stamps_creds_xml(self, p):
        ns = self._stamps_ns()
        return (
            "<Credentials xmlns=\"%s\">"
            "<IntegrationID>%s</IntegrationID>"
            "<Username>%s</Username>"
            "<Password>%s</Password>"
            "</Credentials>"
        ) % (
            ns,
            self._xml_esc(p.get("integrationId") or p.get("integrationID") or ""),
            self._xml_esc(p.get("username") or p.get("user") or ""),
            self._xml_esc(p.get("password") or ""),
        )

    def _xml_esc(self, s):
        return (
            str(s or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    def _stamps_service_map(self, code):
        c = str(code or "").upper()
        if "GA" in c or "GROUND" in c:
            return "US-GA", "USPS_GA"
        if "XM" in c or "EXPRESS" in c:
            return "US-XM", "USPS_EXPRESS"
        if "PM" in c or "PRIORITY" in c:
            return "US-PM", "USPS_PRIORITY"
        if "FC" in c or "FIRST" in c:
            return "US-FC", "USPS_GA"
        return "US-GA", "USPS_GA"

    def _stamps_rates(self):
        p = self._body()
        if not (p.get("username") or p.get("user")) or not p.get("password") or not (p.get("integrationId") or p.get("integrationID")):
            return self._json(400, {"error": "Add Stamps.com username, password, and Integration ID in Settings"})
        shipper = p.get("shipper") or {}
        recip = p.get("recipient") or {}
        dims = p.get("dimensions") or {}
        ns = self._stamps_ns()
        ship_date = time.strftime("%Y-%m-%d")
        rate_xml = (
            "<Rate xmlns=\"%s\">"
            "<FromZIPCode>%s</FromZIPCode>"
            "<ToZIPCode>%s</ToZIPCode>"
            "<ToCountry>US</ToCountry>"
            "<WeightLb>%.2f</WeightLb>"
            "<PackageType>Package</PackageType>"
            "<Length>%.1f</Length><Width>%.1f</Width><Height>%.1f</Height>"
            "<ShipDate>%s</ShipDate>"
            "</Rate>"
        ) % (
            ns,
            self._xml_esc(str(shipper.get("zip") or "").split("-")[0]),
            self._xml_esc(str(recip.get("zip") or "").split("-")[0]),
            max(0.1, float(p.get("weight") or 1)),
            float(dims.get("l") or 6),
            float(dims.get("w") or 6),
            float(dims.get("h") or 4),
            ship_date,
        )
        body = "<GetRates xmlns=\"%s\">%s%s</GetRates>" % (ns, self._stamps_creds_xml(p), rate_xml)
        url = self._stamps_endpoint(p.get("sandbox"))
        status, xml_text = self._stamps_soap(url, "%s/GetRates" % ns, body)
        if status >= 400 or "faultstring" in xml_text.lower():
            return self._json(status if status >= 400 else 400, {"error": self._stamps_fault(xml_text), "details": xml_text[:800]})
        import xml.etree.ElementTree as ET
        rates = []
        try:
            root = ET.fromstring(xml_text)
        except Exception:
            return self._json(502, {"error": "Stamps returned invalid XML", "details": xml_text[:500]})
        for el in root.iter():
            tag = el.tag.split("}")[-1]
            if tag != "Rate":
                continue
            kids = {c.tag.split("}")[-1]: (c.text or "").strip() for c in list(el)}
            amt = kids.get("Amount") or kids.get("RateAmount")
            if not amt:
                continue
            st = kids.get("ServiceType") or kids.get("ServiceDescription") or "US-GA"
            _, mapped = self._stamps_service_map(st)
            name = kids.get("ServiceDescription") or st
            rates.append({
                "serviceType": mapped,
                "serviceName": "Stamps · " + name.replace("_", " "),
                "transit": kids.get("DeliverDays") or kids.get("DeliveryDays") or "",
                "amount": float(amt),
                "currency": "USD",
                "stampsService": st,
            })
        rates.sort(key=lambda r: r["amount"])
        return self._json(200, {"rates": rates})

    def _stamps_label(self):
        p = self._body()
        if not (p.get("username") or p.get("user")) or not p.get("password") or not (p.get("integrationId") or p.get("integrationID")):
            return self._json(400, {"error": "Add Stamps.com username, password, and Integration ID in Settings"})
        shipper = p.get("shipper") or {}
        recip = p.get("recipient") or {}
        dims = p.get("dimensions") or {}
        ns = self._stamps_ns()
        stamps_svc, _ = self._stamps_service_map(p.get("serviceType"))
        ship_date = time.strftime("%Y-%m-%d")
        def addr(tag, a, fallback_name):
            name = (a.get("name") or fallback_name or "Customer").strip()
            parts = name.split(" ", 1)
            return (
                "<%s xmlns=\"%s\">"
                "<FullName>%s</FullName>"
                "<Name1>%s</Name1>"
                "<Address1>%s</Address1>"
                "<Address2>%s</Address2>"
                "<City>%s</City>"
                "<State>%s</State>"
                "<ZIPCode>%s</ZIPCode>"
                "<Country>US</Country>"
                "</%s>"
            ) % (
                tag, ns,
                self._xml_esc(name),
                self._xml_esc(parts[0]),
                self._xml_esc(a.get("address1") or ""),
                self._xml_esc(a.get("address2") or ""),
                self._xml_esc(a.get("city") or ""),
                self._xml_esc(str(a.get("province") or "").upper()[:2]),
                self._xml_esc(str(a.get("zip") or "").split("-")[0]),
                tag,
            )
        rate_xml = (
            "<Rate xmlns=\"%s\">"
            "<FromZIPCode>%s</FromZIPCode>"
            "<ToZIPCode>%s</ToZIPCode>"
            "<ToCountry>US</ToCountry>"
            "<ServiceType>%s</ServiceType>"
            "<WeightLb>%.2f</WeightLb>"
            "<PackageType>Package</PackageType>"
            "<Length>%.1f</Length><Width>%.1f</Width><Height>%.1f</Height>"
            "<ShipDate>%s</ShipDate>"
            "</Rate>"
        ) % (
            ns,
            self._xml_esc(str(shipper.get("zip") or "").split("-")[0]),
            self._xml_esc(str(recip.get("zip") or "").split("-")[0]),
            stamps_svc,
            max(0.1, float(p.get("weight") or 1)),
            float(dims.get("l") or 6),
            float(dims.get("w") or 6),
            float(dims.get("h") or 4),
            ship_date,
        )
        body = (
            "<CreateIndicium xmlns=\"%s\">%s"
            "<IntegratorTxID>%s</IntegratorTxID>"
            "%s%s%s"
            "<ImageType>Png</ImageType>"
            "</CreateIndicium>"
        ) % (
            ns,
            self._stamps_creds_xml(p),
            uuid.uuid4().hex,
            rate_xml,
            addr("From", shipper, shipper.get("name") or "Shipper"),
            addr("To", recip, recip.get("name") or "Customer"),
        )
        url = self._stamps_endpoint(p.get("sandbox"))
        status, xml_text = self._stamps_soap(url, "%s/CreateIndicium" % ns, body)
        if status >= 400 or "faultstring" in xml_text.lower():
            return self._json(status if status >= 400 else 400, {"error": self._stamps_fault(xml_text), "details": xml_text[:800]})
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(xml_text)
        except Exception:
            return self._json(502, {"error": "Stamps returned invalid XML"})
        tracking = ""
        stamps_tx_id = ""
        image = ""
        for el in root.iter():
            tag = el.tag.split("}")[-1]
            if tag == "TrackingNumber" and not tracking:
                tracking = (el.text or "").strip()
            if tag == "StampsTxID" and not stamps_tx_id:
                stamps_tx_id = (el.text or "").strip()
            if tag in ("ImageData", "PostageLabel") and (el.text or "").strip():
                image = (el.text or "").strip()
        if not tracking:
            tracking = stamps_tx_id
        if not image:
            return self._json(502, {"error": "Stamps label had no image", "details": xml_text[:600]})
        return self._json(200, {"trackingNumber": tracking, "stampsTxId": stamps_tx_id, "labelPdfBase64": image})

    def _decode_body(self, blob):
        if not blob:
            return {}
        if blob[:2] == b"\x1f\x8b":
            try:
                blob = gzip.decompress(blob)
            except Exception:
                pass
        text = blob.decode("utf-8", "replace")
        try:
            return json.loads(text)
        except Exception:
            return {"raw": text[:800]}

    def _fedex_money(self, charge):
        if charge is None:
            return None, "USD"
        if isinstance(charge, (int, float)):
            return float(charge), "USD"
        if isinstance(charge, str):
            try:
                return float(charge), "USD"
            except ValueError:
                return None, "USD"
        if isinstance(charge, dict):
            amt = charge.get("amount")
            if amt is None:
                return None, charge.get("currency") or "USD"
            try:
                return float(amt), charge.get("currency") or "USD"
            except (TypeError, ValueError):
                return None, "USD"
        return None, "USD"

    def _fedex_credentials(self, payload):
        sandbox = bool(payload.get("sandbox"))
        if sandbox and payload.get("useServerSandbox"):
            return (
                os.environ.get("PACKSCAN_DEMO_FEDEX_KEY", "").strip(),
                os.environ.get("PACKSCAN_DEMO_FEDEX_SECRET", "").strip(),
                os.environ.get("PACKSCAN_DEMO_FEDEX_ACCOUNT", "").strip(),
                True,
            )
        return (
            (payload.get("apiKey") or "").strip(),
            (payload.get("secretKey") or "").strip(),
            str(payload.get("accountNumber") or "").strip(),
            sandbox,
        )

    def _phone(self, raw):
        digits = "".join(ch for ch in str(raw or "") if ch.isdigit())
        if len(digits) == 11 and digits.startswith("1"):
            digits = digits[1:]
        return digits[:15] or "0000000000"

    def _fedex_err(self, data, fallback):
        if not isinstance(data, dict):
            return fallback
        errs = data.get("errors") or data.get("error") or []
        if isinstance(errs, dict):
            errs = [errs]
        if isinstance(errs, str):
            return errs
        parts = []
        for e in errs:
            if isinstance(e, dict):
                parts.append(e.get("message") or e.get("code") or str(e))
            else:
                parts.append(str(e))
        return "; ".join(parts) if parts else fallback

    def _json(self, status, obj):
        raw = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))


if __name__ == "__main__":
    evidence_path = os.environ.get("PACKSCAN_EVIDENCE_LOG", "").strip()
    if evidence_path:
        class Tee:
            def __init__(self, stream, path):
                self.stream = stream
                self.file = open(path, "a", encoding="utf-8")

            def write(self, text):
                self.stream.write(text)
                self.file.write(text)
                self.file.flush()

            def flush(self):
                self.stream.flush()
                self.file.flush()

        sys.stdout = Tee(sys.stdout, evidence_path)
        sys.stderr = Tee(sys.stderr, evidence_path)
    bind = os.environ.get("BIND", "0.0.0.0")
    httpd = ThreadingHTTPServer((bind, PORT), Handler)
    print("PackScan listening on %s:%s" % (bind, PORT))
    print("Hosted OAuth:" , "yes" if HOSTED else "set HOST, SHOPIFY_API_KEY, SHOPIFY_API_SECRET")
    if HOST:
        print("App URL", HOST)
    httpd.serve_forever()
