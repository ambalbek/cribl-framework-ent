#!/usr/bin/env python3
"""
app.py — Unified Cribl Framework

Combines:
  - cribl-flask  (Cribl Pusher + ELK Roles + Cribl Routes)
  - cribl-portal (Client-facing onboarding request portal)

Run with:
    flask run --host=0.0.0.0 --port=5000
  or:
    python app.py

Environment variables:
    LOG_LEVEL   DEBUG / INFO / WARNING / ERROR  (default: INFO)
    LOG_FILE    Path to log file  (default: none, console only)
"""
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

import requests as http_client
import urllib3
from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for
from ldap3 import Server, Connection, ALL
from requests.auth import HTTPBasicAuth
from werkzeug.exceptions import HTTPException

SCRIPT_DIR  = Path(__file__).parent.resolve()
CONFIG_PATH = SCRIPT_DIR / "config.json"
PUSHER      = SCRIPT_DIR / "cribl-pusher.py"
RODE_RM     = SCRIPT_DIR / "rode_rm.py"


# ── Logging setup ──────────────────────────────────────────────────────────────

def setup_app_logging(app: Flask) -> logging.Logger:
    """
    Configure a dedicated 'cribl-framework' logger for the web layer.

    - Console handler always attached (stdout).
    - File handler attached when LOG_FILE env var is set
      (daily rotation, 30-day retention).
    - Flask's default werkzeug request logger is left intact but its
      level is raised to WARNING so it doesn't double-print every request.
    """
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    if log_level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        log_level = "INFO"

    fmt       = "%(asctime)s  %(levelname)-8s  [framework]  %(message)s"
    datefmt   = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt, datefmt)

    logger = logging.getLogger("cribl-framework")
    logger.setLevel(getattr(logging, log_level))
    logger.handlers.clear()
    logger.propagate = False

    # Console
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File (optional)
    log_file = os.environ.get("LOG_FILE", "").strip()
    if log_file:
        fh = TimedRotatingFileHandler(
            log_file, when="midnight", backupCount=30, encoding="utf-8"
        )
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        logger.info("File logging enabled: %s", log_file)

    # Silence werkzeug's per-request lines (we log our own)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    return logger


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

log = setup_app_logging(app)


# ── Request lifecycle hooks ────────────────────────────────────────────────────

@app.context_processor
def inject_user():
    """Make current user info available in all templates."""
    return {
        "current_user": session.get("username"),
        "current_role": session.get("role"),
        "current_display_name": session.get("display_name"),
    }


@app.before_request
def _before():
    g.start_time = time.monotonic()
    g.username = session.get("username")
    g.role = session.get("role")
    log.info("→ %s %s  [%s]  user=%s", request.method, request.path,
             request.remote_addr or "-", g.username or "anonymous")


@app.after_request
def _after(response):
    elapsed_ms = (time.monotonic() - g.start_time) * 1000
    level = logging.WARNING if response.status_code >= 400 else logging.INFO
    log.log(level, "← %s %s  %d  %.0fms",
            request.method, request.path,
            response.status_code, elapsed_ms)
    return response


# ── Unhandled exception handler — always return JSON, never bare HTML ──────────

@app.errorhandler(404)
def _not_found(exc):
    log.warning("404 Not Found: %s %s", request.method, request.path)
    return jsonify({"errors": [f"Not found: {request.path}"]}), 404


@app.errorhandler(Exception)
def _handle_exception(exc):
    # Let Flask handle standard HTTP errors (404, 405, etc.) normally
    if isinstance(exc, HTTPException):
        return exc

    if isinstance(exc, SystemExit):
        # sys.exit() called inside a route (e.g. cribl die()) — treat as 500
        msg = f"Internal process exited unexpectedly (code={exc.code})"
    else:
        msg = str(exc)

    log.error("Unhandled exception on %s %s:\n%s",
              request.method, request.path,
              traceback.format_exc())
    return jsonify({"errors": [f"Server error: {msg}"]}), 500


# ── Helpers ────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)


# ── Session & LDAP configuration ─────────────────────────────────────────────

_startup_config = load_config()
app.secret_key = _startup_config.get("secret_key", "CHANGE-ME-insecure-default")
app.config["SESSION_COOKIE_NAME"] = "cribl_session"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
_auth_cfg = _startup_config.get("auth", {})
app.permanent_session_lifetime = timedelta(
    minutes=_auth_cfg.get("session_lifetime_minutes", 480)
)


def ldap_authenticate(username, password):
    """
    Validate credentials against Active Directory and return the user's role.
    Falls back to local admin accounts in config.json when LDAP is unavailable.
    Returns (True, role, display_name) on success, (False, None, error_msg) on failure.
    """
    config = load_config()
    auth = config.get("auth", {})

    # Check local accounts first (fallback when LDAP is down)
    for admin in auth.get("local_admins", []):
        if admin.get("username") == username and admin.get("password") == password:
            log.info("Local admin auth OK — user=%s", username)
            return True, "admin", admin.get("display_name", username)

    for local_user in auth.get("local_users", []):
        if local_user.get("username") == username and local_user.get("password") == password:
            log.info("Local user auth OK — user=%s", username)
            return True, "user", local_user.get("display_name", username)

    ldap_url = auth.get("ldap_url", "")
    use_ssl = auth.get("ldap_use_ssl", False)
    bind_dn_template = auth.get("ldap_bind_dn_template", "{username}")
    base_dn = auth.get("ldap_base_dn", "")

    if not ldap_url:
        log.error("LDAP auth — ldap_url not configured")
        return False, None, "LDAP is not configured. Contact your administrator."

    bind_dn = bind_dn_template.replace("{username}", username)

    try:
        server = Server(ldap_url, use_ssl=use_ssl, get_info=ALL, connect_timeout=10)
        conn = Connection(server, user=bind_dn, password=password,
                          auto_bind=True, read_only=True, receive_timeout=10)
    except Exception as e:
        log.warning("LDAP bind failed for user=%s: %s", username, e)
        return False, None, "Invalid credentials."

    try:
        search_filter = f"(sAMAccountName={username})"
        conn.search(base_dn, search_filter,
                    attributes=["memberOf", "displayName", "cn"])

        if not conn.entries:
            log.warning("LDAP user not found: %s", username)
            conn.unbind()
            return False, None, "User not found in directory."

        entry = conn.entries[0]
        member_of = []
        if hasattr(entry, "memberOf") and entry.memberOf:
            member_of = [str(g).upper() for g in entry.memberOf.values]
        display_name = str(entry.displayName) if hasattr(entry, "displayName") and entry.displayName else username

        conn.unbind()

        # Determine role from group membership — check admin first
        roles_cfg = auth.get("roles", {})

        admin_groups = [g.upper() for g in roles_cfg.get("admin", {}).get("ad_groups", [])]
        for group_dn in member_of:
            if group_dn in admin_groups:
                log.info("LDAP auth OK — user=%s role=admin", username)
                return True, "admin", display_name

        user_groups = [g.upper() for g in roles_cfg.get("user", {}).get("ad_groups", [])]
        for group_dn in member_of:
            if group_dn in user_groups:
                log.info("LDAP auth OK — user=%s role=user", username)
                return True, "user", display_name

        log.warning("LDAP auth denied — user=%s has no matching group", username)
        return False, None, "You are not authorized to use this application. Contact your admin to be added to the appropriate AD group."

    except Exception as e:
        log.error("LDAP group lookup failed for user=%s: %s", username, e)
        try:
            conn.unbind()
        except Exception:
            pass
        return False, None, "Authentication error during group lookup."


# ── Auth decorators ───────────────────────────────────────────────────────────

def login_required(f):
    """Redirect to login if no valid session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login_page", next=request.path))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Require admin role. Redirects to login or returns 403."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login_page", next=request.path))
        if session.get("role") != "admin":
            log.warning("Unauthorized admin access attempt by %s to %s",
                        session.get("username"), request.path)
            return render_template("login.html",
                                   error="You do not have permission to access this page."), 403
        return f(*args, **kwargs)
    return decorated


def run_subprocess(cmd: list, masked: str = "") -> tuple:
    log.info("  subprocess: %s", masked or " ".join(cmd))
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=str(SCRIPT_DIR),
    )
    log.info("  subprocess exit code: %d", result.returncode)
    if result.returncode != 0:
        log.warning("  subprocess failed — first 500 chars: %s",
                    (result.stdout or "")[:500])
    return result.stdout or "", result.returncode


def mask_cmd(cmd: list, sensitive: set) -> str:
    masked = [
        "***" if i > 0 and cmd[i - 1] in sensitive else part
        for i, part in enumerate(cmd)
    ]
    return " ".join(masked)


# ── Portal helpers ─────────────────────────────────────────────────────────────

def es_index(doc: dict, config: dict) -> str:
    """Write a document to the configured ES datastream. Returns the ES _id."""
    ds       = config.get("datastream", {})
    base_url = ds.get("elk_url", "").strip().rstrip("/")
    index    = ds.get("index", "logs-cribl-onboarding-requests")
    skip_ssl = ds.get("skip_ssl", False)
    timeout  = ds.get("timeout", 30)

    if not base_url:
        raise ValueError(
            'datastream.elk_url is not configured in config.json. '
            'Example: "datastream": { "elk_url": "https://localhost:9200", "index": "cribl-onboarding-requests", ... }'
        )

    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
        log.debug("elk_url had no scheme — prepended https://: %s", base_url)

    if skip_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = http_client.Session()
    session.verify = not skip_ssl

    headers = {"Content-Type": "application/json"}
    token    = ds.get("token",    "").strip()
    username = ds.get("username", "").strip()
    password = ds.get("password", "").strip()
    if token:
        headers["Authorization"] = f"ApiKey {token}"
    elif username:
        session.auth = (username, password)

    resp = session.post(
        f"{base_url}/{index}/_doc",
        json=doc,
        headers=headers,
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json().get("_id", "unknown")


def portal_update_status_internal(request_id: str, status: str, config: dict) -> dict:
    """
    Update the status of a portal request directly in Elasticsearch.
    Used by cribl-pusher after a successful run to mark requests as done.
    """
    ds       = config.get("datastream", {})
    base_url = ds.get("elk_url", "").strip().rstrip("/")
    index    = ds.get("index", "logs-cribl-onboarding-requests")
    skip_ssl = ds.get("skip_ssl", False)
    timeout  = ds.get("timeout", 30)

    if not base_url:
        log.warning("portal_update_status — datastream.elk_url not configured; skipping")
        return {"skipped": True, "reason": "datastream not configured"}

    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url

    if skip_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    headers = {"Content-Type": "application/json"}
    token    = ds.get("token",    "").strip()
    username = ds.get("username", "").strip()
    password = ds.get("password", "").strip()
    if token:
        headers["Authorization"] = f"ApiKey {token}"

    session = http_client.Session()
    session.verify = not skip_ssl
    if not token and username:
        session.auth = (username, password)

    payload = {
        "query":  {"term": {"request_id": request_id}},
        "script": {"source": f"ctx._source.status = '{status}'", "lang": "painless"},
    }

    try:
        resp = session.post(
            f"{base_url}/{index}/_update_by_query",
            json=payload,
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 200:
            result  = resp.json()
            updated = result.get("updated", 0)
            log.info("portal_update_status — request_id=%s  status=%s  updated=%d",
                     request_id, status, updated)
            return {"ok": True, "updated": updated}
        else:
            log.warning("portal_update_status — %d %s", resp.status_code, resp.text[:200])
            return {"ok": False, "status_code": resp.status_code, "body": resp.text[:500]}
    except Exception as exc:
        log.error("portal_update_status — failed: %s", exc)
        return {"ok": False, "error": str(exc)}


# ── Entitlement helpers ───────────────────────────────────────────────────────

def extract_entitlement_cns(rules, filter_text):
    """
    Walk the role mapping rules tree and extract DNs that contain the entitlement filter.
    Elasticsearch role mapping rules can have nested all/any/except/field structures.
    """
    cns = set()

    def walk(node):
        if not node or not isinstance(node, dict):
            return
        if 'field' in node:
            for field_key in ('dn', 'groups'):
                values = node['field'].get(field_key)
                if values is None:
                    continue
                if isinstance(values, str):
                    values = [values]
                for v in values:
                    if filter_text.lower() in v.lower():
                        cns.add(v)
        for key in ('all', 'any'):
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    walk(child)
        if 'except' in node:
            walk(node['except'])

    walk(rules)
    return list(cns)


def parse_cn(dn):
    """Extract the CN value from a full DN string."""
    match = re.search(r'CN=([^,]+)', dn, re.IGNORECASE)
    return match.group(1) if match else dn


def fetch_role_mappings(cluster):
    """Fetch role mappings from an Elasticsearch cluster via the Security API."""
    url = f"{cluster['url'].rstrip('/')}/_security/role_mapping"
    log.info("Cluster [%s] — requesting %s", cluster['name'], url)
    start = time.time()
    try:
        resp = http_client.get(
            url,
            auth=HTTPBasicAuth(cluster['username'], cluster['password']),
            verify=False,
            timeout=(10, 120),
        )
        elapsed = time.time() - start
        log.info("Cluster [%s] — %d response in %.2fs", cluster['name'], resp.status_code, elapsed)
        resp.raise_for_status()
        return resp.json()
    except http_client.exceptions.ConnectTimeout:
        log.error("Cluster [%s] — connection timed out after %.2fs to %s", cluster['name'], time.time() - start, url)
        raise
    except http_client.exceptions.ReadTimeout:
        log.error("Cluster [%s] — read timed out after %.2fs to %s", cluster['name'], time.time() - start, url)
        raise
    except http_client.exceptions.ConnectionError as e:
        log.error("Cluster [%s] — connection error after %.2fs: %s", cluster['name'], time.time() - start, e)
        raise
    except http_client.exceptions.RequestException as e:
        log.error("Cluster [%s] — request failed after %.2fs: %s", cluster['name'], time.time() - start, e)
        raise


# ── Command builders (for subprocess calls to CLI scripts) ─────────────────────

def build_pusher_cmd(form: dict, appfile_path: str) -> tuple:
    cmd = [
        sys.executable, str(PUSHER),
        "--yes",
        "--workspace",    form["workspace"],
        "--worker-group", form["worker_group"],
        "--region",       form["region"],
        "--log-level",    form.get("log_level", "INFO"),
        "--config",       str(CONFIG_PATH),
    ]

    if form.get("cribl_url", "").strip():
        cmd += ["--cribl-url", form["cribl_url"].strip()]
    if form.get("allow_prod"):
        cmd.append("--allow-prod")
    if form.get("dry_run"):
        cmd.append("--dry-run")
    if form.get("skip_ssl"):
        cmd.append("--skip-ssl")

    token    = form.get("token", "").strip()
    username = form.get("username", "").strip()
    password = form.get("password", "").strip()
    if token:
        cmd += ["--token", token]
    elif username and password:
        cmd += ["--username", username, "--password", password]

    if form.get("mode") == "bulk":
        cmd += ["--from-file", "--appfile", appfile_path or ""]
    else:
        cmd += ["--appid",   form.get("appid", "").strip(),
                "--appname", form.get("appname", "").strip()]

    group_id = form.get("group_id", "").strip()
    if group_id:
        cmd += ["--group-id", group_id]
        if form.get("create_missing_group"):
            cmd.append("--create-missing-group")
        if form.get("group_name", "").strip():
            cmd += ["--group-name", form["group_name"].strip()]

    if form.get("min_routes", "").strip():
        cmd += ["--min-existing-total-routes", form["min_routes"].strip()]
    if form.get("diff_lines", "").strip():
        cmd += ["--diff-lines", form["diff_lines"].strip()]
    if form.get("snapshot_dir", "").strip():
        cmd += ["--snapshot-dir", form["snapshot_dir"].strip()]
    if form.get("log_file", "").strip():
        cmd += ["--log-file", form["log_file"].strip()]

    sensitive = {"--password", "--token"}
    return cmd, mask_cmd(cmd, sensitive)


def build_rode_rm_cmd(form: dict, appfile_path: str) -> tuple:
    cmd = [sys.executable, str(RODE_RM), "--yes", "--config", str(CONFIG_PATH)]

    if form.get("mode") == "bulk":
        cmd += ["--from-file", "--appfile", appfile_path or ""]
    else:
        cmd += ["--app_name", form.get("app_name", "").strip(),
                "--apmid",    form.get("apmid", "").strip()]

    cribl_token    = form.get("cribl_token", "").strip()
    cribl_username = form.get("cribl_username", "").strip()
    cribl_password = form.get("cribl_password", "").strip()
    if cribl_token:
        cmd += ["--token", cribl_token]
    elif cribl_username and cribl_password:
        cmd += ["--username", cribl_username, "--password", cribl_password]

    skip_elk = bool(form.get("skip_elk"))
    if not skip_elk:
        cmd += ["--elk-url", form.get("elk_url_nonprod", "").strip()]
        np_token = form.get("elk_token_nonprod", "").strip()
        np_user  = form.get("elk_user_nonprod", "").strip()
        np_pass  = form.get("elk_password_nonprod", "").strip()
        if np_token:
            cmd += ["--elk-token", np_token]
        elif np_user:
            cmd += ["--elk-user", np_user]
            if np_pass:
                cmd += ["--elk-password", np_pass]

        cmd += ["--elk-url-prod", form.get("elk_url_prod", "").strip()]
        p_token = form.get("elk_token_prod", "").strip()
        p_user  = form.get("elk_user_prod", "").strip()
        p_pass  = form.get("elk_password_prod", "").strip()
        if p_token:
            cmd += ["--elk-token-prod", p_token]
        elif p_user:
            cmd += ["--elk-user-prod", p_user]
            if p_pass:
                cmd += ["--elk-password-prod", p_pass]

    if form.get("cribl_url", "").strip():
        cmd += ["--cribl-url", form["cribl_url"].strip()]
    cmd += ["--workspace", form.get("workspace", "")]
    if form.get("worker_group", "").strip():
        cmd += ["--worker-group", form["worker_group"].strip()]
    if form.get("region", "").strip():
        cmd += ["--region", form["region"].strip()]
    if form.get("allow_prod"):
        cmd.append("--allow-prod")
    cmd += ["--order", form.get("order", "elk-first")]
    if skip_elk:
        cmd.append("--skip-elk")
    if form.get("skip_cribl"):
        cmd.append("--skip-cribl")
    if form.get("dry_run"):
        cmd.append("--dry-run")
    if form.get("skip_ssl"):
        cmd.append("--skip-ssl")
    cmd += ["--log-level", form.get("log_level", "INFO")]

    sensitive = {
        "--elk-password", "--elk-token",
        "--elk-password-prod", "--elk-token-prod",
        "--password", "--token",
    }
    return cmd, mask_cmd(cmd, sensitive)


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — Authentication
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET"])
def login_page():
    if session.get("username"):
        return redirect(url_for("landing"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_submit():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    next_url = request.form.get("next") or request.args.get("next") or "/"

    if not username or not password:
        return render_template("login.html",
                               error="LAN ID and password are required.", next=next_url)

    success, role, display_name_or_error = ldap_authenticate(username, password)

    if not success:
        log.warning("Login failed for user=%s from %s", username, request.remote_addr)
        return render_template("login.html",
                               error=display_name_or_error, next=next_url)

    session.permanent = True
    session["username"] = username
    session["role"] = role
    session["display_name"] = display_name_or_error

    log.info("Login OK — user=%s role=%s from %s", username, role, request.remote_addr)

    # User role can only access portal and entitlements
    user_allowed = ("/portal", "/portal/", "/portal/api/submit", "/api/submit",
                    "/entitlements", "/entitlements/", "/api/entitlements")
    if role == "user" and next_url not in user_allowed:
        next_url = "/portal"

    return redirect(next_url)


@app.route("/logout")
def logout():
    username = session.get("username", "anonymous")
    session.clear()
    log.info("Logout — user=%s from %s", username, request.remote_addr)
    return redirect(url_for("login_page"))


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — Landing / Navigation
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
@login_required
def landing():
    if session.get("role") == "user":
        return redirect(url_for("portal_index"))
    return render_template("index.html")


@app.route("/health")
def health():
    return "ok", 200


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — Portal (onboarding requests)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/portal")
@app.route("/portal/")
@login_required
def portal_index():
    config = load_config()
    return render_template("request.html", iiq_url=config.get("iiq_url", ""))


@app.route("/portal/api/submit", methods=["POST"])
@app.route("/api/submit", methods=["POST"])
@login_required
def portal_submit():
    log.debug("submit — Content-Type: %s  body: %s",
              request.content_type, request.get_data(as_text=True)[:500])

    data     = request.get_json(silent=True) or {}
    lan_id   = session.get("username", (data.get("lan_id") or "").strip())
    req_name = session.get("display_name", (data.get("requester_name") or "").strip())
    app_id   = (data.get("apmid")    or "").strip()
    app_name = (data.get("appname")  or "").strip()
    region   = (data.get("region")   or "").strip()
    log_dests = [d for d in (data.get("log_destinations") or []) if d]
    log_types = [t for t in (data.get("log_types") or []) if t]
    groups   = [grp for grp in (data.get("groups") or []) if grp]

    log.info("submit — lan_id=%r  requester_name=%r  apmid=%r  appname=%r  region=%r  log_dest=%s  log_types=%s  groups=%s",
             lan_id, req_name, app_id, app_name, region, log_dests, log_types, groups)

    errors = []
    if not app_id:                        errors.append("APM ID is required.")
    if not app_name:                      errors.append("App Name is required.")
    elif not re.match(r"^\w+$", app_name):
                                          errors.append("App Name must be a single word using only letters, numbers, and underscores.")
    if region not in ("azn", "azs"):      errors.append("Region must be azn or azs.")
    if not log_dests:                     errors.append("Select at least one log destination.")
    if not log_types:                     errors.append("Select at least one log type.")
    if not groups:                        errors.append("Select at least one entitlement group.")
    if errors:
        return jsonify({"errors": errors}), 400

    try:
        config = load_config()
    except Exception as exc:
        return jsonify({"errors": [f"Could not load config.json: {exc}"]}), 500

    now        = datetime.now(timezone.utc)
    request_id = f"REQ-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

    doc = {
        "@timestamp":         now.isoformat(),
        "request_id":         request_id,
        "lan_id":             lan_id,
        "requester_name":     req_name,
        "apmid":              app_id,
        "appname":            app_name,
        "region":             region,
        "log_destinations":   log_dests,
        "log_types":          log_types,
        "entitlement_groups": groups,
        "status":             "pending",
    }

    try:
        log.info("indexing to ES — index=%s  request_id=%s",
                 config.get("datastream", {}).get("index", "logs-cribl-onboarding-requests"),
                 request_id)
        es_id = es_index(doc, config)
        log.info("ES index OK — request_id=%s  es_id=%s", request_id, es_id)
    except Exception as exc:
        log.error("ES index failed — %s: %s", type(exc).__name__, exc)
        return jsonify({"errors": [f"Failed to store request: {exc}"]}), 500

    return jsonify({"request_id": request_id})


@app.route("/portal/admin/update-status", methods=["GET", "POST"])
@app.route("/admin/update-status", methods=["GET", "POST"])
@admin_required
def portal_admin_update_status():
    if request.method == "GET":
        return render_template("admin.html")
    try:
        config = load_config()
    except Exception as exc:
        return jsonify({"errors": [f"Could not load config.json: {exc}"]}), 500

    data       = request.get_json(silent=True) or {}
    request_id = (data.get("request_id") or "").strip()
    status     = (data.get("status")     or "").strip()

    if not request_id:
        return jsonify({"errors": ["request_id is required"]}), 400
    if status not in ("pending", "done", "rejected"):
        return jsonify({"errors": ["status must be one of: pending, done, rejected"]}), 400

    ds       = config.get("datastream", {})
    base_url = ds.get("elk_url", "").strip().rstrip("/")
    index    = ds.get("index", "logs-cribl-onboarding-requests")
    skip_ssl = ds.get("skip_ssl", False)
    timeout  = ds.get("timeout", 30)

    if not base_url:
        return jsonify({"errors": ["datastream.elk_url is not configured in config.json"]}), 500

    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url

    if skip_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    headers = {"Content-Type": "application/json"}
    token    = ds.get("token",    "").strip()
    username = ds.get("username", "").strip()
    password = ds.get("password", "").strip()
    if token:
        headers["Authorization"] = f"ApiKey {token}"

    session = http_client.Session()
    session.verify = not skip_ssl
    if not token and username:
        session.auth = (username, password)

    payload = {
        "query":  {"term": {"request_id": request_id}},
        "script": {"source": f"ctx._source.status = '{status}'", "lang": "painless"},
    }

    try:
        resp = session.post(
            f"{base_url}/{index}/_update_by_query",
            json=payload,
            headers=headers,
            timeout=timeout,
        )
        resp.raise_for_status()
        result  = resp.json()
        updated = result.get("updated", 0)
        if updated == 0:
            log.warning("admin/update-status — request_id=%s not found", request_id)
            return jsonify({"errors": [f"Request ID {request_id!r} not found"]}), 404
        log.info("admin/update-status — request_id=%s  status=%s  updated=%d", request_id, status, updated)
        return jsonify({"request_id": request_id, "status": status, "updated": updated})
    except Exception as exc:
        log.error("admin/update-status failed — %s: %s", type(exc).__name__, exc)
        return jsonify({"errors": [f"Failed to update status: {exc}"]}), 500


@app.route("/health/es")
def health_es():
    try:
        config  = load_config()
        ds      = config.get("datastream", {})
        base_url = ds.get("elk_url", "").strip().rstrip("/")
        skip_ssl = ds.get("skip_ssl", False)
        timeout  = ds.get("timeout", 30)

        if not base_url.startswith(("http://", "https://")):
            base_url = "https://" + base_url

        if skip_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        headers = {"Content-Type": "application/json"}
        token    = ds.get("token",    "").strip()
        username = ds.get("username", "").strip()
        password = ds.get("password", "").strip()
        if token:
            headers["Authorization"] = f"ApiKey {token}"

        session = http_client.Session()
        session.verify = not skip_ssl
        if not token and username:
            session.auth = (username, password)

        resp = session.get(f"{base_url}/_cluster/health", headers=headers, timeout=timeout)
        return jsonify({"status": "ok", "es_status": resp.status_code, "es_body": resp.json()}), 200
    except Exception as exc:
        log.error("ES health check failed: %s", exc)
        return jsonify({"status": "error", "error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — Entitlement Lookup
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/entitlements")
@app.route("/entitlements/")
@login_required
def entitlements_page():
    return render_template("entitlements.html")


@app.route("/api/entitlements")
@login_required
def api_entitlements():
    try:
        config = load_config()
    except Exception as exc:
        return jsonify({"errors": [f"Could not load config.json: {exc}"]}), 500

    ent_cfg     = config.get("entitlement", {})
    clusters    = ent_cfg.get("clusters", [])
    filter_text = ent_cfg.get("entitlementFilter", "")

    if not clusters:
        return jsonify({"errors": ["No entitlement clusters configured in config.json"]}), 500

    log.info("Entitlements API called — filter: '%s', clusters: %d", filter_text, len(clusters))
    results = []

    for cluster in clusters:
        try:
            role_mappings = fetch_role_mappings(cluster)
            log.info("Cluster [%s] — %d role mappings returned", cluster['name'], len(role_mappings))

            for mapping_name, mapping in role_mappings.items():
                entitlement_dns = extract_entitlement_cns(
                    mapping.get('rules', {}), filter_text
                )
                for dn in entitlement_dns:
                    results.append({
                        'cluster': cluster['name'],
                        'mappingName': mapping_name,
                        'entitlement': parse_cn(dn),
                        'entitlementDN': dn,
                        'roles': mapping.get('roles', []),
                        'enabled': mapping.get('enabled', False),
                    })

        except Exception as e:
            log.exception("Cluster [%s] — failed: %s", cluster['name'], e)
            results.append({
                'cluster': cluster['name'],
                'mappingName': '-',
                'entitlement': f'ERROR: {str(e)}',
                'entitlementDN': '',
                'roles': [],
                'enabled': False,
                'error': True,
            })

    results.sort(key=lambda r: (r['cluster'], r['entitlement']))
    return jsonify(results)


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — Cribl Pusher (automation UI)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/cribl")
@app.route("/cribl/")
@admin_required
def cribl_landing():
    return render_template("index.html")


@app.route("/cribl/app")
@app.route("/cribl/app/")
@admin_required
def cribl_app_page():
    try:
        config = load_config()
    except Exception as exc:
        log.error("Failed to load config.json: %s", exc)
        return f"Error loading config.json: {exc}", 500
    workspaces = {
        k: v for k, v in config.get("workspaces", {}).items()
        if not k.startswith("_")
    }
    return render_template("app.html", workspaces=workspaces, config=config)


@app.route("/cribl/api/run-pusher", methods=["POST"])
@admin_required
def run_pusher():
    form       = request.form
    file       = request.files.get("appfile")
    mode       = form.get("mode", "single")
    request_id = (form.get("request_id") or "").strip()

    errors = []
    if mode == "single":
        if not form.get("appid", "").strip():   errors.append("App ID is required.")
        if not form.get("appname", "").strip(): errors.append("App Name is required.")
    else:
        if not file or not file.filename:
            errors.append("Please upload an app list file (.txt).")

    worker_groups = form.getlist("worker_groups")
    if not worker_groups:
        errors.append("Select at least one worker group.")

    try:
        config = load_config()
    except Exception as exc:
        log.error("Config load error: %s", exc)
        return jsonify({"errors": [f"Could not load config.json: {exc}"]}), 500

    ws_cfg = config.get("workspaces", {}).get(form.get("workspace", ""), {})
    if ws_cfg.get("require_allow") and not form.get("allow_prod"):
        errors.append(
            f"Workspace '{form.get('workspace')}' requires the "
            "'Allow production writes' checkbox."
        )

    if errors:
        log.warning("run-pusher validation failed: %s", errors)
        return jsonify({"errors": errors}), 400

    log.info("run-pusher  workspace=%s  wgs=%s  mode=%s  dry_run=%s",
             form.get("workspace"), worker_groups, mode,
             bool(form.get("dry_run")))

    tmp_path = None
    try:
        if mode == "bulk" and file:
            with tempfile.NamedTemporaryFile(
                mode="wb", suffix=".txt", delete=False, dir=SCRIPT_DIR
            ) as tmp:
                file.save(tmp)
                tmp_path = tmp.name

        all_output = ""
        last_rc    = 0
        commands   = []

        for wg in worker_groups:
            form_dict = form.to_dict()
            form_dict["worker_group"] = wg
            cmd, masked = build_pusher_cmd(form_dict, tmp_path or "")
            commands.append({"wg": wg, "cmd": masked})
            output, rc = run_subprocess(cmd, masked)
            all_output += f"\n{'='*60}\n Worker group: {wg}\n{'='*60}\n{output}"
            if rc != 0:
                last_rc = rc

    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    portal_result = None
    dry_run = bool(form.get("dry_run"))
    if last_rc == 0 and not dry_run and request_id:
        portal_result = portal_update_status_internal(request_id, "done", config)

    return jsonify({
        "output":        all_output.strip(),
        "returncode":    last_rc,
        "commands":      commands,
        "portal_update": portal_result,
    })


@app.route("/cribl/api/run-rode-rm", methods=["POST"])
@admin_required
def run_rode_rm():
    form       = request.form
    file       = request.files.get("appfile")
    mode       = form.get("mode", "single")
    request_id = (form.get("request_id") or "").strip()

    errors    = []
    skip_elk   = bool(form.get("skip_elk"))
    skip_cribl = bool(form.get("skip_cribl"))

    if mode == "single":
        if not form.get("app_name", "").strip(): errors.append("App Name is required.")
        if not form.get("apmid", "").strip():    errors.append("App ID is required.")
    else:
        if not file or not file.filename:
            errors.append("Please upload an app list file (.txt).")

    if skip_elk and skip_cribl:
        errors.append("Nothing to do: both Skip ELK and Skip Cribl are checked.")

    if not skip_cribl and not form.get("worker_group", "").strip():
        errors.append("Worker Group is required when Cribl is not skipped.")

    if not skip_elk:
        if not form.get("elk_url_nonprod", "").strip():
            errors.append("ELK Nonprod URL is required.")
        if not form.get("elk_token_nonprod", "").strip() and not form.get("elk_user_nonprod", "").strip():
            errors.append("ELK Nonprod: provide User or Token.")
        if not form.get("elk_url_prod", "").strip():
            errors.append("ELK Prod URL is required.")
        if not form.get("elk_token_prod", "").strip() and not form.get("elk_user_prod", "").strip():
            errors.append("ELK Prod: provide User or Token.")

    try:
        config = load_config()
    except Exception as exc:
        log.error("Config load error: %s", exc)
        return jsonify({"errors": [f"Could not load config.json: {exc}"]}), 500

    ws_cfg = config.get("workspaces", {}).get(form.get("workspace", ""), {})
    if ws_cfg.get("require_allow") and not form.get("allow_prod"):
        errors.append(
            f"Workspace '{form.get('workspace')}' requires the "
            "'Allow production writes' checkbox."
        )

    if errors:
        log.warning("run-rode-rm validation failed: %s", errors)
        return jsonify({"errors": errors}), 400

    log.info("run-rode-rm  workspace=%s  wg=%s  mode=%s  skip_elk=%s  skip_cribl=%s  dry_run=%s",
             form.get("workspace"), form.get("worker_group"), mode,
             skip_elk, skip_cribl, bool(form.get("dry_run")))

    tmp_path = None
    try:
        if mode == "bulk" and file:
            with tempfile.NamedTemporaryFile(
                mode="wb", suffix=".txt", delete=False, dir=SCRIPT_DIR
            ) as tmp:
                file.save(tmp)
                tmp_path = tmp.name

        cmd, masked = build_rode_rm_cmd(form.to_dict(), tmp_path or "")
        output, rc  = run_subprocess(cmd, masked)

    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    portal_result = None
    dry_run = bool(form.get("dry_run"))
    if rc == 0 and not dry_run and request_id:
        portal_result = portal_update_status_internal(request_id, "done", config)

    return jsonify({
        "output":        output,
        "returncode":    rc,
        "command":       masked,
        "portal_update": portal_result,
    })


if __name__ == "__main__":
    log.info("Starting Cribl Framework on 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
