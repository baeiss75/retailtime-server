"""
RetailTime Sync Server
======================
A tiny central server that receives database snapshots from each store
(RetailTime desktop app with Internet Sync enabled) and serves them to
the master dashboard.

Key model (two tiers, so a leaked branch key can't touch other branches):
    HQ key    (env var API_KEY) — full access to every branch. Only ever
              entered in Settings on the MASTER/HQ computer.
    Branch key — derived automatically from the HQ key + branch name.
              Each store's app uses only its own derived key, which can
              upload/fetch its own commands but cannot read or command
              ANY other branch. Get a branch's key via GET /branch-key/
              (HQ key required) instead of computing it by hand.

Endpoints:
    POST /upload/<branch>        branch key OR HQ key — upload a snapshot
    GET  /db/<branch>            HQ key only — download a branch's DB
    GET  /status                 HQ key only — list branches
    POST /command/<branch>       HQ key only — queue an instruction
    GET  /commands/<branch>      branch key OR HQ key — fetch its queue
    POST /commands/<branch>/ack  branch key OR HQ key — acknowledge
    GET  /branch-key/<branch>    HQ key only — get that branch's derived key

Quick start (local test):
    pip install flask
    set API_KEY=choose-a-long-random-secret     (Windows)
    export API_KEY=choose-a-long-random-secret  (Linux/Mac)
    python retailtime_server.py                 (listens on port 8000)

Production notes:
  - Run behind HTTPS. Easiest: deploy on Render/Railway/Fly.io free or
    hobby tier (HTTPS automatic), or a $5 VPS with Caddy in front.
  - Set a long random API_KEY environment variable — this is the HQ key.
    Put it ONLY in the master computer's Settings. Each store's own
    computer gets its own derived branch key instead (see RetailTime's
    Settings > Internet Sync > "Get This Branch's Key").
  - Data lives in ./data/<branch>.db next to this file. Back that
    folder up like any other important data.
"""

import os
import re
import json
import hmac
import hashlib
import sqlite3
import tempfile
from datetime import datetime

from flask import Flask, request, jsonify, send_file, abort

app = Flask(__name__)

# API_KEY (env var) is now the MASTER / HQ key. It grants full access to
# every branch. Each branch instead uses a KEY DERIVED from this master
# key + its own branch name — so a branch key can only upload/fetch its
# own commands, never read or command any OTHER branch. If a branch key
# leaks, the damage is contained to that one branch.
HQ_KEY = os.environ.get("API_KEY", "")
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)

MAX_DB_BYTES = 50 * 1024 * 1024          # refuse uploads bigger than 50 MB
BRANCH_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


def derive_branch_key(branch):
    return hmac.new(HQ_KEY.encode(), branch.encode(),
                    hashlib.sha256).hexdigest()[:32]


def _presented_key():
    return request.headers.get("X-Api-Key", "")


def check_hq_auth():
    """Full access: only the master HQ key is accepted."""
    if not HQ_KEY:
        abort(500, "server has no API_KEY (HQ key) configured")
    if not hmac.compare_digest(_presented_key(), HQ_KEY):
        abort(401, "HQ key required for this operation")


def check_branch_auth(branch):
    """Scoped access for one branch: its own derived key, OR the HQ key
    (so the master can also act on behalf of any branch if ever needed)."""
    if not HQ_KEY:
        abort(500, "server has no API_KEY (HQ key) configured")
    presented = _presented_key()
    if hmac.compare_digest(presented, HQ_KEY):
        return
    if hmac.compare_digest(presented, derive_branch_key(branch)):
        return
    abort(401, "invalid key for this branch")


def branch_path(branch):
    if not BRANCH_RE.match(branch):
        abort(400, "invalid branch name (letters, digits, - and _ only)")
    return os.path.join(DATA_DIR, f"{branch}.db")


@app.post("/upload/<branch>")
def upload(branch):
    check_branch_auth(branch)
    path = branch_path(branch)
    body = request.get_data(cache=False)
    if not body:
        abort(400, "empty upload")
    if len(body) > MAX_DB_BYTES:
        abort(413, "database too large")
    if not body.startswith(b"SQLite format 3"):
        abort(400, "not a SQLite database")
    # verify integrity BEFORE replacing the stored copy, so a corrupted
    # upload can never clobber the last good snapshot
    fd, tmp = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(body)
        try:
            con = sqlite3.connect(tmp)
            ok = con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            con.close()
        except sqlite3.Error:
            ok = False
        if not ok:
            abort(400, "database failed integrity check")
        os.replace(tmp, path)          # atomic swap
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    return jsonify(ok=True, branch=branch, bytes=len(body))


@app.get("/db/<branch>")
def download(branch):
    check_hq_auth()
    path = branch_path(branch)
    if not os.path.exists(path):
        abort(404, "no data uploaded yet for this branch")
    return send_file(path, mimetype="application/octet-stream",
                     as_attachment=True, download_name=f"{branch}.db")


@app.get("/status")
def status():
    check_hq_auth()
    out = []
    for fn in sorted(os.listdir(DATA_DIR)):
        if fn.endswith(".db"):
            p = os.path.join(DATA_DIR, fn)
            out.append({
                "branch": fn[:-3],
                "size_kb": round(os.path.getsize(p) / 1024, 1),
                "last_upload": datetime.fromtimestamp(
                    os.path.getmtime(p)).strftime("%Y-%m-%d %H:%M:%S"),
            })
    return jsonify(branches=out)


# ---------------------------------------------------------------------------
# Command queue: HQ -> branch instructions (e.g. edit an employee's name).
# The branch's OWN app applies each command to its local database at its
# next sync, then acknowledges it. The server just holds the mailbox.
# ---------------------------------------------------------------------------

def _cmd_path(branch):
    if not BRANCH_RE.match(branch):
        abort(400, "invalid branch name")
    return os.path.join(DATA_DIR, f"{branch}.commands.json")


def _load_cmds(branch):
    p = _cmd_path(branch)
    if not os.path.exists(p):
        return []
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return []


def _save_cmds(branch, cmds):
    p = _cmd_path(branch)
    fd, tmp = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cmds, fh)
    os.replace(tmp, p)


@app.post("/command/<branch>")
def post_command(branch):
    """HQ pushes one command for a branch to apply."""
    check_hq_auth()
    body = request.get_json(silent=True)
    if not body or "type" not in body:
        abort(400, "JSON body with a 'type' field required")
    cmds = _load_cmds(branch)
    cmd_id = int(datetime.now().timestamp() * 1000)
    while any(c["id"] == cmd_id for c in cmds):
        cmd_id += 1
    cmds.append({"id": cmd_id, "type": body["type"],
                 "payload": body.get("payload", {}),
                 "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    _save_cmds(branch, cmds)
    return jsonify(ok=True, id=cmd_id, pending=len(cmds))


@app.get("/commands/<branch>")
def get_commands(branch):
    """Branch fetches its pending commands."""
    check_branch_auth(branch)
    return jsonify(commands=_load_cmds(branch))


@app.post("/commands/<branch>/ack")
def ack_commands(branch):
    """Branch acknowledges command ids it has processed."""
    check_branch_auth(branch)
    body = request.get_json(silent=True) or {}
    ids = set(body.get("ids", []))
    if not ids:
        abort(400, "ids list required")
    cmds = [c for c in _load_cmds(branch) if c["id"] not in ids]
    _save_cmds(branch, cmds)
    return jsonify(ok=True, remaining=len(cmds))


@app.get("/branch-key/<branch>")
def branch_key(branch):
    """HQ-only: hand back the derived key for one branch, so the owner
    only ever has to remember the single HQ key and can fetch each
    branch's own key on demand instead of computing it by hand."""
    check_hq_auth()
    if not BRANCH_RE.match(branch):
        abort(400, "invalid branch name")
    return jsonify(branch=branch, key=derive_branch_key(branch))


# ---------------------------------------------------------------------------
# License revocation. license_id is an opaque, non-sensitive identifier
# (not a secret) — the license key's real protection is its signature,
# verified locally by the app using LICENSE_SECRET (a separate value not
# stored here). This endpoint only answers "has this id been killed?" so
# the status check itself needs no auth; only revoking/unrevoking does.
# ---------------------------------------------------------------------------

REVOKED_PATH = os.path.join(DATA_DIR, "revoked_licenses.json")
LICENSE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _load_revoked():
    if not os.path.exists(REVOKED_PATH):
        return {}
    try:
        with open(REVOKED_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save_revoked(data):
    fd, tmp = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, REVOKED_PATH)


@app.get("/license/<license_id>")
def license_status(license_id):
    if not LICENSE_RE.match(license_id):
        abort(400, "invalid license id")
    revoked = _load_revoked()
    entry = revoked.get(license_id)
    return jsonify(license_id=license_id, revoked=bool(entry),
                  reason=(entry or {}).get("reason", "") if entry else "")


@app.post("/admin/license/revoke/<license_id>")
def license_revoke(license_id):
    check_hq_auth()
    if not LICENSE_RE.match(license_id):
        abort(400, "invalid license id")
    body = request.get_json(silent=True) or {}
    revoked = _load_revoked()
    revoked[license_id] = {
        "reason": body.get("reason", ""),
        "revoked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    _save_revoked(revoked)
    return jsonify(ok=True, license_id=license_id, revoked=True)


@app.post("/admin/license/unrevoke/<license_id>")
def license_unrevoke(license_id):
    check_hq_auth()
    if not LICENSE_RE.match(license_id):
        abort(400, "invalid license id")
    revoked = _load_revoked()
    revoked.pop(license_id, None)
    _save_revoked(revoked)
    return jsonify(ok=True, license_id=license_id, revoked=False)


@app.get("/admin/license/list")
def license_list():
    check_hq_auth()
    return jsonify(revoked=_load_revoked())


# ---------------------------------------------------------------------------
# Version manifest — lets HQ publish "a new RetailTime build is available,
# get it here" without emailing exe files around. Version info itself
# isn't sensitive, so GET needs no auth (even a freshly-installed branch
# machine with no key configured yet could, in principle, check); only
# publishing a new notice requires the HQ key.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Version manifest — lets HQ publish "here's the version everyone should
# be on, get it here" without emailing exe files around. Version info
# isn't sensitive, so GET needs no auth; only publishing needs the HQ
# key. Every publish is kept in history (never overwritten), so an older
# version's download link stays findable — including for a ROLLBACK:
# re-publishing an OLDER version as "current" is exactly how you tell
# every branch "go back to this one, the newer build had a problem."
# ---------------------------------------------------------------------------

VERSION_PATH = os.path.join(DATA_DIR, "version.json")


def _load_version_data():
    if not os.path.exists(VERSION_PATH):
        return {"current": None, "history": []}
    try:
        with open(VERSION_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        data.setdefault("current", None)
        data.setdefault("history", [])
        return data
    except Exception:
        return {"current": None, "history": []}


@app.get("/version")
def version_get():
    cur = _load_version_data()["current"]
    if not cur:
        return jsonify(version="", url="", notes="")
    return jsonify(**cur)


@app.get("/versions")
def versions_list():
    return jsonify(history=_load_version_data()["history"])


@app.post("/version")
def version_set():
    check_hq_auth()
    body = request.get_json(silent=True) or {}
    version = str(body.get("version", "")).strip()
    url = str(body.get("url", "")).strip()
    notes = str(body.get("notes", "")).strip()
    if not version or not url:
        abort(400, "version and url are required")
    entry = {"version": version, "url": url, "notes": notes,
             "published": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    data = _load_version_data()
    data["current"] = entry
    data["history"].append(entry)  # newest last; never removed/overwritten
    fd, tmp = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, VERSION_PATH)
    return jsonify(ok=True, version=version)


# ---------------------------------------------------------------------------
# Daily report cloud backup — each branch's Store Close report gets
# uploaded here too, so it's retrievable even if that branch's computer
# is dead/unreachable. Same branch-key scoping as /upload — a branch can
# only push/read its OWN reports; the HQ key can read any branch's.
# ---------------------------------------------------------------------------

REPORT_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _report_path(branch, day):
    if not BRANCH_RE.match(branch):
        abort(400, "invalid branch name")
    if not REPORT_DATE_RE.match(day):
        abort(400, "invalid date (expected YYYY-MM-DD)")
    d = os.path.join(DATA_DIR, "reports", branch)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, f"{day}.html")


@app.post("/report/<branch>/<day>")
def report_upload(branch, day):
    check_branch_auth(branch)
    body = request.get_data(cache=False)
    if not body:
        abort(400, "empty report")
    if len(body) > 5 * 1024 * 1024:
        abort(413, "report too large")
    path = _report_path(branch, day)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    with os.fdopen(fd, "wb") as fh:
        fh.write(body)
    os.replace(tmp, path)
    return jsonify(ok=True, branch=branch, date=day, bytes=len(body))


@app.get("/report/<branch>/<day>")
def report_download(branch, day):
    check_branch_auth(branch)
    path = _report_path(branch, day)
    if not os.path.exists(path):
        abort(404, "no report on file for that branch/date")
    return send_file(path, mimetype="text/html")


@app.get("/reports/<branch>")
def report_list(branch):
    check_branch_auth(branch)
    if not BRANCH_RE.match(branch):
        abort(400, "invalid branch name")
    d = os.path.join(DATA_DIR, "reports", branch)
    if not os.path.isdir(d):
        return jsonify(branch=branch, dates=[])
    dates = sorted(fn[:-5] for fn in os.listdir(d) if fn.endswith(".html"))
    return jsonify(branch=branch, dates=dates)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
