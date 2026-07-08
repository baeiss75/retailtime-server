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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
