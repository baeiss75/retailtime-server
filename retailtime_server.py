"""
RetailTime Sync Server
======================
A tiny central server that receives database snapshots from each store
(RetailTime desktop app with Internet Sync enabled) and serves them to
the master dashboard.

Endpoints (all require the X-Api-Key header):
    POST /upload/<branch>   store uploads its timecard.db snapshot
    GET  /db/<branch>       master dashboard downloads a branch DB
    GET  /status            list branches + last upload times (JSON)

Quick start (local test):
    pip install flask
    set API_KEY=choose-a-long-random-secret     (Windows)
    export API_KEY=choose-a-long-random-secret  (Linux/Mac)
    python retailtime_server.py                 (listens on port 8000)

Production notes:
  - Run behind HTTPS. Easiest: deploy on Render/Railway/Fly.io free or
    hobby tier (HTTPS automatic), or a $5 VPS with Caddy in front.
  - Set a long random API_KEY environment variable; put the same key in
    each store's Settings and in the master's Settings.
  - Data lives in ./data/<branch>.db next to this file. Back that
    folder up like any other important data.
"""

import os
import re
import json
import sqlite3
import tempfile
from datetime import datetime

from flask import Flask, request, jsonify, send_file, abort

app = Flask(__name__)

API_KEY = os.environ.get("API_KEY", "")
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)

MAX_DB_BYTES = 50 * 1024 * 1024          # refuse uploads bigger than 50 MB
BRANCH_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


def check_auth():
    if not API_KEY:
        abort(500, "server has no API_KEY configured")
    if request.headers.get("X-Api-Key", "") != API_KEY:
        abort(401, "bad or missing X-Api-Key")


def branch_path(branch):
    if not BRANCH_RE.match(branch):
        abort(400, "invalid branch name (letters, digits, - and _ only)")
    return os.path.join(DATA_DIR, f"{branch}.db")


@app.post("/upload/<branch>")
def upload(branch):
    check_auth()
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
    check_auth()
    path = branch_path(branch)
    if not os.path.exists(path):
        abort(404, "no data uploaded yet for this branch")
    return send_file(path, mimetype="application/octet-stream",
                     as_attachment=True, download_name=f"{branch}.db")


@app.get("/status")
def status():
    check_auth()
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
    check_auth()
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
    check_auth()
    return jsonify(commands=_load_cmds(branch))


@app.post("/commands/<branch>/ack")
def ack_commands(branch):
    """Branch acknowledges command ids it has processed."""
    check_auth()
    body = request.get_json(silent=True) or {}
    ids = set(body.get("ids", []))
    if not ids:
        abort(400, "ids list required")
    cmds = [c for c in _load_cmds(branch) if c["id"] not in ids]
    _save_cmds(branch, cmds)
    return jsonify(ok=True, remaining=len(cmds))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
