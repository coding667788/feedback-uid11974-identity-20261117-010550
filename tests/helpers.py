"""测试公共工具:真实子进程网关 + 真实 HTTP 请求。"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from gateway import protocol  # noqa: E402


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def run_cli(module_args, check=True):
    return subprocess.run([sys.executable, "-m"] + module_args,
                          cwd=ROOT, capture_output=True, text=True, check=check)


def seed_db(db_path: str) -> None:
    run_cli(["gateway.seed", "--db", db_path, "--force"])


def keymgr(db_path: str, *args) -> str:
    return run_cli(["gateway.keymgr", "--db", db_path] + list(args)).stdout


def db_query(db_path: str, sql: str, params=()):
    con = sqlite3.connect(db_path, timeout=15)
    try:
        return con.execute(sql, params).fetchall()
    finally:
        con.close()


def key_for(db_path: str, tenant: str, name: str, include_revoked=False):
    """返回 [(key_id, secret, revoked), ...],按创建顺序。"""
    sql = ("SELECT k.key_id, k.secret, k.revoked FROM keys k"
           " JOIN identities i ON i.identity_id = k.identity_id"
           " WHERE i.tenant_id=? AND i.name=?")
    if not include_revoked:
        sql += " AND k.revoked=0"
    sql += " ORDER BY k.rowid"
    return db_query(db_path, sql, (tenant, name))


def start_gateway(port: int, db_path: str, extra_env=None, wait=True):
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env.update(extra_env or {})
    p = subprocess.Popen(
        [sys.executable, "-m", "gateway.server",
         "--port", str(port), "--db", db_path],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if wait:
        wait_health(port)
    return p


def stop_gateway(p) -> None:
    if p.poll() is None:
        p.terminate()
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(timeout=5)


def wait_health(port: int, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            conn.request("GET", "/health")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status == 200:
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("gateway on port %d not ready" % port)


def health_now(port: int) -> float:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/health")
    resp = conn.getresponse()
    data = json.loads(resp.read())
    conn.close()
    return float(data["now"])


def signed_headers(key_id: str, secret: str, method: str, target: str,
                   body: bytes, timestamp=None, nonce=None) -> dict:
    ts = str(timestamp if timestamp is not None else int(time.time()))
    nc = nonce if nonce is not None else secrets.token_hex(16)
    body_sha = hashlib.sha256(body).hexdigest()
    return {
        protocol.H_KEY_ID: key_id,
        protocol.H_TIMESTAMP: ts,
        protocol.H_NONCE: nc,
        protocol.H_BODY_SHA256: body_sha,
        protocol.H_SIGNATURE: protocol.sign(secret, method, target, ts, nc,
                                            body_sha),
    }


def call(port: int, method: str, target: str, key_id: str, secret: str,
         body: bytes = b"", timestamp=None, nonce=None,
         extra_headers=None, header_overrides=None):
    """发送一次真实签名 HTTP 请求,返回 (status, payload_dict)。"""
    headers = signed_headers(key_id, secret, method, target, body,
                             timestamp=timestamp, nonce=nonce)
    if header_overrides:
        headers.update(header_overrides)
    if extra_headers:
        headers.update(extra_headers)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    conn.request(method, target, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    status = resp.status
    conn.close()
    try:
        payload = json.loads(data)
    except ValueError:
        payload = {"raw": data.decode("utf-8", "replace")}
    return status, payload


def raw_call(port: int, raw: bytes):
    """发送原始字节(用于重复头/畸形请求测试),返回 (status, body_bytes)。"""
    s = socket.create_connection(("127.0.0.1", port), timeout=15)
    s.sendall(raw)
    chunks = []
    while True:
        d = s.recv(65536)
        if not d:
            break
        chunks.append(d)
    s.close()
    data = b"".join(chunks)
    status = int(data.split(b" ", 2)[1])
    body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
    return status, body
