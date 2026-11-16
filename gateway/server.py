"""HTTP 签名网关。

端点(均需签名,除 /health):
  GET  /health              未签名,返回服务器当前时刻(测试/演示用)
  POST /v1/counter/increment  账户计数器 +1,返回新值
  GET  /v1/counter            查询账户计数器

身份模型:租户与服务身份完全由 X-Key-Id 对应的服务端记录推导,
请求体/请求参数中任何自报身份一律不被采信(本网关也不解析业务参数)。

原子性:密钥/身份状态检查(事务内重新检查)、nonce 占用、业务写入、
审计记录在同一 BEGIN IMMEDIATE ... COMMIT 中提交。签名验证失败、
时间窗超界、越权目标等均发生在 nonce 插入之前,不会预先占用 nonce。

测试钩子(仅当环境变量 GATEWAY_TEST_HOOKS=1 时生效,且不参与签名):
  X-Test-Kill-At: after_nonce | after_business | after_commit
      在对应位置 os._exit(42) 自杀,用于故障注入测试。
  X-Test-Sleep-Before-Txn: <秒>
      在"事务外预检"之后、"事务内重新检查"之前睡眠,
      用于制造"撤销先提交、旧密钥请求后进入事务"的交错。
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
import sqlite3
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import protocol
from .clock import Clock
from .db import connect

CLOCK = Clock()
TEST_HOOKS = os.environ.get("GATEWAY_TEST_HOOKS") == "1"

ROUTE_INCREMENT = "/v1/counter/increment"
ROUTE_QUERY = "/v1/counter"
ROUTES = {ROUTE_INCREMENT: "POST", ROUTE_QUERY: "GET"}


class AuthFailure(Exception):
    """认证/授权失败。reason 进入审计,message 返回给客户端(均不含密钥/签名)。"""

    def __init__(self, status: int, reason: str, message: str):
        super().__init__(message)
        self.status = status
        self.reason = reason
        self.message = message


def _load_key_row(con, key_id: str):
    return con.execute(
        "SELECT k.key_id, k.secret, k.revoked,"
        "       i.identity_id, i.tenant_id, i.disabled"
        " FROM keys k JOIN identities i ON i.identity_id = k.identity_id"
        " WHERE k.key_id = ?", (key_id,)).fetchone()


def _check_state(row) -> None:
    if row is None:
        raise AuthFailure(401, "unknown_key", "unknown key_id")
    if row[2]:
        raise AuthFailure(401, "key_revoked", "key has been revoked")
    if row[5]:
        raise AuthFailure(403, "identity_disabled", "service identity is disabled")


def _ctx_from_row(row) -> dict:
    return {"key_id": row[0], "secret": row[1], "revoked": row[2],
            "identity_id": row[3], "tenant_id": row[4], "disabled": row[5]}


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "SigGateway/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # 日志不含密钥/签名
        sys.stderr.write("[gw:%d] %s %s\n"
                         % (self.server.port, self.address_string(), fmt % args))

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    # ---------------- 请求处理 ----------------

    def _dispatch(self, method: str) -> None:
        try:
            status, payload = self._process(method)
        except protocol.ProtocolError as exc:
            status, payload = 400, {"error": str(exc)}
        except Exception:
            traceback.print_exc()
            status, payload = 500, {"error": "internal error"}
        try:
            self._respond(status, payload)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _process(self, method: str):
        # 1. request-target 协议校验(不解码、不重排,原样参与签名)
        target = self.path
        protocol.validate_request_target(target)
        route = target.split("?", 1)[0]

        if route == "/health" and method == "GET":
            return 200, {"ok": True, "now": CLOCK.now()}
        # 越权/未知目标:在消耗 nonce 之前直接拒绝
        if route not in ROUTES:
            return 404, {"error": "unknown target"}
        if ROUTES[route] != method:
            return 405, {"error": "method not allowed"}
        action = "increment" if route == ROUTE_INCREMENT else "query"

        # 2. 五个认证头:唯一、必填、格式合法
        hdrs = self._auth_headers()
        key_id = protocol.validate_key_id(hdrs[protocol.H_KEY_ID])
        ts_text = hdrs[protocol.H_TIMESTAMP]
        req_ts = protocol.validate_timestamp(ts_text)
        nonce = protocol.validate_nonce(hdrs[protocol.H_NONCE])
        body_sha = protocol.validate_hex64(hdrs[protocol.H_BODY_SHA256],
                                           "X-Body-Sha256")
        sig = protocol.validate_hex64(hdrs[protocol.H_SIGNATURE], "X-Signature")

        # 3. 请求体(<=1MiB)与其 SHA256 比对;不符则拒绝且不消耗 nonce
        body = self._read_body(method)
        if protocol.body_sha256_hex(body) != body_sha:
            raise protocol.ProtocolError("X-Body-Sha256 does not match request body")

        con = connect(self.server.db_path)
        ctx = {"tenant_id": None, "identity_id": None, "key_id": key_id}
        try:
            try:
                # 4. 事务外预检:取密钥、验时间窗、验签名(均不消耗 nonce)
                row = _load_key_row(con, key_id)
                _check_state(row)
                ctx = _ctx_from_row(row)
                now = CLOCK.now()
                if not protocol.timestamp_in_window(req_ts, now):
                    raise AuthFailure(401, "stale_timestamp",
                                      "timestamp outside +/-%ds window"
                                      % protocol.SKEW_SECONDS)
                expected = protocol.sign(ctx["secret"], method, target,
                                         ts_text, nonce, body_sha)
                if not hmac.compare_digest(expected, sig):
                    raise AuthFailure(401, "invalid_signature",
                                      "signature mismatch")

                self._hook_sleep_before_txn()

                # 5. 原子事务:重新检查状态 + 占用 nonce + 业务写入 + 审计
                con.execute("BEGIN IMMEDIATE")
                try:
                    # 撤销/禁用若已提交,在此处重新检查并失败
                    _check_state(_load_key_row(con, key_id))
                    # nonce 至少保留到其签名时间窗完全过期后才可清理
                    con.execute("DELETE FROM nonces WHERE req_ts + ? < ?",
                                (protocol.SKEW_SECONDS, now))
                    try:
                        con.execute(
                            "INSERT INTO nonces(tenant_id, identity_id, nonce, req_ts)"
                            " VALUES(?,?,?,?)",
                            (ctx["tenant_id"], ctx["identity_id"], nonce, req_ts))
                    except sqlite3.IntegrityError:
                        raise AuthFailure(409, "replay", "nonce already used")
                    self._hook_kill("after_nonce")

                    if action == "increment":
                        con.execute(
                            "INSERT INTO counters(identity_id, value) VALUES(?, 1)"
                            " ON CONFLICT(identity_id) DO UPDATE SET value = value + 1",
                            (ctx["identity_id"],))
                    row_v = con.execute(
                        "SELECT value FROM counters WHERE identity_id = ?",
                        (ctx["identity_id"],)).fetchone()
                    value = row_v[0] if row_v else 0
                    self._hook_kill("after_business")

                    self._audit(con, ctx, action, "ok", "")
                    con.execute("COMMIT")
                except BaseException:
                    try:
                        con.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
                self._hook_kill("after_commit")

                return 200, {"status": "ok", "action": action,
                             "tenant_id": ctx["tenant_id"],
                             "identity_id": ctx["identity_id"],
                             "counter": value}
            except AuthFailure as exc:
                # 失败审计在事务外(autocommit)写入,不随业务事务回滚
                self._audit(con, ctx, action, exc.reason, exc.message)
                return exc.status, {"error": exc.message}
        finally:
            con.close()

    # ---------------- 辅助 ----------------

    def _auth_headers(self) -> dict:
        out = {}
        for name in protocol.AUTH_HEADERS:
            vals = self.headers.get_all(name)
            if not vals:
                raise protocol.ProtocolError("missing required header: " + name)
            if len(vals) > 1:
                raise protocol.ProtocolError("duplicate header: " + name)
            out[name] = vals[0]
        return out

    def _read_body(self, method: str) -> bytes:
        if self.headers.get("Transfer-Encoding") is not None:
            raise protocol.ProtocolError("Transfer-Encoding not supported")
        vals = self.headers.get_all("Content-Length")
        if vals is None:
            return b""
        if len(vals) > 1:
            raise protocol.ProtocolError("duplicate Content-Length header")
        text = vals[0]
        if not (text.isascii() and text.isdigit()) or text != str(int(text)):
            raise protocol.ProtocolError("Content-Length not canonical")
        length = int(text)
        if length > protocol.MAX_BODY_BYTES:
            raise protocol.ProtocolError("request body exceeds 1 MiB limit")
        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            raise protocol.ProtocolError("incomplete request body")
        return body

    def _audit(self, con, ctx: dict, action: str, result: str, detail: str) -> None:
        try:
            con.execute(
                "INSERT INTO audit(server_ts, tenant_id, identity_id, key_id,"
                " action, result, detail) VALUES(?,?,?,?,?,?,?)",
                (CLOCK.now(), ctx.get("tenant_id"), ctx.get("identity_id"),
                 ctx.get("key_id"), action, result, detail))
        except sqlite3.Error:
            traceback.print_exc()

    def _hook_kill(self, point: str) -> None:
        if TEST_HOOKS and self.headers.get("X-Test-Kill-At") == point:
            sys.stderr.write("[gw:%d] TEST KILL at %s\n"
                             % (self.server.port, point))
            sys.stderr.flush()
            os._exit(42)

    def _hook_sleep_before_txn(self) -> None:
        if TEST_HOOKS:
            v = self.headers.get("X-Test-Sleep-Before-Txn")
            if v:
                time.sleep(float(v))

    def _respond(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class GatewayServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, db_path: str):
        self.db_path = db_path
        self.port = addr[1]
        super().__init__(addr, GatewayHandler)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="HMAC 签名认证网关")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--db", required=True, help="SQLite 数据库文件路径")
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args(argv)
    srv = GatewayServer((args.host, args.port), args.db)
    sys.stderr.write("[gw:%d] listening on %s, db=%s\n"
                     % (args.port, args.host, args.db))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
