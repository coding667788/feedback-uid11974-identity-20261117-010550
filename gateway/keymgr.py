"""密钥/身份管理命令行。

子命令:
  list                                列出身份与密钥状态(不显示密钥明文)
  enable-key   --tenant T --identity I  启用一把新密钥(自动轮换:若已有 2 把
                                        有效密钥,最旧的一把同时被撤销);
                                        新密钥明文仅在此打印一次
  revoke-key   --key-id K               撤销指定密钥
  disable-identity --tenant T --identity I   禁用整个服务身份
  enable-identity  --tenant T --identity I   重新启用服务身份

所有变更在单个 BEGIN IMMEDIATE 事务内提交并写审计;提交返回后,
网关事务内的重新检查会立即看到新状态。
"""
from __future__ import annotations

import argparse
import secrets
import sys
import time

from .db import connect


def _find_identity(con, tenant: str, name: str) -> str:
    row = con.execute(
        "SELECT identity_id FROM identities WHERE tenant_id=? AND name=?",
        (tenant, name)).fetchone()
    if not row:
        raise SystemExit("identity not found: %s/%s" % (tenant, name))
    return row[0]


def _audit(con, key_id, result, detail):
    con.execute(
        "INSERT INTO audit(server_ts, tenant_id, identity_id, key_id,"
        " action, result, detail) VALUES(?,?,?,?,?,?,?)",
        (time.time(), None, None, key_id, "keymgr", result, detail))


def cmd_list(args) -> None:
    con = connect(args.db)
    try:
        print("IDENTITIES")
        for row in con.execute(
                "SELECT tenant_id, name, disabled FROM identities"
                " ORDER BY tenant_id, name"):
            print("  %-10s %-12s %s"
                  % (row[0], row[1], "DISABLED" if row[2] else "enabled"))
        print("KEYS")
        for row in con.execute(
                "SELECT k.key_id, i.tenant_id, i.name, k.revoked"
                " FROM keys k JOIN identities i ON i.identity_id = k.identity_id"
                " ORDER BY i.tenant_id, i.name, k.rowid"):
            print("  %-19s %-10s %-12s %s"
                  % (row[0], row[1], row[2], "REVOKED" if row[3] else "active"))
    finally:
        con.close()


def cmd_enable_key(args) -> None:
    con = connect(args.db)
    try:
        con.execute("BEGIN IMMEDIATE")
        identity_id = _find_identity(con, args.tenant, args.identity)
        active = [r[0] for r in con.execute(
            "SELECT key_id FROM keys WHERE identity_id=? AND revoked=0"
            " ORDER BY rowid", (identity_id,))]
        # 每个身份最多新旧两把有效密钥:超出时撤销最旧的
        if len(active) >= 2:
            for old_key in active[:-1]:
                con.execute("UPDATE keys SET revoked=1 WHERE key_id=?", (old_key,))
                _audit(con, old_key, "key_revoked", "rotated out by enable-key")
        key_id = "key_" + secrets.token_hex(8)
        secret = secrets.token_hex(32)
        con.execute(
            "INSERT INTO keys(key_id, identity_id, secret, revoked, created_at)"
            " VALUES(?,?,?,0,?)", (key_id, identity_id, secret, time.time()))
        _audit(con, key_id, "key_enabled", "identity=%s" % identity_id)
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()
    print("key_id=%s" % key_id)
    print("secret=%s" % secret)


def cmd_revoke_key(args) -> None:
    con = connect(args.db)
    try:
        con.execute("BEGIN IMMEDIATE")
        cur = con.execute("UPDATE keys SET revoked=1 WHERE key_id=? AND revoked=0",
                          (args.key_id,))
        if cur.rowcount == 0:
            con.execute("ROLLBACK")
            sys.exit("no active key found: %s" % args.key_id)
        _audit(con, args.key_id, "key_revoked", "revoked by keymgr")
        con.execute("COMMIT")
    finally:
        con.close()
    print("revoked: %s" % args.key_id)


def _set_disabled(args, disabled: int) -> None:
    con = connect(args.db)
    try:
        con.execute("BEGIN IMMEDIATE")
        identity_id = _find_identity(con, args.tenant, args.identity)
        con.execute("UPDATE identities SET disabled=? WHERE identity_id=?",
                    (disabled, identity_id))
        _audit(con, None,
               "identity_disabled" if disabled else "identity_enabled",
               "identity=%s" % identity_id)
        con.execute("COMMIT")
    finally:
        con.close()
    print("%s: %s/%s"
          % ("disabled" if disabled else "enabled", args.tenant, args.identity))


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="网关密钥/身份管理")
    ap.add_argument("--db", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list")

    p = sub.add_parser("enable-key")
    p.add_argument("--tenant", required=True)
    p.add_argument("--identity", required=True)

    p = sub.add_parser("revoke-key")
    p.add_argument("--key-id", required=True)

    p = sub.add_parser("disable-identity")
    p.add_argument("--tenant", required=True)
    p.add_argument("--identity", required=True)

    p = sub.add_parser("enable-identity")
    p.add_argument("--tenant", required=True)
    p.add_argument("--identity", required=True)

    args = ap.parse_args(argv)
    if args.cmd == "list":
        cmd_list(args)
    elif args.cmd == "enable-key":
        cmd_enable_key(args)
    elif args.cmd == "revoke-key":
        cmd_revoke_key(args)
    elif args.cmd == "disable-identity":
        _set_disabled(args, 1)
    elif args.cmd == "enable-identity":
        _set_disabled(args, 0)


if __name__ == "__main__":
    main()
