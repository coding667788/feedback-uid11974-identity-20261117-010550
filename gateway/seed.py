"""预置数据:初始化 schema 并写入预置租户、服务身份和首把密钥。

预置内容(无注册接口,身份只能由本工具/ keymgr 管理):
  租户 tenant-a:服务身份 svc-report、svc-ingest
  租户 tenant-b:服务身份 svc-report   (与 tenant-a 同名,验证跨租户隔离)

每个身份生成一把初始密钥,密钥明文只在此处打印一次,请妥善保存。
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys
import time

from .db import connect, init_db, remove_db

TENANTS = [("tenant-a", "Tenant A"), ("tenant-b", "Tenant B")]
IDENTITIES = [("tenant-a", "svc-report"),
              ("tenant-a", "svc-ingest"),
              ("tenant-b", "svc-report")]


def seed(db_path: str):
    init_db(db_path)
    con = connect(db_path)
    issued = []
    try:
        con.execute("BEGIN IMMEDIATE")
        for tenant_id, name in TENANTS:
            con.execute("INSERT INTO tenants(tenant_id, name) VALUES(?,?)",
                        (tenant_id, name))
        for tenant_id, iname in IDENTITIES:
            identity_id = "%s:%s" % (tenant_id, iname)
            con.execute(
                "INSERT INTO identities(identity_id, tenant_id, name, disabled)"
                " VALUES(?,?,?,0)",
                (identity_id, tenant_id, iname))
            key_id = "key_" + secrets.token_hex(8)
            secret = secrets.token_hex(32)
            con.execute(
                "INSERT INTO keys(key_id, identity_id, secret, revoked, created_at)"
                " VALUES(?,?,?,0,?)",
                (key_id, identity_id, secret, time.time()))
            issued.append((tenant_id, iname, key_id, secret))
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()
    return issued


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="初始化网关数据库并预置身份/密钥")
    ap.add_argument("--db", required=True)
    ap.add_argument("--force", action="store_true", help="删除已存在的数据库后重建")
    args = ap.parse_args(argv)

    if os.path.exists(args.db):
        if not args.force:
            sys.exit("database already exists: %s (use --force to rebuild)" % args.db)
        remove_db(args.db)

    issued = seed(args.db)
    print("seeded db: %s" % args.db)
    print("tenant     identity    key_id              secret")
    for tenant_id, iname, key_id, secret in issued:
        print("%-11s %-11s %-19s %s" % (tenant_id, iname, key_id, secret))


if __name__ == "__main__":
    main()
