"""SQLite 数据层:schema、连接工厂。

多进程共享同一数据库文件;WAL 模式 + busy_timeout。
所有"检查密钥/身份状态 + 占用 nonce + 业务写入 + 审计"都在
BEGIN IMMEDIATE ... COMMIT 的单个事务内完成(见 server.py)。
"""
from __future__ import annotations

import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
  tenant_id   TEXT PRIMARY KEY,
  name        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS identities (
  identity_id TEXT PRIMARY KEY,              -- 形如 "<tenant_id>:<name>"
  tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id),
  name        TEXT NOT NULL,
  disabled    INTEGER NOT NULL DEFAULT 0,
  UNIQUE (tenant_id, name)
);
CREATE TABLE IF NOT EXISTS keys (
  key_id      TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL REFERENCES identities(identity_id),
  secret      TEXT NOT NULL,                 -- 本地网关,明文存储(见 README 限制说明)
  revoked     INTEGER NOT NULL DEFAULT 0,
  created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces (
  tenant_id   TEXT NOT NULL,
  identity_id TEXT NOT NULL,
  nonce       TEXT NOT NULL,
  req_ts      INTEGER NOT NULL,              -- 签名时刻(客户端 timestamp)
  PRIMARY KEY (tenant_id, identity_id, nonce)  -- 唯一性范围:(租户, 服务身份)
);
CREATE TABLE IF NOT EXISTS counters (
  identity_id TEXT PRIMARY KEY,
  value       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  server_ts   REAL NOT NULL,
  tenant_id   TEXT,
  identity_id TEXT,
  key_id      TEXT,
  action      TEXT NOT NULL,                 -- increment / query / keymgr
  result      TEXT NOT NULL,                 -- ok / invalid_signature / replay / ...
  detail      TEXT NOT NULL DEFAULT ''
);
"""


def connect(db_path: str) -> sqlite3.Connection:
    """autocommit(isolation_level=None);显式 BEGIN IMMEDIATE 由调用方控制。"""
    con = sqlite3.connect(db_path, timeout=15.0, isolation_level=None)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=15000")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db(db_path: str) -> None:
    con = connect(db_path)
    try:
        con.executescript(SCHEMA)
    finally:
        con.close()


def remove_db(db_path: str) -> None:
    for suffix in ("", "-wal", "-shm"):
        p = db_path + suffix
        if os.path.exists(p):
            os.remove(p)
