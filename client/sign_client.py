"""独立签名客户端:不依赖网关代码,可单独分发。

签名协议(与 gateway/protocol.py 一致,此处独立实现):
  签名输入 = METHOD "\\n" 原始request-target "\\n" 十进制timestamp "\\n"
             nonce "\\n" body_sha256        (ASCII 字节串)
  签名值   = HMAC-SHA256(secret 的 ASCII 字节, 签名输入) 的小写十六进制

用法示例:
  python -m client.sign_client --url http://127.0.0.1:8401/v1/counter/increment \
      --method POST --key-id key_xxx --secret <hex> --body "{}"
  python -m client.sign_client --url "http://127.0.0.1:8401/v1/counter?raw=a%20b&x=1" \
      --method GET --key-id key_xxx --secret <hex>
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import secrets
import sys
import time
from urllib.parse import urlsplit


def canonical_request(method: str, target: str, timestamp: str,
                      nonce: str, body_sha256: str) -> bytes:
    return (method + "\n" + target + "\n" + timestamp + "\n"
            + nonce + "\n" + body_sha256).encode("ascii")


def sign(secret: str, method: str, target: str, timestamp: str,
         nonce: str, body_sha256: str) -> str:
    return hmac.new(secret.encode("ascii"),
                    canonical_request(method, target, timestamp, nonce,
                                      body_sha256),
                    hashlib.sha256).hexdigest()


def build_headers(key_id: str, secret: str, method: str, target: str,
                  body: bytes, timestamp: str | None = None,
                  nonce: str | None = None) -> dict:
    ts = timestamp if timestamp is not None else str(int(time.time()))
    nc = nonce if nonce is not None else secrets.token_hex(16)  # 128 bit
    body_sha = hashlib.sha256(body).hexdigest()
    return {
        "X-Key-Id": key_id,
        "X-Timestamp": ts,
        "X-Nonce": nc,
        "X-Body-Sha256": body_sha,
        "X-Signature": sign(secret, method.upper(), target, ts, nc, body_sha),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="HMAC-SHA256 签名客户端")
    ap.add_argument("--url", required=True,
                    help="完整 URL;查询串原样参与签名,不会被重编码")
    ap.add_argument("--method", default="POST", choices=["GET", "POST"])
    ap.add_argument("--key-id", required=True)
    ap.add_argument("--secret", required=True)
    ap.add_argument("--body", default="", help="请求体字符串(默认空)")
    ap.add_argument("--body-file", help="从文件读取请求体(二进制)")
    ap.add_argument("--timestamp", help="覆盖签名时间戳(十进制秒)")
    ap.add_argument("--nonce", help="覆盖 nonce(小写十六进制,>=32 字符)")
    args = ap.parse_args(argv)

    parts = urlsplit(args.url)
    # request-target = 原始路径 + 原始查询串,不解码、不重排
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query

    if args.body_file:
        with open(args.body_file, "rb") as f:
            body = f.read()
    else:
        body = args.body.encode("utf-8")

    headers = build_headers(args.key_id, args.secret, args.method, target,
                            body, args.timestamp, args.nonce)
    conn = http.client.HTTPConnection(parts.hostname, parts.port or 80,
                                      timeout=15)
    conn.request(args.method.upper(), target, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    print("HTTP %d %s" % (resp.status, resp.reason))
    sys.stdout.write(data.decode("utf-8", "replace") + "\n")
    return 0 if resp.status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
