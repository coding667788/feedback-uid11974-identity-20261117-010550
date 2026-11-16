"""签名协议定义与协议级校验。

签名算法:HMAC-SHA256
签名输入(ASCII 字节串,共 5 行,每行以换行分隔,末尾无换行)::

    METHOD "\\n" request-target "\\n" timestamp "\\n" nonce "\\n" body_sha256

- METHOD          固定大写(GET / POST)。
- request-target  原始路径 + 查询串(origin-form),不解码、不排序、不重新编码;
                  只能是不含空白/控制字符的 ASCII,必须以 '/' 开头。
- timestamp       客户端签名时刻的十进制 Unix 秒,规范形式(无前导零、无符号、无空白)。
- nonce           32~128 个字符的小写十六进制(>=128 bit 随机)。
- body_sha256     实际收到请求体的 SHA256,小写十六进制,64 字符;空 body 即空串的哈希。

签名值 = HMAC-SHA256(key=secret 的 ASCII 字节, msg=上述字节串) 的小写十六进制。

五个认证头均为唯一必填:X-Key-Id / X-Timestamp / X-Nonce / X-Body-Sha256 / X-Signature。
重复头、非规范数字、超长或非法字段一律拒绝(ProtocolError),且不消耗 nonce。
"""
from __future__ import annotations

import hashlib
import hmac
import re

MAX_BODY_BYTES = 1 << 20          # 请求体上限 1 MiB
SKEW_SECONDS = 60                 # timestamp 允许前后 60 秒
MAX_TARGET_LEN = 2048             # request-target 长度上限
MAX_TIMESTAMP_LEN = 12            # 十进制 timestamp 长度上限
MAX_KEY_ID_LEN = 64

H_KEY_ID = "X-Key-Id"
H_TIMESTAMP = "X-Timestamp"
H_NONCE = "X-Nonce"
H_BODY_SHA256 = "X-Body-Sha256"
H_SIGNATURE = "X-Signature"
AUTH_HEADERS = (H_KEY_ID, H_TIMESTAMP, H_NONCE, H_BODY_SHA256, H_SIGNATURE)

_RE_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_RE_NONCE = re.compile(r"[0-9a-f]{32,128}\Z")
_RE_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class ProtocolError(ValueError):
    """协议级校验失败(格式非法)。服务器对此类请求不得消耗 nonce。"""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ProtocolError(msg)


def validate_request_target(target: str) -> str:
    _require(isinstance(target, str) and 1 <= len(target) <= MAX_TARGET_LEN,
             "request-target missing or too long")
    _require(target.startswith("/"),
             "request-target must be origin-form starting with '/'")
    for ch in target:
        o = ord(ch)
        _require(0x21 <= o <= 0x7E,
                 "request-target must be non-whitespace printable ASCII")
    return target


def validate_key_id(value: str) -> str:
    _require(bool(_RE_KEY_ID.match(value or "")), "X-Key-Id invalid")
    return value


def validate_timestamp(value: str) -> int:
    """十进制秒,规范形式:仅 ASCII 数字、无前导零、长度受限。"""
    _require(bool(value) and value.isascii() and value.isdigit()
             and len(value) <= MAX_TIMESTAMP_LEN,
             "X-Timestamp must be a decimal integer")
    _require(value == str(int(value)),
             "X-Timestamp not canonical (leading zeros)")
    return int(value)


def validate_nonce(value: str) -> str:
    """小写十六进制,32~128 字符(最少 128 bit)。"""
    _require(bool(_RE_NONCE.match(value or "")),
             "X-Nonce must be 32..128 lowercase hex chars (>=128 bit)")
    return value


def validate_hex64(value: str, name: str) -> str:
    _require(bool(_RE_HEX64.match(value or "")),
             "%s must be 64 lowercase hex chars" % name)
    return value


def body_sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_request(method: str, target: str, timestamp: str,
                      nonce: str, body_sha256: str) -> bytes:
    return (method + "\n" + target + "\n" + timestamp + "\n"
            + nonce + "\n" + body_sha256).encode("ascii")


def sign(secret: str, method: str, target: str, timestamp: str,
         nonce: str, body_sha256: str) -> str:
    return hmac.new(secret.encode("ascii"),
                    canonical_request(method, target, timestamp, nonce, body_sha256),
                    hashlib.sha256).hexdigest()


def timestamp_in_window(req_ts: int, now: float) -> bool:
    """|服务器接收时刻 - 签名时刻| <= 60 秒(边界含等号)。"""
    return -SKEW_SECONDS <= (now - req_ts) <= SKEW_SECONDS
