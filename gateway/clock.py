"""可注入时钟:偏移量来自环境变量 GATEWAY_CLOCK_OFFSET(秒),保证非递减。

即使注入的偏移为负、或系统时钟回拨,now() 返回值也绝不小于上一次返回值。
"""
from __future__ import annotations

import os
import threading
import time


class Clock:
    def __init__(self, offset: float | None = None):
        if offset is None:
            offset = float(os.environ.get("GATEWAY_CLOCK_OFFSET", "0") or 0)
        self._offset = float(offset)
        self._lock = threading.Lock()
        self._last = 0.0

    def now(self) -> float:
        with self._lock:
            t = time.time() + self._offset
            if t < self._last:
                t = self._last
            else:
                self._last = t
            return t
