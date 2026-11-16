"""启动 N 个独立网关进程,共享同一 SQLite 数据库。Ctrl+C 全部停止。

用法:
  python run_gateways.py --db gateway.db --count 4 --base-port 8401
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--count", type=int, default=4)
    ap.add_argument("--base-port", type=int, default=8401)
    args = ap.parse_args()

    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    procs = []
    for i in range(args.count):
        port = args.base_port + i
        p = subprocess.Popen(
            [sys.executable, "-m", "gateway.server",
             "--port", str(port), "--db", args.db],
            cwd=ROOT, env=env)
        procs.append(p)
        print("gateway #%d pid=%d port=%d" % (i, p.pid, port))
    print("press Ctrl+C to stop all")
    try:
        while True:
            time.sleep(0.5)
            for p in procs:
                if p.poll() is not None:
                    print("gateway pid=%d exited with %s" % (p.pid, p.returncode))
                    raise KeyboardInterrupt
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    main()
