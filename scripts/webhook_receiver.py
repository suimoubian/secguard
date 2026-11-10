#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""告警通知的本地接收端(演示/调试用)

用途:验证 SECGUARD_ALERT_WEBHOOK 真的会把告警推出去,并看清载荷长什么样。

用法:
    python3 scripts/webhook_receiver.py 9099

然后把服务指向它:
    export SECGUARD_ALERT_WEBHOOK=http://127.0.0.1:9099/hook
    export SECGUARD_ALERT_MIN_SEVERITY=HIGH

真实环境里不该用这个 —— 应该接钉钉/Slack/飞书/自建的告警平台。
它们要的格式各不相同,所以这里推的是**通用 JSON**,
中间加一个转发器转换即可。
"""

import json
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""

        ts = datetime.now().strftime("%H:%M:%S")
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            print(f"[{ts}] 收到非 JSON 载荷({n} 字节): {raw[:200]!r}")
            self.send_response(400)
            self.end_headers()
            return

        # 把最关键的几项打出来,别把整个 JSON 刷一屏
        print(f"[{ts}] 收到告警 #{data.get('alert_id')}", flush=True)
        print(f"        事件    : {data.get('event')}", flush=True)
        print(f"        来源 IP : {data.get('ip')}", flush=True)
        print(f"        威胁类型: {data.get('threat_type')}", flush=True)
        print(f"        严重级别: {data.get('severity')}   置信度: {data.get('confidence')}",
              flush=True)
        print(f"        关联日志: {data.get('log_ids')}", flush=True)
        reason = (data.get("reasoning") or "").replace("\n", " ")
        print(f"        理由    : {reason[:120]}", flush=True)
        print(flush=True)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *args):
        pass   # 关掉默认的访问日志,只留我们自己的输出


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9099
    # flush=True 是必须的:输出重定向到文件时 Python 会缓冲,
    # 进程被 kill 时缓冲区里的内容就丢了 —— 看起来像"一条都没收到"。
    print(f"告警接收端已启动: http://127.0.0.1:{port}/hook", flush=True)
    print("把服务指向它:  export SECGUARD_ALERT_WEBHOOK=http://127.0.0.1:%d/hook" % port,
          flush=True)
    print("按 Ctrl+C 停止\n", flush=True)
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
