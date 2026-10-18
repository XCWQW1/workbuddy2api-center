# 独立日志查看器：轮询本地 wb_proxy 的 /logs，只输出到本进程自己的控制台窗口。
import sys
import time
import json
import urllib.request
import urllib.error

HOST = "127.0.0.1"
PORT = 8788
TOKEN = ""
REFRESH = 1.0
# 服务就绪前的连接失败静默等待，超过该时长仍连不上才退出。
STARTUP_GRACE = 30.0
# 连接成功后连续失败达到该次数，视为服务已关闭并退出。
FAIL_STREAK_EXIT = 3

# 本地回环请求不走代理：全局 HTTP_PROXY 或 HTTPS_PROXY 会把请求转给代理层，
# 服务退出时看到的将是代理返回的 502。
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _ensure_console_output():
    """把 stdout 与 stderr 绑到本进程自己的控制台窗口。

    服务进程可能以 pythonw 运行并被重定向标准句柄。新建控制台窗口会继承这些
    句柄，print 便写进文件而非窗口。CONOUT$ 指向当前进程附加的控制台缓冲区，
    显式重开 stdout 即可。stdout 已是 tty 时保持原样，保留管道调试能力。
    """
    try:
        if sys.stdout is not None and sys.stdout.isatty():
            return
    except Exception:
        pass
    try:
        import ctypes
        if not ctypes.windll.kernel32.GetConsoleWindow():
            return
        sys.stdout = open("CONOUT$", "w", buffering=1, encoding="utf-8", errors="replace")
        sys.stderr = open("CONOUT$", "w", buffering=1, encoding="utf-8", errors="replace")
    except Exception:
        pass


def parse_args(argv):
    global HOST, PORT, TOKEN
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--port" and i + 1 < len(argv):
            try:
                PORT = int(argv[i + 1])
            except ValueError:
                pass
            i += 2
        elif a == "--host" and i + 1 < len(argv):
            HOST = argv[i + 1]
            i += 2
        elif a == "--token" and i + 1 < len(argv):
            TOKEN = argv[i + 1]
            i += 2
        else:
            i += 1


def _url(path):
    return "http://%s:%d%s" % (HOST, PORT, path)


def login():
    global TOKEN
    data = json.dumps({"password": "admin"}).encode("utf-8")
    req = urllib.request.Request(
        _url("/panel/login"),
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with _OPENER.open(req, timeout=5) as r:
        body = json.loads(r.read().decode("utf-8"))
    TOKEN = body.get("token", "")
    return bool(TOKEN)


def fetch_logs(since_id):
    headers = {}
    if TOKEN:
        headers["X-Panel-Token"] = TOKEN
    req = urllib.request.Request(
        _url("/logs?since_id=%d&limit=300" % since_id), headers=headers)
    with _OPENER.open(req, timeout=5) as r:
        return json.loads(r.read().decode("utf-8"))


def fmt(entry):
    t = entry.get("time", "")
    lvl = entry.get("level", "")
    tag = entry.get("tag", "")
    msg = entry.get("msg", "")
    if tag and tag != "system":
        return "%s [%s/%s] %s" % (t, lvl, tag, msg)
    return "%s [%s] %s" % (t, lvl, msg)


def main():
    _ensure_console_output()
    parse_args(sys.argv)
    print("=" * 60, flush=True)
    print("  WorkBuddy proxy - live console (port %d)" % PORT)
    print("  关闭本窗口【不会】停止服务，仅关闭日志查看。")
    print("  按 Ctrl+C 仅关闭本查看器。")
    print("=" * 60)
    if not TOKEN:
        try:
            login()
            print("[viewer] logged in")
        except Exception:
            print("[viewer] 等待面板登录（默认密码 admin）...")
    since = 0
    fail_streak = 0
    ever_ok = False
    started = time.time()
    while True:
        try:
            d = fetch_logs(since)
            ever_ok = True
            fail_streak = 0
            for e in d.get("logs", []):
                since = max(since, e.get("id", since))
                print(fmt(e))
        except urllib.error.HTTPError as e:
            if e.code == 401:
                # token 失效或尚未登录时重新登录。
                try:
                    login()
                    fail_streak = 0
                except Exception:
                    fail_streak += 1
            else:
                fail_streak += 1
        except Exception:
            # 连接被拒或超时只计数，不打印，避免刷屏。
            fail_streak += 1
        if fail_streak >= FAIL_STREAK_EXIT:
            if ever_ok:
                print("[viewer] 服务已关闭，查看器退出。")
                print("[viewer] 本窗口将在 2 秒后自动关闭")
                time.sleep(2)
                return
            if time.time() - started > STARTUP_GRACE:
                if TOKEN:
                    print("[viewer] 无法连接服务（30 秒无响应），查看器退出。")
                else:
                    print("[viewer] 面板登录失败：请确认面板密码，或从面板"
                          "「眼睛」按钮打开查看器。")
                time.sleep(2)
                return
            # 服务尚未就绪：静默等待，不打印错误。
        time.sleep(REFRESH)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        # 崩溃时让错误留在窗口里可见。
        try:
            print("[viewer] fatal error: %s" % e, flush=True)
            print("[viewer] 本窗口将在 15 秒后关闭", flush=True)
            time.sleep(15)
        except Exception:
            pass
