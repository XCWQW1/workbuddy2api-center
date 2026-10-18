import atexit
import os
import tempfile


def isolated_data_dirs(prefix):
    """返回独立的 ACCOUNTS_DIR 与 WB_PROXY_USAGE_DIR，进程退出时删除。

    两个环境变量直接赋值，不用 `setdefault`：环境里已有的值属于启动本进程的
    程序，继承它会让多个套件共用同一个目录。
    """
    tmp = tempfile.TemporaryDirectory(prefix=prefix)
    atexit.register(tmp.cleanup)
    accounts = os.path.join(tmp.name, "accounts")
    usage = os.path.join(tmp.name, "usage")
    os.makedirs(accounts, exist_ok=True)
    os.makedirs(usage, exist_ok=True)
    os.environ["ACCOUNTS_DIR"] = accounts
    os.environ["WB_PROXY_USAGE_DIR"] = usage
    return tmp
