# -*- coding: utf-8 -*-
"""wb_identity.py - 出站身分 (WorkBuddy 桌面端 / 官方 VSCode 插件 / 官方 CodeBuddy CLI)

支援三套出站身分:
  1. WorkBuddy 独立桌面客户端 (workbuddy / desktop / wb):
     - X-IDE-Type / X-IDE-Name: WorkBuddy
     - X-Product: SaaS
     - X-Agent-Intent: craft、X-Agent-Purpose: conversation、X-Agent-Type: main
     - 国际版端点: www.workbuddy.ai
       实测 5.8.4（2026-10-16 mitmproxy 抓包，账号 uid 已脱敏）:
         X-IDE-Version: 5.8.4
         User-Agent: WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0
     - 国内版端点: www.workbuddy.cn
       实测 5.8.3（WorkBuddy-win32-x64-user-5.8.3.41334564 安装包）:
         X-IDE-Version: 5.8.3
         User-Agent: WorkBuddy/5.8.3 WorkBuddy/5.8.3 CLI/2.161.0

  2. 官方 VSCode 插件 (vscode / vsc):
     - X-IDE-Type / X-IDE-Name: VSCode
     - X-Product: SaaS
     - X-IDE-Version: 宿主 VS Code 的 vscode.version
     - X-Product-Version: 插件 package.json 的 version
     - UA: VSCode/<vscode.version> CodeBuddy/<plugin.version>
       依据 CodeBuddy 4.12.39997873 的 buildUserAgent：先写
       platform/platformVersion，再写 productName/productVersion。
       宿主 product.json 的 applicationName 为 workbuddy 时，插件把次段写成
       WorkBuddy；本渠道按公开插件在标准 VS Code 里的取值。
     - 国际版端点: www.workbuddy.ai，国内版端点: www.workbuddy.cn

  3. 官方 CodeBuddy CLI (cli):
     - X-IDE-Type / X-IDE-Name: CLI
     - X-Product: SaaS
     - UA: CLI/<ver> CodeBuddy/<ver>
     - 国际版端点: www.workbuddy.ai，国内版端点: www.workbuddy.cn
     （版本号取 5.8.4 内置 CLI 的 2.161.0）

三套身分都带官方客户端的会话头族（X-Conversation-ID / -Request-ID /
-Message-ID / -Root-Request-ID）：缺了它会触发上游的渠道校验，回 400 /
code 11-128（`conversation id missing`）。官方 5.8.3 用 crypto.randomUUID()
（UUIDv4）生成会话与请求 id：会话 id 带连字符，请求/消息 id 去掉连字符。
"""

import base64
import json
import secrets
import uuid

# 5.8.4 实测（国际版桌面客户端抓包）: 对话请求的版本号与 UA。
# UA 末段 CLI/2.161.0 是客户端内置 CLI 的版本，不是桌面端自己的版本。
DESKTOP_VERSION_INTL = "5.8.4"
# 对话请求由客户端内置 CLI 子进程发出，该进程带 CLIENT_INFO_IDE_TYPE=WorkBuddy
# （sidecar-manager.js 硬编码），buildUserAgent 里 platform 段取它、application
# 段取 product.json 的 applicationName（国际版为 workbuddy-ai），所以首段是大写
# WorkBuddy、次段是小写 workbuddy-ai。
# 注意 Electron 主进程自己发的旁路请求（msg-center / conversations）UA 是
# workbuddy-ai/... workbuddy-ai/...，两者不是同一条链路，别照抄错。
DESKTOP_UA_INTL = "WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0"
# 国内版 5.8.3（WorkBuddy-win32-x64-user-5.8.3.41334564）实测: product.json 的
# productName 与 applicationName 都是 WorkBuddy，sidecar 把 CLIENT_INFO_PLATFORM
# 固定成 WorkBuddy，UA 首两段因此同名；内置 CLI 2.161.0 由 cli/package.json 的
# publishConfig.customPackage.version 给出。
DESKTOP_VERSION_CN = "5.8.3"
DESKTOP_UA_CN = "WorkBuddy/5.8.3 WorkBuddy/5.8.3 CLI/2.161.0"

DEFAULT_IDE_VERSION = "2.161.0"
# CodeBuddy 插件在标准 VS Code 宿主里的身分：X-IDE-Version 取 vscode.version，
# X-Product-Version 与 UA 次段取插件 package.json 的 version。
DEFAULT_VSCODE_VERSION = "1.142.0"
DEFAULT_VSCODE_PLUGIN_VERSION = "4.12.39997873"

PRODUCT_DESKTOP = "workbuddy"
PRODUCT_VSCODE = "vscode"
PRODUCT_CLI = "cli"
VALID_PRODUCTS = (PRODUCT_DESKTOP, PRODUCT_VSCODE, PRODUCT_CLI)


def normalize_product(value):
    """把各种写法收敛成 'workbuddy'、'vscode' 或 'cli'。"""
    v = str(value or "").strip().lower()
    if v in ("workbuddy", "wb", "desktop"):
        return PRODUCT_DESKTOP
    if v in ("vscode", "vsc", "ide"):
        return PRODUCT_VSCODE
    if v in ("cli", "codebuddy"):
        return PRODUCT_CLI
    return PRODUCT_DESKTOP


_ENDPOINTS = {
    ("intl", PRODUCT_DESKTOP): ("https://www.workbuddy.ai", "www.workbuddy.ai"),
    ("intl", PRODUCT_VSCODE): ("https://www.workbuddy.ai", "www.workbuddy.ai"),
    # www.codebuddy.ai does not resolve on the networks this was measured on
    # (getaddrinfo fails; the system resolver hands back the 0.0.0.1 sinkhole),
    # so the international CLI identity rides the workbuddy.ai edge, which
    # accepts CLI headers and answers normally.
    ("intl", PRODUCT_CLI): ("https://www.workbuddy.ai", "www.workbuddy.ai"),
    ("cn", PRODUCT_DESKTOP): ("https://www.workbuddy.cn", "www.workbuddy.cn"),
    ("cn", PRODUCT_VSCODE): ("https://www.workbuddy.cn", "www.workbuddy.cn"),
    ("cn", PRODUCT_CLI): ("https://www.workbuddy.cn", "www.workbuddy.cn"),
}


def endpoint_for(realm, product):
    """回传 (chat base URL, X-Domain)。身分换了，端点也要跟着换。"""
    key = ("cn" if realm == "cn" else "intl", normalize_product(product))
    return _ENDPOINTS[key]


def domain_for_realm(realm):
    """X-Domain 的值（预设桌面端）。"""
    return endpoint_for(realm, PRODUCT_DESKTOP)[1]


def new_conversation_id():
    """X-Conversation-ID：带连字符的 UUIDv4。"""
    return str(uuid.uuid4())


def new_message_id():
    """X-Request-ID / X-Conversation-Message-ID / -Request-ID / -Root-Request-ID：
    32 位无连字符 hex（UUIDv4 去掉连字符）。"""
    return uuid.uuid4().hex


def trace_headers():
    """5.8.4 对话请求带的链路头族（traceparent / b3 / X-B3-* / X-Trace-ID）。

    main 请求还带 X-B3-ParentSpanId，那需要真实的父子调用关系，网关没有，
    就不伪造了（辅助请求本来也不带）。
    """
    trace = new_message_id()
    span = secrets.token_hex(8)
    return {
        "X-Trace-ID": trace,
        "traceparent": "00-%s-%s-01" % (trace, span),
        "b3": "%s-%s-1" % (trace, span),
        "X-B3-TraceId": trace,
        "X-B3-SpanId": span,
        "X-B3-Sampled": "1",
    }


def build_identity_headers(product, realm, uid, token,
                           conversation_id=None, enterprise_id="",
                           tenant_id="", department="", domain=""):
    """回传这一轮要用的身分标头。product = 'workbuddy' (桌面端), 'vscode' 或 'cli'。

    conversation_id 只用于显式指定：留空（网关的常态）就每次请求新生成一个
    UUIDv4。上游不拿这个 id 存历史——抓包后的实测里，同一 id 连发两轮、第二轮
    只带 system+user，模型仍答不出上一轮；换个新 id 结果一样。所以网关不需要
    在会话维度上维护映射。
    """
    product = normalize_product(product)
    is_cn = (realm == "cn")

    conv = str(conversation_id or "").strip() or new_conversation_id()
    msg_id = new_message_id()
    # main 请求里 X-Conversation-Request-ID 与 X-Root-Request-ID 是同一个值，
    # 且早于消息 id —— 一次 user send 开始时生成、该轮所有请求复用。
    conv_req_id = new_message_id()

    if product == PRODUCT_DESKTOP:
        client_ver = DESKTOP_VERSION_CN if is_cn else DESKTOP_VERSION_INTL
        chat_ua = DESKTOP_UA_CN if is_cn else DESKTOP_UA_INTL
        headers = {
            "X-Agent-Intent": "craft",
            "X-Agent-Purpose": "conversation",
            "X-Agent-Type": "main",
            "X-IDE-Name": "WorkBuddy",
            "X-IDE-Type": "WorkBuddy",
            "X-IDE-Version": client_ver,
            "X-Private-Data": "true",
            "X-Product": "SaaS",
            "X-Domain": str(domain or endpoint_for(realm, product)[1]),
            "User-Agent": chat_ua,
            "X-User-Id": str(uid or "anonymous"),
            "Authorization": "Bearer " + str(token or ""),
            "X-Conversation-ID": conv,
            "X-Conversation-Request-ID": conv_req_id,
            "X-Root-Request-ID": conv_req_id,
            "X-Conversation-Message-ID": msg_id,
            "X-Request-ID": msg_id,
        }
        headers.update(trace_headers())
    elif product == PRODUCT_VSCODE:
        headers = {
            "X-Agent-Intent": "craft",
            "X-IDE-Type": "VSCode",
            "X-IDE-Name": "VSCode",
            "X-IDE-Version": DEFAULT_VSCODE_VERSION,
            "X-Product-Version": DEFAULT_VSCODE_PLUGIN_VERSION,
            "X-Env-ID": "production",
            "X-Product": "SaaS",
            "X-Domain": str(domain or endpoint_for(realm, product)[1]),
            "User-Agent": "VSCode/%s CodeBuddy/%s" % (
                DEFAULT_VSCODE_VERSION, DEFAULT_VSCODE_PLUGIN_VERSION),
            "X-User-Id": str(uid or "anonymous"),
            "Authorization": "Bearer " + str(token or ""),
            "X-Conversation-ID": conv,
            "X-Conversation-Request-ID": conv_req_id,
            "X-Root-Request-ID": conv_req_id,
            "X-Conversation-Message-ID": msg_id,
            "X-Request-ID": msg_id,
        }
    else:  # PRODUCT_CLI
        ide_version = DEFAULT_IDE_VERSION
        headers = {
            "X-Agent-Intent": "craft",
            "X-IDE-Type": "CLI",
            "X-IDE-Name": "CLI",
            "X-IDE-Version": ide_version,
            "X-Product": "SaaS",
            "X-Domain": str(domain or endpoint_for(realm, product)[1]),
            "User-Agent": "CLI/%s CodeBuddy/%s" % (ide_version, ide_version),
            "X-User-Id": str(uid or "anonymous"),
            "Authorization": "Bearer " + str(token or ""),
            "X-Conversation-ID": conv,
            "X-Conversation-Request-ID": conv_req_id,
            "X-Root-Request-ID": conv_req_id,
            "X-Conversation-Message-ID": msg_id,
            "X-Request-ID": msg_id,
        }

    if enterprise_id:
        headers["X-Enterprise-Id"] = str(enterprise_id)
        headers["X-Tenant-Id"] = str(tenant_id or enterprise_id)
        userinfo = {"uin": str(uid or ""), "owner_uin": str(enterprise_id)}
        headers["X-Userinfo"] = base64.b64encode(
            json.dumps(userinfo, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
    if department:
        headers["X-Department-Info"] = str(department)
    headers.setdefault("Accept", "application/json")
    headers.setdefault("Content-Type", "application/json")

    return headers
