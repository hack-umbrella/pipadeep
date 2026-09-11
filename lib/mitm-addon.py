# @pipadeep/dsh-pentest — mitmproxy 证据索引 addon
#
# 作用：把携带 `X-Pentest-Evidence: <runId>` 标记头的请求，按 runId 落到 JSONL
# 索引里（方法/URL/状态码/耗时/请求头/请求体/响应头/响应体预览），供截图工具
# 精确取回「这次截图对应的原始请求/响应」，形成 截图 + 原始包 的证据链。
#
# 环境变量：
#   PENTEST_SHOT_INDEX      索引文件路径（默认 ./evidence-index.jsonl）
#   PENTEST_SHOT_BODY_LIMIT 请求/响应体预览上限（默认 6000 字符）
#   PENTEST_SHOT_RAWDIR     可选：每条命中的完整 request/response 落盘目录
#
# 运行（由 pentest_shot 工具自动拉起，也可手工）：
#   mitmdump -p 8081 --mode upstream:http://127.0.0.1:8080 --set ssl_insecure=true \
#     -s mitm-addon.py -w flows.mitm --set hardump=flows.har
import json
import os
import time

INDEX = os.environ.get("PENTEST_SHOT_INDEX", "evidence-index.jsonl")
BODY_LIMIT = int(os.environ.get("PENTEST_SHOT_BODY_LIMIT", "6000"))
RAWDIR = os.environ.get("PENTEST_SHOT_RAWDIR", "")
EVIDENCE_HEADER = "x-pentest-evidence"


def _clip(value, limit=BODY_LIMIT):
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "\n…(truncated, %d bytes total)" % len(text)


def _header(flow):
    for key, value in flow.request.headers.items():
        if key.lower() == EVIDENCE_HEADER:
            return value
    return None


def response(flow):
    try:
        evid = _header(flow)
        if not evid:
            return
        resp = flow.response
        rec = {
            "evid": evid,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.pretty_host,
            "status": resp.status_code if resp else None,
            "ts": time.time(),
            "durationMs": int((resp.timestamp_end - flow.request.timestamp_start) * 1000) if resp else None,
            "clientIp": flow.client_conn.peername[0] if flow.client_conn and flow.client_conn.peername else None,
            "reqHeaders": dict(flow.request.headers),
            "reqBody": _clip(flow.request.get_text(strict=False)),
            "respHeaders": dict(resp.headers) if resp else {},
            "respBody": _clip(resp.get_text(strict=False)) if resp else "",
            "contentType": (resp.headers.get("content-type", "") if resp else ""),
        }
        with open(INDEX, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if RAWDIR:
            try:
                os.makedirs(RAWDIR, exist_ok=True)
                target = os.path.join(RAWDIR, "%s-%s.http" % (str(rec["ts"]).replace(".", ""), flow.request.method))
                with open(target, "a", encoding="utf-8") as handle:
                    handle.write("=== REQUEST ===\n%s %s\n" % (flow.request.method, flow.request.pretty_url))
                    for key, value in flow.request.headers.items():
                        handle.write("%s: %s\n" % (key, value))
                    handle.write("\n" + _clip(flow.request.get_text(strict=False), 200000) + "\n")
                    handle.write("\n=== RESPONSE %s ===\n" % (rec["status"]))
                    if resp:
                        for key, value in resp.headers.items():
                            handle.write("%s: %s\n" % (key, value))
                        handle.write("\n" + _clip(resp.get_text(strict=False), 200000) + "\n")
                    handle.write("\n")
            except Exception:
                pass
    except Exception:
        # 证据索引失败绝不能影响代理转发
        pass
