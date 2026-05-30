"""Fixture: hardened Python module (no findings expected)."""
import json
import subprocess
import yaml
from flask import Flask, request

app = Flask(__name__)

ALLOWED = {"a.txt", "b.txt"}


@app.route("/load")
def load():
    data = json.loads(request.data)                       # safe parser
    cfg = yaml.safe_load(request.data)                    # safe loader
    return str(data) + str(cfg)


@app.route("/run")
def run():
    subprocess.run(["ls", "-l", request.args["dir"]])     # arg list, no shell
    return "ok"


@app.route("/read")
def read():
    name = request.args["name"]
    if name not in ALLOWED:
        return "forbidden", 403
    return open("data/" + name).read()                    # allowlisted, not request.*


CORS_CONFIG = dict(allow_origins=["https://app.example.com"])
DEBUG = False

if __name__ == "__main__":
    app.run(debug=False)
