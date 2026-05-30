"""Fixture: insecure Python module (multiple findings for py-005..py-010)."""
import os
import pickle
import subprocess
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/load")
def load():
    data = pickle.loads(request.data)          # py-005: unsafe deserialization
    cfg = yaml.load(request.data)              # py-005: unsafe yaml.load
    return str(data) + str(cfg)


@app.route("/run")
def run():
    subprocess.run(request.args["cmd"], shell=True)   # py-006: command injection
    os.system(request.args["cmd"])                    # py-006: os.system
    result = eval(request.args["expr"])               # py-007: eval
    return str(result)


@app.route("/read")
def read():
    return open(request.args["path"]).read()   # py-010: path traversal


# py-009: permissive CORS (FastAPI-style config) + py-008: debug mode
CORS_CONFIG = dict(allow_origins=["*"])
DEBUG = True

if __name__ == "__main__":
    app.run(debug=True)                        # py-008: debug mode
