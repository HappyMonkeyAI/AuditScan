"""Insecure Python service (multiple findings)."""
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    subprocess.run(request.args["cmd"], shell=True)   # command injection
    os.system(request.args["cmd"])                    # os.system
    return str(eval(request.args["expr"]))            # eval


if __name__ == "__main__":
    app.run(debug=True)                               # debug mode
