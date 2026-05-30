// Fixture: hardened JS/TS module (no findings expected).
const { execFile } = require("child_process");
const axios = require("axios");

const ALLOWED_HOSTS = new Set(["api.example.com"]);

function handler(req, res) {
  execFile("ls", ["-l", req.query.dir]);             // arg array, not exec()

  const url = new URL(req.query.url);
  if (!ALLOWED_HOSTS.has(url.host)) {
    return res.status(403).send("forbidden");        // SSRF allowlist
  }
  axios.get(url.toString()).then(r => res.send(r));  // validated URL, not req.* directly

  const data = JSON.parse(req.query.payload);        // no eval
  const map = new Map();
  map.set(req.body.key, req.body.value);             // no __proto__ write
  return data;
}

// session token kept in an HttpOnly cookie, never in browser storage
function View(props) {
  return <div>{props.text}</div>;                    // renders escaped text only
}

module.exports = { handler, View };
