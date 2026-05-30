// Insecure JS service (multiple findings).
const child_process = require("child_process");
const axios = require("axios");

function handler(req, res) {
  child_process.exec(req.query.cmd);                 // command execution
  axios.get(req.query.url).then(r => res.send(r));   // SSRF
  const out = eval(req.query.expr);                  // eval
  return out;
}

module.exports = { handler };
