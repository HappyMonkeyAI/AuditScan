// Fixture: insecure JS/TS module (findings for js-004..js-009).
const child_process = require("child_process");
const axios = require("axios");

function handler(req, res) {
  child_process.exec(req.query.cmd);                 // js-004: command execution
  axios.get(req.query.url).then(r => res.send(r));   // js-005: SSRF
  const out = eval(req.query.expr);                  // js-006: eval

  const obj = {};
  obj["__proto__"] = req.body.payload;               // js-007: prototype pollution

  localStorage.setItem("authToken", req.query.t);    // js-008: token in localStorage
  return out;
}

// js-009: React XSS sink
function View(props) {
  return <div dangerouslySetInnerHTML={{ __html: props.userHtml }} />;
}

module.exports = { handler, View };
