"use strict";
// Vercel entrypoint: default-export an http.Server (not listened — the
// hosting runtime assigns the port). Raw body is preserved by the Node
// server itself, so HMAC verification over the raw body works unchanged.
const { createAgentServer } = require("../src/server");
module.exports = createAgentServer();
