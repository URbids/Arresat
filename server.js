// Consilience AI proxy — forwards requests to the Anthropic API with your key.
// Zero dependencies. Needs Node 18+ (Railway uses this by default).
//
// Required environment variable:
//   ANTHROPIC_API_KEY  — your key from console.anthropic.com
// Recommended environment variable:
//   ALLOWED_ORIGIN     — your site's origin, e.g. https://yourname.github.io
//                        (locks the proxy to your page; default "*" allows any)

const http = require("http");

const KEY = process.env.ANTHROPIC_API_KEY;
const ALLOWED = process.env.ALLOWED_ORIGIN || "*";
const PORT = process.env.PORT || 3000;

// simple in-memory rate limit: max requests per IP per minute
const hits = new Map();
function rateLimited(ip) {
  const now = Date.now(), win = 60000, max = 40;
  const arr = (hits.get(ip) || []).filter((t) => now - t < win);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > max;
}

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "content-type");
  res.setHeader("Access-Control-Max-Age", "86400");
}

const server = http.createServer((req, res) => {
  const origin = req.headers.origin || "";
  setCors(res);

  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }
  if (req.method === "GET") { res.writeHead(200, { "content-type": "text/plain" }); res.end("Consilience proxy: OK"); return; }
  if (req.method !== "POST") { res.writeHead(405); res.end(); return; }

  if (!KEY) { res.writeHead(500, { "content-type": "application/json" }); res.end(JSON.stringify({ error: "Server is missing ANTHROPIC_API_KEY" })); return; }
  if (ALLOWED !== "*" && origin && origin !== ALLOWED) { res.writeHead(403, { "content-type": "application/json" }); res.end(JSON.stringify({ error: "origin not allowed" })); return; }

  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || (req.socket.remoteAddress || "?");
  if (rateLimited(ip)) { res.writeHead(429, { "content-type": "application/json" }); res.end(JSON.stringify({ error: "rate limit — slow down" })); return; }

  let body = "";
  req.on("data", (c) => { body += c; if (body.length > 200000) req.destroy(); });
  req.on("end", async () => {
    try {
      const r = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": KEY, "anthropic-version": "2023-06-01" },
        body,
      });
      const text = await r.text();
      res.writeHead(r.status, { "content-type": "application/json" });
      res.end(text);
    } catch (e) {
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "upstream failure" }));
    }
  });
});

server.listen(PORT, () => console.log("Consilience proxy listening on " + PORT));
