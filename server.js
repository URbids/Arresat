// Arresat API — accounts, per-user map storage, and the Anthropic AI proxy.
// One dependency: pg. Everything else uses Node's built-in crypto. Needs Node 18+.
//
// Required environment variables:
//   DATABASE_URL       — Postgres connection string. On Railway, add this as a
//                        reference variable:  ${{ Postgres.DATABASE_URL }}
//   ANTHROPIC_API_KEY  — your key from console.anthropic.com (for the /ai proxy)
// Recommended:
//   ALLOWED_ORIGIN     — your site origin, e.g. https://urbids.github.io
//                        (locks the API to your page; default "*" allows any)
// Optional:
//   PGSSL              — "require" or "disable" to force SSL on/off (otherwise auto)
//   SESSION_DAYS       — how long a login lasts (default 30)

const http = require("http");
const crypto = require("crypto");
const { Pool } = require("pg");

const KEY = process.env.ANTHROPIC_API_KEY;
const ALLOWED = process.env.ALLOWED_ORIGIN || "*";
const PORT = process.env.PORT || 3000;
const SESSION_DAYS = parseInt(process.env.SESSION_DAYS || "30", 10);

// ---- Postgres -------------------------------------------------------------
function sslSetting() {
  const url = process.env.DATABASE_URL || "";
  if (process.env.PGSSL === "disable") return false;
  if (process.env.PGSSL === "require") return { rejectUnauthorized: false };
  // Railway internal networking doesn't use SSL; public/external endpoints do.
  if (url.includes("railway.internal") || url.includes("localhost") || url.includes("127.0.0.1")) return false;
  return { rejectUnauthorized: false };
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: sslSetting() });

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      email       TEXT UNIQUE NOT NULL,
      pw_salt     TEXT NOT NULL,
      pw_hash     TEXT NOT NULL,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash  TEXT PRIMARY KEY,
      user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      expires_at  TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS maps (
      user_id     BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      data        JSONB NOT NULL,
      updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
  `);
}

// ---- crypto helpers -------------------------------------------------------
function hashPassword(password, salt) {
  // scrypt: strong, memory-hard KDF built into Node. 64-byte derived key.
  return crypto.scryptSync(password, salt, 64).toString("hex");
}
function makeSalt() { return crypto.randomBytes(16).toString("hex"); }
function safeEqualHex(a, b) {
  const ba = Buffer.from(a, "hex"), bb = Buffer.from(b, "hex");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}
function newToken() { return crypto.randomBytes(32).toString("hex"); }
function sha256(s) { return crypto.createHash("sha256").update(s).digest("hex"); }

// ---- tiny rate limiters (in-memory; reset on redeploy, fine for one instance)
function makeLimiter(windowMs, max) {
  const hits = new Map();
  return (ip) => {
    const now = Date.now();
    const arr = (hits.get(ip) || []).filter((t) => now - t < windowMs);
    arr.push(now);
    hits.set(ip, arr);
    return arr.length > max;
  };
}
const aiLimit = makeLimiter(60000, 40);     // 40 AI calls / minute / IP
const authLimit = makeLimiter(300000, 12);  // 12 auth attempts / 5 min / IP

// ---- http helpers ---------------------------------------------------------
function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "content-type, authorization");
  res.setHeader("Access-Control-Max-Age", "86400");
}
function json(res, status, obj) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(obj));
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let body = "", over = false;
    req.on("data", (c) => { body += c; if (body.length > limit) { over = true; req.destroy(); } });
    req.on("end", () => { if (over) reject(new Error("too large")); else resolve(body); });
    req.on("error", reject);
  });
}
async function readJson(req, limit) {
  const raw = await readBody(req, limit || 2000000);
  if (!raw) return {};
  return JSON.parse(raw);
}
function clientIp(req) {
  return (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || (req.socket.remoteAddress || "?");
}
function bearer(req) {
  const h = req.headers["authorization"] || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}
async function userFromToken(req) {
  const tok = bearer(req);
  if (!tok) return null;
  const { rows } = await pool.query(
    `SELECT u.id, u.email, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1`,
    [sha256(tok)]
  );
  if (!rows.length) return null;
  if (new Date(rows[0].expires_at).getTime() < Date.now()) {
    await pool.query(`DELETE FROM sessions WHERE token_hash = $1`, [sha256(tok)]);
    return null;
  }
  return { id: rows[0].id, email: rows[0].email };
}
async function createSession(userId) {
  const tok = newToken();
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000);
  await pool.query(
    `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
    [sha256(tok), userId, expires]
  );
  return tok;
}
function normEmail(e) { return String(e || "").trim().toLowerCase(); }
function validEmail(e) { return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e) && e.length <= 254; }

// ---- route handlers -------------------------------------------------------
async function handleSignup(req, res) {
  const ip = clientIp(req);
  if (authLimit(ip)) return json(res, 429, { error: "Too many attempts — wait a few minutes." });
  let b;
  try { b = await readJson(req, 10000); } catch { return json(res, 400, { error: "bad request" }); }
  const email = normEmail(b.email);
  const password = String(b.password || "");
  if (!validEmail(email)) return json(res, 400, { error: "Enter a valid email." });
  if (password.length < 8) return json(res, 400, { error: "Password must be at least 8 characters." });
  if (password.length > 200) return json(res, 400, { error: "Password is too long." });
  const salt = makeSalt();
  const pw = hashPassword(password, salt);
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (email, pw_salt, pw_hash) VALUES ($1, $2, $3) RETURNING id`,
      [email, salt, pw]
    );
    const token = await createSession(rows[0].id);
    return json(res, 200, { token, email });
  } catch (e) {
    if (e && e.code === "23505") return json(res, 409, { error: "That email is already registered. Try logging in." });
    return json(res, 500, { error: "Could not create account." });
  }
}

async function handleLogin(req, res) {
  const ip = clientIp(req);
  if (authLimit(ip)) return json(res, 429, { error: "Too many attempts — wait a few minutes." });
  let b;
  try { b = await readJson(req, 10000); } catch { return json(res, 400, { error: "bad request" }); }
  const email = normEmail(b.email);
  const password = String(b.password || "");
  const { rows } = await pool.query(`SELECT id, pw_salt, pw_hash FROM users WHERE email = $1`, [email]);
  const fail = () => json(res, 401, { error: "Invalid email or password." });
  if (!rows.length) { hashPassword(password || "x", "00"); return fail(); } // even out timing vs. real lookups
  const ok = safeEqualHex(rows[0].pw_hash, hashPassword(password, rows[0].pw_salt));
  if (!ok) return fail();
  const token = await createSession(rows[0].id);
  return json(res, 200, { token, email });
}

async function handleLogout(req, res) {
  const tok = bearer(req);
  if (tok) await pool.query(`DELETE FROM sessions WHERE token_hash = $1`, [sha256(tok)]);
  return json(res, 200, { ok: true });
}

async function handleMe(req, res) {
  const user = await userFromToken(req);
  if (!user) return json(res, 401, { error: "Not signed in." });
  return json(res, 200, { email: user.email });
}

async function handleGetMap(req, res) {
  const user = await userFromToken(req);
  if (!user) return json(res, 401, { error: "Not signed in." });
  const { rows } = await pool.query(`SELECT data, updated_at FROM maps WHERE user_id = $1`, [user.id]);
  if (!rows.length) return json(res, 200, { data: null, updated_at: null });
  return json(res, 200, { data: rows[0].data, updated_at: rows[0].updated_at });
}

async function handlePutMap(req, res) {
  const user = await userFromToken(req);
  if (!user) return json(res, 401, { error: "Not signed in." });
  let b;
  try { b = await readJson(req, 4000000); } catch { return json(res, 400, { error: "Map too large or invalid." }); }
  if (!b || typeof b.data !== "object" || b.data === null) return json(res, 400, { error: "Missing map data." });
  await pool.query(
    `INSERT INTO maps (user_id, data, updated_at) VALUES ($1, $2, now())
       ON CONFLICT (user_id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
    [user.id, b.data]
  );
  return json(res, 200, { ok: true, updated_at: new Date().toISOString() });
}

async function handleAi(req, res) {
  const ip = clientIp(req);
  if (!KEY) return json(res, 500, { error: "Server is missing ANTHROPIC_API_KEY" });
  if (aiLimit(ip)) return json(res, 429, { error: "rate limit — slow down" });
  let raw;
  try { raw = await readBody(req, 200000); } catch { return json(res, 413, { error: "request too large" }); }
  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": KEY, "anthropic-version": "2023-06-01" },
      body: raw,
    });
    const text = await r.text();
    res.writeHead(r.status, { "content-type": "application/json" });
    res.end(text);
  } catch {
    return json(res, 502, { error: "upstream failure" });
  }
}

// ---- router ---------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin || "";
  setCors(res);
  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }
  if (ALLOWED !== "*" && origin && origin !== ALLOWED) return json(res, 403, { error: "origin not allowed" });

  const url = (req.url || "/").split("?")[0].replace(/\/+$/, "") || "/";
  const m = req.method;

  try {
    if (m === "GET" && url === "/") { res.writeHead(200, { "content-type": "text/plain" }); res.end("Arresat API: OK"); return; }
    if (m === "POST" && url === "/ai") return await handleAi(req, res);
    if (m === "POST" && url === "/auth/signup") return await handleSignup(req, res);
    if (m === "POST" && url === "/auth/login") return await handleLogin(req, res);
    if (m === "POST" && url === "/auth/logout") return await handleLogout(req, res);
    if (m === "GET" && url === "/me") return await handleMe(req, res);
    if (m === "GET" && url === "/map") return await handleGetMap(req, res);
    if (m === "PUT" && url === "/map") return await handlePutMap(req, res);
    return json(res, 404, { error: "not found" });
  } catch (e) {
    return json(res, 500, { error: "server error" });
  }
});

initDb()
  .then(() => server.listen(PORT, () => console.log("Arresat API listening on " + PORT)))
  .catch((e) => {
    console.error("DB init failed:", e.message);
    // Still listen so health checks pass and you can read logs; DB routes will error until fixed.
    server.listen(PORT, () => console.log("Arresat API listening on " + PORT + " (DB init failed)"));
  });
