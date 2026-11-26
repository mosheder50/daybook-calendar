// Clash calendar: a Cloudflare Worker with a D1 database (binding DB).
// The page and API live only under /c/<KEY>; anything else gets a blank "not found".
import PAGE from "./page.html";

const json = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const DATE = /^\d{4}-\d{2}-\d{2}$/, TIME = /^\d{2}:\d{2}$/;
const mins = t => { const [h, m] = t.split(":").map(Number); return h * 60 + m; };
const endOf = e => (e.end_time && TIME.test(e.end_time) && mins(e.end_time) > mins(e.time)) ? mins(e.end_time) : mins(e.time) + 60; // no end: 1 hour
const key = n => n.trim().toLowerCase().replace(/\s+/g, " ");
const COLS = "id,name,date,time,end_time,rate,note";
const txt = (v, n) => String(v == null ? "" : v).trim().replace(/\s+/g, " ").slice(0, n);
const num = v => (v === null || v === undefined || v === "" || isNaN(Number(v)) || Number(v) < 0) ? null : Math.round(Number(v) * 100) / 100;
// Round 19 (2026-11-26): hours allowed per year (year_hours) + the day the client's year starts (year_start "MM-DD", empty = Jan 1)
const yHours = v => { const n = num(v); return n === null || n > 100000 ? null : n; };
const yStart = v => { const m = /^(\d{1,2})-(\d{1,2})$/.exec(String(v == null ? "" : v).trim()); if (!m) return null; const mo = +m[1], d = +m[2];
  return mo >= 1 && mo <= 12 && d >= 1 && d <= [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1] && !(mo === 1 && d === 1) ? String(mo).padStart(2, "0") + "-" + String(d).padStart(2, "0") : null; };

function clean(b) {
  const name = String(b.name || "").trim().replace(/\s+/g, " ").slice(0, 80);
  const date = String(b.date || ""), time = String(b.time || ""), end = String(b.end || "");
  const note = String(b.note || "").trim().slice(0, 300);
  if (!name) return { err: "Please type a name." };
  if (!DATE.test(date)) return { err: "Please pick a date." };
  if (!TIME.test(time)) return { err: "Please pick a start time." };
  if (!TIME.test(end)) return { err: "Please pick an end time." };
  if (mins(end) <= mins(time)) return { err: "The end time must be after the start time." };
  return { name, date, time, end, note, rate: num(b.rate), clientRate: num(b.clientRate) };
}

async function clashes(env, e, exceptId) {
  const r = await env.DB.prepare("SELECT " + COLS + " FROM entries WHERE date=? AND id<>? ORDER BY time").bind(e.date, exceptId || "").all();
  const s = mins(e.time), en = mins(e.end);
  return (r.results || []).filter(o => mins(o.time) < en && s < endOf(o));
}

async function setClientRate(env, name, rate) {
  await env.DB.prepare("INSERT INTO clients (name_key,name,rate,updated_at) VALUES (?,?,?,?) ON CONFLICT(name_key) DO UPDATE SET rate=excluded.rate, name=excluded.name, updated_at=excluded.updated_at")
    .bind(key(name), name, rate, new Date().toISOString()).run();
}

// 2026-11-24: sign-in. Username/password are checked here on the server; the password itself is stored nowhere,
// only AUTH_HASH = sha256hex(AUTH_SALT + password) (secret env vars, never in the page or on GitHub).
// A good sign-in gets a token "<user>.<expires ms>.<HMAC-SHA256 with AUTH_SECRET>", valid 180 days; every API call
// except /api/login must send it as "Authorization: Bearer <token>", or it gets 401.
const enc = new TextEncoder();
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const sha256 = async t => hex(await crypto.subtle.digest("SHA-256", enc.encode(t)));
async function hmac(secret, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}
function same(a, b) { a = String(a); b = String(b); let d = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return d === 0; }
const TOKEN_DAYS = 180;
// 2026-11-24 (2): the password can be changed from the page. The new salted hash lives in this app's own D1 table auth_settings
// (k,v rows: salt, hash, gen). No row -> the env secrets (AUTH_SALT/AUTH_HASH) are used. "gen" is in every token; a password
// change sets a new gen, so every other device is signed out (the device that changed it gets a fresh token).
async function creds(env) {
  const c = { salt: env.AUTH_SALT, hash: env.AUTH_HASH, gen: "0" };
  try { ((await env.DB.prepare("SELECT k,v FROM auth_settings").all()).results || []).forEach(r => { if (r.k in c && r.v) c[r.k] = r.v; }); } catch (e) {}
  return c;
}
const rnd = n => b64u(crypto.getRandomValues(new Uint8Array(n)));
async function makeToken(env, user, gen) { const p = user + "." + (Date.now() + TOKEN_DAYS * 864e5) + "." + gen; return p + "." + await hmac(env.AUTH_SECRET, p); }
async function tokenOk(env, req) {
  if (!env.AUTH_SECRET || !env.AUTH_USER) return false;
  const m = /^Bearer\s+(\S+)$/.exec(req.headers.get("authorization") || ""); if (!m) return false;
  const t = m[1].split("."); if (t.length !== 3 && t.length !== 4) return false;
  if (t[0] !== env.AUTH_USER || !(Number(t[1]) > Date.now())) return false;
  const gen = t.length === 4 ? t[2] : "0", sig = t[t.length - 1];
  if (!same(sig, await hmac(env.AUTH_SECRET, t.slice(0, -1).join(".")))) return false;
  return same(gen, (await creds(env)).gen);
}
async function login(req, env) {
  let b = {}; try { b = await req.json(); } catch (e) {}
  const user = String(b.user || "").trim().toLowerCase(), pass = String(b.pass || ""), c = await creds(env);
  if (env.AUTH_USER && c.hash && c.salt && same(user, env.AUTH_USER) && same(await sha256(c.salt + pass), c.hash))
    return json({ ok: true, token: await makeToken(env, env.AUTH_USER, c.gen), user: env.AUTH_USER, days: TOKEN_DAYS });
  await new Promise(r => setTimeout(r, 700)); // slow down guessing
  return json({ error: "Wrong username or password." }, 401);
}
async function changePassword(req, env) { // caller already has a valid token
  let b = {}; try { b = await req.json(); } catch (e) {}
  const old = String(b.old || ""), nw = String(b.new || ""), c = await creds(env);
  if (!same(await sha256(c.salt + old), c.hash)) { await new Promise(r => setTimeout(r, 700)); return json({ error: "The old password is not right." }, 403); }
  if (nw.length < 4) return json({ error: "The new password must be at least 4 characters." }, 400);
  if (nw.length > 100) return json({ error: "The new password is too long." }, 400);
  const salt = rnd(18), gen = rnd(9), hash = await sha256(salt + nw), q = "INSERT INTO auth_settings (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v";
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS auth_settings (k TEXT PRIMARY KEY, v TEXT)").run();
  await env.DB.batch([env.DB.prepare(q).bind("salt", salt), env.DB.prepare(q).bind("hash", hash), env.DB.prepare(q).bind("gen", gen)]);
  return json({ ok: true, token: await makeToken(env, env.AUTH_USER, gen), user: env.AUTH_USER });
}

// 2026-11-24 (3): "Forgot password?" by TEXT. The Worker cannot send texts itself; it only makes the code.
// Switched on only when RESET_PHONE (secret, a +1 phone number) is set; otherwise the link is hidden and these calls say off.
// D1 table reset_codes: id, code_hash (HMAC of the code), code_plain (held ONLY until the relay computer fetched+texted it,
// or the code expired), created, expires (15 min), tries (max 5 wrong), used, texted.
// The relay (owner's assistant computer) reads pending codes from GET /api/reset-outbox with header
// "x-relay-secret: <RELAY_SECRET>", texts them, then POST /api/reset-outbox/<id>/texted wipes the plain code.
const RESET_MIN = 15, RESET_PER_HOUR = 3, RESET_TRIES = 5;
const resetOn = env => !!(env.RESET_PHONE && String(env.RESET_PHONE).replace(/\D/g, "").length >= 10 && env.RELAY_SECRET);
async function resetTable(env) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS reset_codes (id INTEGER PRIMARY KEY AUTOINCREMENT, code_hash TEXT, code_plain TEXT, created INTEGER, expires INTEGER, tries INTEGER DEFAULT 0, used INTEGER DEFAULT 0, texted INTEGER DEFAULT 0)").run();
  // plain codes never outlive their code
  await env.DB.prepare("UPDATE reset_codes SET code_plain=NULL WHERE code_plain IS NOT NULL AND (expires<? OR used=1 OR tries>=?)").bind(Date.now(), RESET_TRIES).run();
}
const codeHash = (env, id, code) => hmac(env.AUTH_SECRET, "reset:" + id + ":" + code);
function resetInfo(env) {
  if (!resetOn(env)) return json({ on: false });
  return json({ on: true, last4: String(env.RESET_PHONE).replace(/\D/g, "").slice(-4), minutes: RESET_MIN });
}
async function resetRequest(env) {
  if (!resetOn(env)) return json({ error: "Not available." }, 404);
  await resetTable(env);
  const now = Date.now();
  const n = (await env.DB.prepare("SELECT COUNT(*) AS n FROM reset_codes WHERE created>?").bind(now - 3600e3).first()).n;
  if (n >= RESET_PER_HOUR) return json({ error: "Too many codes asked for. Please wait an hour and try again, or use the last code you got." }, 429);
  const r = new Uint32Array(1); crypto.getRandomValues(r);
  const code = String(r[0] % 1000000).padStart(6, "0");
  const ins = await env.DB.prepare("INSERT INTO reset_codes (code_hash, code_plain, created, expires) VALUES ('', ?, ?, ?)").bind(code, now, now + RESET_MIN * 60e3).run();
  const id = ins.meta.last_row_id;
  await env.DB.prepare("UPDATE reset_codes SET code_hash=? WHERE id=?").bind(await codeHash(env, id, code), id).run();
  return json({ ok: true, last4: String(env.RESET_PHONE).replace(/\D/g, "").slice(-4), minutes: RESET_MIN });
}
async function resetVerify(req, env) {
  if (!resetOn(env)) return json({ error: "Not available." }, 404);
  let b = {}; try { b = await req.json(); } catch (e) {}
  const code = String(b.code || "").replace(/\D/g, ""), nw = String(b.new || "");
  if (nw.length < 4) return json({ error: "The new password must be at least 4 characters." }, 400);
  if (nw.length > 100) return json({ error: "The new password is too long." }, 400);
  await resetTable(env);
  const now = Date.now();
  const live = (await env.DB.prepare("SELECT id, code_hash FROM reset_codes WHERE used=0 AND expires>? AND tries<?").bind(now, RESET_TRIES).all()).results || [];
  if (!live.length) return json({ error: "This code has run out (or was used). Please ask for a new code.", expired: true }, 410);
  let hit = null;
  if (code.length === 6) for (const c of live) if (same(await codeHash(env, c.id, code), c.code_hash)) hit = c;
  if (!hit) {
    await env.DB.prepare("UPDATE reset_codes SET tries=tries+1 WHERE used=0 AND expires>? AND tries<?").bind(now, RESET_TRIES).run();
    await new Promise(r => setTimeout(r, 700));
    const left = (await env.DB.prepare("SELECT MAX(?-tries) AS l FROM reset_codes WHERE used=0 AND expires>?").bind(RESET_TRIES, now).first()).l;
    return json(left > 0 ? { error: "That code is not right. Please check the text and try again." } : { error: "Too many wrong tries. Please ask for a new code.", expired: true }, left > 0 ? 403 : 410);
  }
  const salt = rnd(18), gen = rnd(9), hash = await sha256(salt + nw), q = "INSERT INTO auth_settings (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v";
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS auth_settings (k TEXT PRIMARY KEY, v TEXT)").run();
  await env.DB.batch([env.DB.prepare(q).bind("salt", salt), env.DB.prepare(q).bind("hash", hash), env.DB.prepare(q).bind("gen", gen),
    env.DB.prepare("UPDATE reset_codes SET used=1, code_plain=NULL WHERE used=0")]); // one good code ends all open codes
  return json({ ok: true, token: await makeToken(env, env.AUTH_USER, gen), user: env.AUTH_USER });
}
async function resetOutbox(req, env, id, act) {
  if (!env.RELAY_SECRET || !same(req.headers.get("x-relay-secret") || "", env.RELAY_SECRET)) { await new Promise(r => setTimeout(r, 700)); return json({ error: "no" }, 403); }
  if (!resetOn(env)) return json({ on: false, pending: [] });
  await resetTable(env);
  if (req.method === "GET" && !id) {
    const r = (await env.DB.prepare("SELECT id, code_plain AS code, expires FROM reset_codes WHERE texted=0 AND used=0 AND code_plain IS NOT NULL AND expires>? ORDER BY id").bind(Date.now()).all()).results || [];
    return json({ on: true, phone: env.RESET_PHONE, pending: r });
  }
  if (req.method === "POST" && id && act === "texted") {
    const r = await env.DB.prepare("UPDATE reset_codes SET texted=1, code_plain=NULL WHERE id=?").bind(Number(id)).run();
    return json({ ok: true, changed: r.meta.changes });
  }
  return json({ error: "Not found" }, 404);
}

// The GitHub Pages copy of the page (https://mosheder50.github.io/daybook-calendar/?k=<KEY>, owner's account since 2026-11-26; old copy amy-brooks-fa.github.io) calls this API from another origin.
const CORS_ORIGINS = ["https://mosheder50.github.io", "https://amy-brooks-fa.github.io"];

export default {
  async fetch(req, env) {
    const origin = req.headers.get("origin") || "";
    const allowed = CORS_ORIGINS.includes(origin);
    const cors = { "access-control-allow-origin": origin, "access-control-allow-methods": "GET, POST, PUT, DELETE, OPTIONS", "access-control-allow-headers": "content-type, authorization", "access-control-max-age": "86400", "vary": "origin" };
    const parts = new URL(req.url).pathname.split("/").filter(Boolean);
    if (req.method === "OPTIONS") {
      if (allowed && parts[0] === "c" && parts[1] === env.KEY && parts[2] === "api") return new Response(null, { status: 204, headers: cors });
      return new Response("Not found", { status: 404 });
    }
    const res = await handle(req, env);
    if (!allowed) return res;
    const out = new Response(res.body, res);
    for (const [k, v] of Object.entries(cors)) out.headers.set(k, v);
    return out;
  },
};

async function handle(req, env) {
  {
    const url = new URL(req.url);
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts[0] !== "c" || parts[1] !== env.KEY) return new Response("Not found", { status: 404, headers: { "x-robots-tag": "noindex" } });

    if (parts.length === 2) {
      if (!url.pathname.endsWith("/")) return Response.redirect(url.origin + url.pathname + "/", 301);
      return new Response(PAGE, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-robots-tag": "noindex" } });
    }
    if (parts[2] !== "api") return new Response("Not found", { status: 404 });
    if (parts[3] === "login" && parts.length === 4 && req.method === "POST") return login(req, env);
    if (parts[3] === "reset-info" && parts.length === 4 && req.method === "GET") return resetInfo(env);
    if (parts[3] === "reset-request" && parts.length === 4 && req.method === "POST") return resetRequest(env);
    if (parts[3] === "reset-verify" && parts.length === 4 && req.method === "POST") return resetVerify(req, env);
    if (parts[3] === "reset-outbox") return resetOutbox(req, env, parts[4], parts[5]);
    if (!(await tokenOk(env, req))) return json({ error: "Please sign in.", signin: true }, 401);
    if (parts[3] === "password" && parts.length === 4 && req.method === "POST") return changePassword(req, env);

    const id = parts[4];
    const now = new Date().toISOString();
    try {
      if (parts[3] === "entries" && !id && req.method === "GET") {
        const from = url.searchParams.get("from") || "0000-00-00", to = url.searchParams.get("to") || "9999-99-99";
        const r = await env.DB.prepare("SELECT " + COLS + " FROM entries WHERE date>=? AND date<=? ORDER BY date,time,created_at").bind(from, to).all();
        return json({ entries: r.results || [] });
      }
      if (parts[3] === "entries" && req.method === "POST" || parts[3] === "entries" && id && req.method === "PUT") {
        const b = await req.json(); const e = clean(b);
        if (e.err) return json({ error: e.err }, 400);
        const c = await clashes(env, e, id);
        if (c.length && !b.force) return json({ clash: c }, 409);
        if (e.clientRate !== null) await setClientRate(env, e.name, e.clientRate);
        else await env.DB.prepare("INSERT INTO clients (name_key,name,rate,updated_at) VALUES (?,?,NULL,?) ON CONFLICT(name_key) DO NOTHING").bind(key(e.name), e.name, now).run();
        if (id) {
          const r = await env.DB.prepare("UPDATE entries SET name=?,date=?,time=?,end_time=?,rate=?,note=?,updated_at=? WHERE id=?")
            .bind(e.name, e.date, e.time, e.end, e.rate, e.note, now, id).run();
          if (!r.meta.changes) return json({ error: "That entry was already deleted." }, 404);
          return json({ ok: true });
        }
        const nid = crypto.randomUUID();
        await env.DB.prepare("INSERT INTO entries (id,name,date,time,end_time,rate,note,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)")
          .bind(nid, e.name, e.date, e.time, e.end, e.rate, e.note, now, now).run();
        return json({ ok: true, id: nid });
      }
      if (parts[3] === "entries" && id && req.method === "DELETE") {
        await env.DB.prepare("DELETE FROM entries WHERE id=?").bind(id).run();
        return json({ ok: true });
      }
      if (parts[3] === "search" && req.method === "GET") {
        const q = (url.searchParams.get("q") || "").trim();
        if (!q) return json({ entries: [] });
        const r = await env.DB.prepare("SELECT " + COLS + " FROM entries WHERE name LIKE ? ORDER BY date,time LIMIT 200").bind("%" + q + "%").all();
        return json({ entries: r.results || [] });
      }
      // Round 12: each agency's billing cover sheet (.docx/.xlsx), stored base64 in chunks (D1 rows stay small), plus its saved "where things go" mapping.
      if (parts[3] === "sheets" && !id && req.method === "GET") {
        const r = await env.DB.prepare("SELECT agency_key,agency,filename,kind,size,mapping,updated_at FROM sheets ORDER BY agency_key").all();
        return json({ sheets: r.results || [] });
      }
      if (parts[3] === "sheets" && id) {
        const ak = key(decodeURIComponent(id)).slice(0, 80);
        if (req.method === "GET") {
          const m = await env.DB.prepare("SELECT agency_key,agency,filename,kind,size,mapping,updated_at FROM sheets WHERE agency_key=?").bind(ak).first();
          if (!m) return json({ error: "No sheet for this agency." }, 404);
          const ps = await env.DB.prepare("SELECT data FROM sheet_parts WHERE agency_key=? ORDER BY idx").bind(ak).all();
          return json({ sheet: { ...m, data: (ps.results || []).map(x => x.data).join("") } });
        }
        if (req.method === "DELETE") {
          await env.DB.batch([env.DB.prepare("DELETE FROM sheets WHERE agency_key=?").bind(ak), env.DB.prepare("DELETE FROM sheet_parts WHERE agency_key=?").bind(ak)]);
          return json({ ok: true });
        }
        if (req.method === "PUT") {
          const b = await req.json();
          const mapping = b.mapping == null ? null : JSON.stringify(b.mapping).slice(0, 20000);
          if (b.data == null) { // only the mapping changes
            const r = await env.DB.prepare("UPDATE sheets SET mapping=?, updated_at=? WHERE agency_key=?").bind(mapping, now, ak).run();
            return json({ ok: true });
          }
          const data = String(b.data), kind = String(b.kind || "");
          // Round 13: PDF or Word only for new uploads (Excel dropped by the owner); a key "client:<name>" = that one client's own sheet.
          if (!/^(docx|pdf)$/.test(kind)) return json({ error: "Only PDF or Word (.docx) files." }, 400);
          if (!/^[A-Za-z0-9+/=]+$/.test(data) || data.length > 8400000) return json({ error: "The file is too big (6 MB at most)." }, 400);
          const CH = 700000, st = [env.DB.prepare("DELETE FROM sheet_parts WHERE agency_key=?").bind(ak)];
          for (let i = 0; i * CH < data.length; i++) st.push(env.DB.prepare("INSERT INTO sheet_parts (agency_key,idx,data) VALUES (?,?,?)").bind(ak, i, data.slice(i * CH, (i + 1) * CH)));
          st.push(env.DB.prepare("INSERT INTO sheets (agency_key,agency,filename,kind,size,parts,mapping,updated_at) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(agency_key) DO UPDATE SET agency=excluded.agency,filename=excluded.filename,kind=excluded.kind,size=excluded.size,parts=excluded.parts,mapping=excluded.mapping,updated_at=excluded.updated_at")
            .bind(ak, txt(b.agency, 80), txt(b.filename, 120), kind, Math.round(data.length * 3 / 4), Math.ceil(data.length / CH), mapping, now));
          await env.DB.batch(st);
          return json({ ok: true });
        }
      }
      if (parts[3] === "clients" && !id && req.method === "GET") {
        const r = await env.DB.prepare("SELECT c.name_key,c.name,c.rate,c.phone,c.email,c.note,c.agency,c.medicaid,c.year_hours,c.year_start,(SELECT COUNT(*) FROM entries e WHERE lower(e.name)=c.name_key) AS bookings FROM clients c ORDER BY lower(c.name)").all();
        return json({ clients: r.results || [] });
      }
      if (parts[3] === "clients" && !id && req.method === "POST") {
        const b = await req.json(); const name = String(b.name || "").trim().replace(/\s+/g, " ").slice(0, 80);
        if (!name) return json({ error: "Please type a name." }, 400);
        if (b.rate !== "" && b.rate != null && num(b.rate) === null) return json({ error: "The rate must be a number, like 50." }, 400);
        const ex = await env.DB.prepare("SELECT name FROM clients WHERE name_key=?").bind(key(name)).first();
        if (ex) return json({ error: ex.name + " is already in your clients." }, 409);
        await setClientRate(env, name, num(b.rate));
        await env.DB.prepare("UPDATE clients SET phone=?,email=?,note=?,agency=?,medicaid=?,year_hours=?,year_start=? WHERE name_key=?").bind(txt(b.phone, 40) || null, txt(b.email, 120) || null, txt(b.note, 300) || null, txt(b.agency, 80) || null, txt(b.medicaid, 40) || null, yHours(b.year_hours), yStart(b.year_start), key(name)).run();
        return json({ ok: true });
      }
      if (parts[3] === "import" && req.method === "POST") {
        // From an uploaded file: add or update clients (only fields given), add bookings (skips exact duplicates).
        const b = await req.json();
        const cl = Array.isArray(b.clients) ? b.clients.slice(0, 200) : [], bk = Array.isArray(b.bookings) ? b.bookings.slice(0, 200) : [];
        const st = []; let added = 0, updated = 0, booked = 0, dup = 0;
        const have = {}; ((await env.DB.prepare("SELECT name_key FROM clients").all()).results || []).forEach(r => have[r.name_key] = 1);
        const seen = {}, ds = bk.map(x => String(x.date || "")).filter(d => DATE.test(d)).sort();
        if (ds.length) ((await env.DB.prepare("SELECT name,date,time FROM entries WHERE date>=? AND date<=?").bind(ds[0], ds[ds.length - 1]).all()).results || [])
          .forEach(r => seen[key(r.name) + "|" + r.date + "|" + r.time] = 1);
        for (const c of cl) {
          const name = txt(c.name, 80); if (!name) continue;
          const k = key(name), rate = num(c.rate), phone = txt(c.phone, 40) || null, email = txt(c.email, 120) || null, note = txt(c.note, 300) || null, agency = txt(c.agency, 80) || null, medicaid = txt(c.medicaid, 40) || null, yh = yHours(c.year_hours), ys = yStart(c.year_start);
          if (have[k]) { updated++; st.push(env.DB.prepare("UPDATE clients SET rate=COALESCE(?,rate),phone=COALESCE(?,phone),email=COALESCE(?,email),note=COALESCE(?,note),agency=COALESCE(?,agency),medicaid=COALESCE(?,medicaid),year_hours=COALESCE(?,year_hours),year_start=COALESCE(?,year_start),updated_at=? WHERE name_key=?").bind(rate, phone, email, note, agency, medicaid, yh, ys, now, k)); }
          else { added++; have[k] = 1; st.push(env.DB.prepare("INSERT INTO clients (name_key,name,rate,phone,email,note,agency,medicaid,year_hours,year_start,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)").bind(k, name, rate, phone, email, note, agency, medicaid, yh, ys, now)); }
        }
        for (const x of bk) {
          const e = clean(x); if (e.err) continue;
          const sig = key(e.name) + "|" + e.date + "|" + e.time;
          if (seen[sig]) { dup++; continue; }
          seen[sig] = 1; booked++;
          if (!have[key(e.name)]) { have[key(e.name)] = 1; st.push(env.DB.prepare("INSERT INTO clients (name_key,name,rate,updated_at) VALUES (?,?,NULL,?) ON CONFLICT(name_key) DO NOTHING").bind(key(e.name), e.name, now)); }
          st.push(env.DB.prepare("INSERT INTO entries (id,name,date,time,end_time,rate,note,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)")
            .bind(crypto.randomUUID(), e.name, e.date, e.time, e.end, e.rate, e.note, now, now));
        }
        if (st.length) await env.DB.batch(st);
        return json({ ok: true, added, updated, booked, dup });
      }
      if (parts[3] === "clients" && id && req.method === "PUT") {
        const old = decodeURIComponent(id);
        const b = await req.json(); const name = String(b.name || "").trim().replace(/\s+/g, " ").slice(0, 80);
        if (!name) return json({ error: "Please type a name." }, 400);
        if (b.rate !== "" && b.rate != null && num(b.rate) === null) return json({ error: "The rate must be a number, like 50." }, 400);
        const cur = await env.DB.prepare("SELECT name FROM clients WHERE name_key=?").bind(old).first();
        if (!cur) return json({ error: "That client was already deleted." }, 404);
        const nk = key(name);
        if (nk !== old) {
          const ex = await env.DB.prepare("SELECT name FROM clients WHERE name_key=?").bind(nk).first();
          if (ex) return json({ error: ex.name + " is already in your clients." }, 409);
        }
        const extra = ["phone", "email", "note", "agency", "medicaid", "year_hours", "year_start"].filter(f => b[f] !== undefined);
        await env.DB.batch([
          env.DB.prepare("UPDATE clients SET name_key=?, name=?, rate=?, updated_at=?" + extra.map(f => "," + f + "=?").join("") + " WHERE name_key=?")
            .bind(nk, name, num(b.rate), now, ...extra.map(f => f === "year_hours" ? yHours(b[f]) : f === "year_start" ? yStart(b[f]) : txt(b[f], f === "phone" ? 40 : f === "email" ? 120 : f === "agency" || f === "medicaid" ? (f === "agency" ? 80 : 40) : 300) || null), old),
          env.DB.prepare("UPDATE entries SET name=?, updated_at=? WHERE lower(name)=?").bind(name, now, old),
          // Round 13: the client's own cover sheet follows a rename
          ...(nk !== old ? [env.DB.prepare("DELETE FROM sheets WHERE agency_key=?").bind("client:" + nk), env.DB.prepare("DELETE FROM sheet_parts WHERE agency_key=?").bind("client:" + nk),
            env.DB.prepare("UPDATE sheets SET agency_key=?, agency=? WHERE agency_key=?").bind("client:" + nk, name, "client:" + old),
            env.DB.prepare("UPDATE sheet_parts SET agency_key=? WHERE agency_key=?").bind("client:" + nk, "client:" + old)] : []),
        ]);
        return json({ ok: true });
      }
      if (parts[3] === "clients" && id && req.method === "DELETE") {
        const old = decodeURIComponent(id);
        const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM entries WHERE lower(name)=?").bind(old).first();
        if (c && c.n > 0) return json({ error: "This client has " + c.n + " booking(s). Delete or change those first." }, 409);
        await env.DB.batch([env.DB.prepare("DELETE FROM clients WHERE name_key=?").bind(old),
          env.DB.prepare("DELETE FROM sheets WHERE agency_key=?").bind("client:" + old), env.DB.prepare("DELETE FROM sheet_parts WHERE agency_key=?").bind("client:" + old)]); // Round 13: and its own sheet
        return json({ ok: true });
      }
      if (parts[3] === "clients" && !id && req.method === "PUT") {
        const b = await req.json(); const name = String(b.name || "").trim().replace(/\s+/g, " ").slice(0, 80);
        if (!name) return json({ error: "No name." }, 400);
        await setClientRate(env, name, num(b.rate));
        return json({ ok: true });
      }
    } catch (err) {
      return json({ error: "Something went wrong saving. Please try again." }, 500);
    }
    return json({ error: "Not found" }, 404);
  }
}
