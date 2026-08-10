import express from "express";
import crypto from "crypto";
import pg from "pg";
import path from "path";
import { fileURLToPath } from "url";

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Yerim";
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

if (!ADMIN_PASSWORD) console.warn("WARNING: ADMIN_PASSWORD no está configurada.");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

const sessions = new Map();

app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS keys (
      id UUID PRIMARY KEY,
      key_hash TEXT UNIQUE NOT NULL,
      type TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      expires_at BIGINT,
      used_by TEXT,
      used_username TEXT,
      used_at BIGINT,
      revoked BOOLEAN NOT NULL DEFAULT FALSE
    );

    CREATE TABLE IF NOT EXISTS whitelist (
      roblox_user_id TEXT PRIMARY KEY,
      roblox_username TEXT,
      created_at BIGINT NOT NULL
    );
  `);
}

function hashKey(key) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(String(key).trim().toUpperCase())
    .digest("hex");
}

function makeKey() {
  const raw = crypto.randomBytes(18).toString("base64url").toUpperCase();
  return `X23-${raw.slice(0,6)}-${raw.slice(6,12)}-${raw.slice(12,18)}`;
}

function sessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

function admin(req, res, next) {
  const token = req.headers["x-admin-token"];
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ success:false, message:"No autorizado" });
  }
  next();
}

function passwordMatches(input) {
  const a = Buffer.from(String(input || ""));
  const b = Buffer.from(ADMIN_PASSWORD);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.get("/health", (_req,res) => {
  res.json({ ok:true, service:"roblox-key-api" });
});

app.post("/api/admin/login", (req,res) => {
  if (!passwordMatches(req.body?.password)) {
    return res.status(401).json({ success:false, message:"Contraseña incorrecta" });
  }
  const token = sessionToken();
  sessions.set(token, { createdAt: Date.now() });
  res.json({ success:true, token });
});

app.post("/api/admin/logout", admin, (req,res) => {
  sessions.delete(req.headers["x-admin-token"]);
  res.json({ success:true });
});

app.post("/api/admin/keys/generate", admin, async (req,res) => {
  const type = String(req.body?.type || "hours").toLowerCase();
  const amount = Math.max(1, Math.min(100, Number(req.body?.amount || 1)));

  const units = {
    minutes: 60_000,
    hours: 3_600_000,
    days: 86_400_000,
    weeks: 604_800_000,
    months: 2_592_000_000
  };

  const permanent = type === "permanent" || type === "perm";
  if (!permanent && !units[type]) {
    return res.status(400).json({ success:false, message:"Duración inválida" });
  }

  const createdAt = Date.now();
  const expiresAt = permanent ? null : createdAt + units[type];
  const generated = [];

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    for (let i=0; i<amount; i++) {
      const key = makeKey();
      await client.query(
        `INSERT INTO keys
        (id,key_hash,type,created_at,expires_at)
        VALUES ($1,$2,$3,$4,$5)`,
        [crypto.randomUUID(), hashKey(key), permanent ? "permanent" : type, createdAt, expiresAt]
      );
      generated.push({ key, type: permanent ? "permanent" : type, expiresAt });
    }

    await client.query("COMMIT");
    res.json({ success:true, keys:generated });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(e);
    res.status(500).json({ success:false, message:"No se pudieron generar las keys" });
  } finally {
    client.release();
  }
});

app.get("/api/admin/keys", admin, async (_req,res) => {
  const { rows } = await pool.query(`
    SELECT id,type,created_at,expires_at,used_by,used_username,used_at,revoked
    FROM keys
    ORDER BY created_at DESC
  `);

  res.json({
    success:true,
    keys: rows.map(k => ({
      id:k.id,
      type:k.type,
      createdAt:Number(k.created_at),
      expiresAt:k.expires_at === null ? null : Number(k.expires_at),
      usedBy:k.used_by,
      usedUsername:k.used_username,
      usedAt:k.used_at === null ? null : Number(k.used_at),
      revoked:k.revoked,
      expired:!k.revoked && k.expires_at !== null && Number(k.expires_at) <= Date.now()
    }))
  });
});

app.post("/api/admin/keys/:id/revoke", admin, async (req,res) => {
  const result = await pool.query(
    `UPDATE keys SET revoked=TRUE WHERE id=$1`,
    [req.params.id]
  );
  if (!result.rowCount) {
    return res.status(404).json({ success:false, message:"Key no encontrada" });
  }
  res.json({ success:true });
});

app.delete("/api/admin/keys/:id", admin, async (req,res) => {
  const result = await pool.query(`DELETE FROM keys WHERE id=$1`, [req.params.id]);
  if (!result.rowCount) {
    return res.status(404).json({ success:false, message:"Key no encontrada" });
  }
  res.json({ success:true });
});

/*
  Compatible con tu LocalScript actual:
  POST /api/keys/validate
  body: { code, userId, username }
*/
app.post("/api/keys/validate", async (req,res) => {
  const code = String(req.body?.code || "").trim();
  const userId = String(req.body?.userId || "");
  const username = String(req.body?.username || userId);

  if (!code) {
    return res.json({ valid:false, permanent:false, message:"Key vacía" });
  }

  const { rows } = await pool.query(
    `SELECT * FROM keys WHERE key_hash=$1 LIMIT 1`,
    [hashKey(code)]
  );

  if (!rows.length) {
    return res.json({ valid:false, permanent:false, message:"Key inválida" });
  }

  const k = rows[0];

  if (k.revoked) {
    return res.json({ valid:false, permanent:false, message:"Key revocada" });
  }

  if (k.expires_at !== null && Number(k.expires_at) <= Date.now()) {
    return res.json({ valid:false, permanent:false, message:"Key expirada" });
  }

  if (k.used_by && String(k.used_by) !== userId) {
    return res.json({ valid:false, permanent:false, message:"Esta key ya está vinculada a otro usuario" });
  }

  if (!k.used_by) {
    await pool.query(
      `UPDATE keys
       SET used_by=$1, used_username=$2, used_at=$3
       WHERE id=$4`,
      [userId, username, Date.now(), k.id]
    );
  }

  res.json({
    valid:true,
    permanent:k.type === "permanent",
    message:"Key válida",
    expiresAt:k.expires_at === null ? null : Number(k.expires_at)
  });
});

/* ---------------- WHITELIST COMPATIBLE ---------------- */

app.post("/api/whitelist/check", async (req,res) => {
  const robloxUserId = String(req.body?.robloxUserId || "");

  const { rows } = await pool.query(
    `SELECT roblox_user_id, roblox_username
     FROM whitelist WHERE roblox_user_id=$1`,
    [robloxUserId]
  );

  res.json({
    whitelisted: rows.length > 0,
    username: rows[0]?.roblox_username || null
  });
});

app.post("/api/whitelist", async (req,res) => {
  const id = String(req.body?.robloxUserId || "");
  const username = String(req.body?.robloxUsername || id);

  if (!id) {
    return res.status(400).json({ success:false, message:"User ID requerido" });
  }

  await pool.query(
    `INSERT INTO whitelist (roblox_user_id,roblox_username,created_at)
     VALUES ($1,$2,$3)
     ON CONFLICT (roblox_user_id)
     DO UPDATE SET roblox_username=EXCLUDED.roblox_username`,
    [id, username, Date.now()]
  );

  res.json({
    success:true,
    message:`✓ ${username} agregado a la whitelist`
  });
});

app.get("/api/whitelist", async (_req,res) => {
  const { rows } = await pool.query(`
    SELECT roblox_user_id,roblox_username,created_at
    FROM whitelist
    ORDER BY created_at DESC
  `);

  res.json(rows.map(x => ({
    robloxUserId:x.roblox_user_id,
    robloxUsername:x.roblox_username,
    createdAt:Number(x.created_at)
  })));
});

app.delete("/api/admin/whitelist/:userId", admin, async (req,res) => {
  const result = await pool.query(
    `DELETE FROM whitelist WHERE roblox_user_id=$1`,
    [String(req.params.userId)]
  );

  if (!result.rowCount) {
    return res.status(404).json({ success:false, message:"Usuario no encontrado" });
  }

  res.json({ success:true });
});

app.get("/api/admin/stats", admin, async (_req,res) => {
  const keys = await pool.query(`SELECT COUNT(*)::int AS count FROM keys`);
  const active = await pool.query(`
    SELECT COUNT(*)::int AS count FROM keys
    WHERE revoked=FALSE AND (expires_at IS NULL OR expires_at > $1)
  `,[Date.now()]);
  const revoked = await pool.query(`
    SELECT COUNT(*)::int AS count FROM keys WHERE revoked=TRUE
  `);
  const whitelist = await pool.query(`SELECT COUNT(*)::int AS count FROM whitelist`);

  res.json({
    success:true,
    totalKeys:keys.rows[0].count,
    activeKeys:active.rows[0].count,
    revokedKeys:revoked.rows[0].count,
    whitelistUsers:whitelist.rows[0].count
  });
});

app.get("*", (_req,res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDB()
  .then(() => app.listen(PORT, () => console.log(`API escuchando en ${PORT}`)))
  .catch(err => {
    console.error("No se pudo inicializar la DB:", err);
    process.exit(1);
  });
