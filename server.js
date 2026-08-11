import express from "express";
import crypto from "crypto";
import pg from "pg";
import path from "path";
import { fileURLToPath } from "url";

const { Pool } = pg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 3000);

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Yerim";

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.randomBytes(32).toString("hex");

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  console.error("ERROR: DATABASE_URL NO ESTA CONFIGURADA");
  process.exit(1);
}

const pool = new Pool({
  connectionString: databaseUrl,
  ssl: {
    rejectUnauthorized: false
  },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const SESSION_TTL = 30 * 24 * 60 * 60 * 1000;

app.use(express.json({ limit: "100kb" }));

app.use(express.static(path.join(__dirname, "public")));

// ============================================================
// FUNCIONES
// ============================================================

function hashKey(key) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(String(key).trim().toUpperCase())
    .digest("hex");
}

// La key real se cifra para poder mostrarla únicamente en el panel admin.
// Esto permite conservar la seguridad sin guardar la key en texto plano.
function encryptKey(key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    crypto.createHash("sha256").update(SESSION_SECRET).digest(),
    iv
  );
  const encrypted = Buffer.concat([cipher.update(String(key), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64url");
}

function decryptKey(value) {
  try {
    const data = Buffer.from(String(value), "base64url");
    const iv = data.subarray(0, 12);
    const tag = data.subarray(12, 28);
    const encrypted = data.subarray(28);
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      crypto.createHash("sha256").update(SESSION_SECRET).digest(),
      iv
    );
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
}

function makeKey() {
  const raw = crypto
    .randomBytes(18)
    .toString("base64url")
    .toUpperCase();

  const a = raw.slice(0, 6);
  const b = raw.slice(6, 12);
  const c = raw.slice(12, 18);

  return "X23-" + a + "-" + b + "-" + c;
}

function sessionToken() {
  const issuedAt = Date.now().toString();
  const nonce = crypto.randomBytes(24).toString("hex");
  const payload = issuedAt + "." + nonce;
  const signature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("hex");

  return payload + "." + signature;
}

function verifySessionToken(token) {
  try {
    const parts = String(token || "").split(".");
    if (parts.length !== 3) return false;

    const issuedAt = Number(parts[0]);
    if (!Number.isFinite(issuedAt)) return false;
    if (Date.now() - issuedAt > SESSION_TTL) return false;
    if (issuedAt > Date.now() + 60000) return false;

    const payload = parts[0] + "." + parts[1];
    const expected = crypto
      .createHmac("sha256", SESSION_SECRET)
      .update(payload)
      .digest("hex");

    const a = Buffer.from(parts[2]);
    const b = Buffer.from(expected);

    return a.length === b.length &&
      crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function hashAccessKey(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function makeAccessKey() {
  return "X23-" + crypto.randomBytes(18).toString("base64url").toUpperCase();
}

async function accessKeyMatches(input) {
  if (!input) return false;
  const raw = await getSetting("admin_access_keys", "[]");
  let list = [];
  try { list = JSON.parse(raw); } catch { list = []; }
  const hash = hashAccessKey(input);
  const found = list.find(x => x.hash === hash && !x.revoked);
  if (!found) return false;
  found.lastUsedAt = Date.now();
  await setSetting("admin_access_keys", JSON.stringify(list));
  return true;
}

function admin(req, res, next) {
  const token = req.headers["x-admin-token"];

  if (!verifySessionToken(token)) {
    return res.status(401).json({
      success: false,
      message: "Sesión expirada o no autorizada"
    });
  }

  next();
}

async function getSetting(key, fallback = null) {
  const result = await pool.query(
    "SELECT value FROM app_settings WHERE key = $1 LIMIT 1",
    [key]
  );
  return result.rows.length ? result.rows[0].value : fallback;
}

async function setSetting(key, value) {
  await pool.query(
    "INSERT INTO app_settings (key, value, updated_at) VALUES ($1,$2,$3) " +
    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
    [key, String(value), Date.now()]
  );
}

async function isApiEnabled() {
  return (await getSetting("api_enabled", "true")) === "true";
}

function passwordMatches(input) {
  const a = Buffer.from(String(input || ""));
  const b = Buffer.from(ADMIN_PASSWORD);

  return (
    a.length === b.length &&
    crypto.timingSafeEqual(a, b)
  );
}

// ============================================================
// BASE DE DATOS
// ============================================================

async function initDB() {
  const sqlKeys =
    "CREATE TABLE IF NOT EXISTS keys (" +
    "id UUID PRIMARY KEY," +
    "key_hash TEXT UNIQUE NOT NULL," +
    "type TEXT NOT NULL," +
    "created_at BIGINT NOT NULL," +
    "expires_at BIGINT," +
    "used_by TEXT," +
    "used_username TEXT," +
    "used_at BIGINT," +
    "revoked BOOLEAN NOT NULL DEFAULT FALSE" +
    ")";

  const sqlWhitelist =
    "CREATE TABLE IF NOT EXISTS whitelist (" +
    "roblox_user_id TEXT PRIMARY KEY," +
    "roblox_username TEXT," +
    "created_at BIGINT NOT NULL" +
    ")";

  const sqlLogs =
    "CREATE TABLE IF NOT EXISTS key_logs (" +
    "id UUID PRIMARY KEY," +
    "key_id UUID," +
    "roblox_user_id TEXT," +
    "roblox_username TEXT," +
    "action TEXT NOT NULL," +
    "success BOOLEAN NOT NULL DEFAULT FALSE," +
    "message TEXT," +
    "created_at BIGINT NOT NULL" +
    ")";

  const sqlTrial =
    "CREATE TABLE IF NOT EXISTS trial_uses (" +
    "id UUID PRIMARY KEY," +
    "key_id UUID NOT NULL," +
    "roblox_user_id TEXT NOT NULL," +
    "roblox_username TEXT," +
    "used_at BIGINT NOT NULL," +
    "UNIQUE(key_id, roblox_user_id)" +
    ")";

  const sqlSettings =
    "CREATE TABLE IF NOT EXISTS app_settings (" +
    "key TEXT PRIMARY KEY," +
    "value TEXT NOT NULL," +
    "updated_at BIGINT NOT NULL" +
    ")";

  await pool.query(sqlKeys);
  // Migración compatible con instalaciones existentes. Las keys antiguas no pueden
  // recuperarse porque históricamente solo se guardaba su hash. Las nuevas sí se
  // guardarán cifradas para poder mostrarlas en el panel administrativo.
  await pool.query("ALTER TABLE keys ADD COLUMN IF NOT EXISTS key_ciphertext TEXT");
  await pool.query(sqlWhitelist);
  await pool.query(sqlLogs);
  await pool.query(sqlTrial);
  await pool.query(sqlSettings);

  await pool.query(
    "INSERT INTO app_settings (key, value, updated_at) " +
    "VALUES ('api_enabled', 'true', $1) " +
    "ON CONFLICT (key) DO NOTHING",
    [Date.now()]
  );

  console.log("[DB] Base de datos inicializada correctamente");
}

// ============================================================
// LOGS
// ============================================================

async function writeKeyLog({
  keyId = null,
  robloxUserId = null,
  robloxUsername = null,
  action,
  success,
  message
}) {
  try {
    await pool.query(
      "INSERT INTO key_logs (" +
      "id, key_id, roblox_user_id, roblox_username, " +
      "action, success, message, created_at" +
      ") VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
      [
        crypto.randomUUID(),
        keyId,
        robloxUserId,
        robloxUsername,
        action,
        success,
        message,
        Date.now()
      ]
    );
  } catch (error) {
    console.error("[LOG] Error:", error);
  }
}

// ============================================================
// HEALTH
// ============================================================

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: true,
      service: "roblox-key-api",
      apiEnabled: await isApiEnabled()
    });
  } catch (error) {
    res.status(503).json({
      ok: false,
      database: false,
      service: "roblox-key-api"
    });
  }
});

// ============================================================
// LOGIN ADMIN
// ============================================================

app.post("/api/admin/login", async (req, res) => {
  try {
    const credential = String(req.body?.password || "");
    const validPassword = passwordMatches(credential);
    const validAccessKey = !validPassword && await accessKeyMatches(credential);

    if (!validPassword && !validAccessKey) {
      return res.status(401).json({
        success: false,
        message: "Contraseña o key de acceso incorrecta"
      });
    }

    const token = sessionToken();

    res.json({
      success: true,
      token,
      expiresAt: Date.now() + SESSION_TTL
    });
  } catch (error) {
    console.error("Error de login:", error);
    res.status(500).json({ success: false, message: "No se pudo iniciar sesión" });
  }
});

// ============================================================
// LOGOUT
// ============================================================

app.post("/api/admin/logout", admin, (req, res) => {
  res.json({
    success: true
  });
});

// ============================================================
// KEYS DE ACCESO DEL PANEL
// ============================================================

app.get("/api/admin/access-keys", admin, async (req, res) => {
  try {
    const raw = await getSetting("admin_access_keys", "[]");
    let list = [];
    try { list = JSON.parse(raw); } catch { list = []; }
    res.json({
      keys: list.filter(x => !x.revoked).map(x => ({
        id: x.id,
        createdAt: x.createdAt,
        lastUsedAt: x.lastUsedAt || null
      }))
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "No se pudieron cargar las keys de acceso" });
  }
});

app.post("/api/admin/access-keys", admin, async (req, res) => {
  try {
    const raw = await getSetting("admin_access_keys", "[]");
    let list = [];
    try { list = JSON.parse(raw); } catch { list = []; }
    const createdKey = makeAccessKey();
    const item = {
      id: crypto.randomUUID(),
      hash: hashAccessKey(createdKey),
      createdAt: Date.now(),
      lastUsedAt: null,
      revoked: false
    };
    list.push(item);
    await setSetting("admin_access_keys", JSON.stringify(list));
    res.json({ success: true, createdKey, keys: list.filter(x => !x.revoked).map(x => ({ id: x.id, createdAt: x.createdAt, lastUsedAt: x.lastUsedAt || null })) });
  } catch (error) {
    res.status(500).json({ success: false, message: "No se pudo crear la key de acceso" });
  }
});

app.delete("/api/admin/access-keys/:id", admin, async (req, res) => {
  try {
    const raw = await getSetting("admin_access_keys", "[]");
    let list = [];
    try { list = JSON.parse(raw); } catch { list = []; }
    const item = list.find(x => x.id === req.params.id);
    if (!item) return res.status(404).json({ success: false, message: "Key de acceso no encontrada" });
    item.revoked = true;
    await setSetting("admin_access_keys", JSON.stringify(list));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: "No se pudo revocar la key de acceso" });
  }
});

// ============================================================
// MÚSICA DEL PANEL
// ============================================================

app.get("/api/admin/music", admin, async (req, res) => {
  try {
    res.json({ url: await getSetting("panel_music_url", "") });
  } catch {
    res.status(500).json({ success: false, message: "No se pudo cargar la música" });
  }
});

app.post("/api/admin/music", admin, async (req, res) => {
  try {
    const url = String(req.body?.url || "").trim();
    if (url && !/^https?:\/\//i.test(url)) {
      return res.status(400).json({ success: false, message: "La URL debe comenzar con http:// o https://" });
    }
    await setSetting("panel_music_url", url);
    res.json({ success: true, url });
  } catch {
    res.status(500).json({ success: false, message: "No se pudo guardar la música" });
  }
});

// ============================================================
// GENERAR KEYS
// ============================================================

app.post(
  "/api/admin/keys/generate",
  admin,
  async (req, res) => {
    try {
      const type = String(
        req.body?.type || "hours"
      ).toLowerCase();

      const amount = Math.max(
        1,
        Math.min(
          100,
          Number(req.body?.amount || 1)
        )
      );

      const units = {
        minutes: 60000,
        hours: 3600000,
        days: 86400000,
        weeks: 604800000,
        months: 2592000000
      };

      const permanent =
        type === "permanent" ||
        type === "perm";

      if (!permanent && !units[type]) {
        return res.status(400).json({
          success: false,
          message: "Duración inválida"
        });
      }

      /*
       * IMPORTANTE:
       *
       * expiresAt se calcula UNA SOLA VEZ al crear
       * la key.
       *
       * Volver a validar la key NO cambia esta fecha.
       */

      const createdAt = Date.now();

      const expiresAt = permanent
        ? null
        : createdAt + units[type];

      const generated = [];

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        for (let i = 0; i < amount; i++) {
          let key;
          let inserted = false;

          while (!inserted) {
            key = makeKey();

            try {
              await client.query(
                "INSERT INTO keys (" +
                "id, key_hash, key_ciphertext, type, created_at, expires_at" +
                ") VALUES ($1,$2,$3,$4,$5,$6)",
                [
                  crypto.randomUUID(),
                  hashKey(key),
                  encryptKey(key),
                  permanent ? "permanent" : type,
                  createdAt,
                  expiresAt
                ]
              );

              inserted = true;
            } catch (error) {
              if (error.code === "23505") {
                continue;
              }

              throw error;
            }
          }

          generated.push({
            key,
            type: permanent ? "permanent" : type,
            createdAt,
            expiresAt
          });
        }

        await client.query("COMMIT");

        res.json({
          success: true,
          keys: generated
        });
      } catch (error) {
        await client.query("ROLLBACK");

        console.error(
          "Error generando keys:",
          error
        );

        res.status(500).json({
          success: false,
          message: "No se pudieron generar las keys"
        });
      } finally {
        client.release();
      }
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Error interno"
      });
    }
  }
);

// ============================================================
// GENERAR KEY PERSONALIZADA
// ============================================================

app.post(
  "/api/admin/keys/generate-custom",
  admin,
  async (req, res) => {
    try {
      const customKey = String(req.body?.key || "")
        .trim()
        .toUpperCase();

      const type = String(req.body?.type || "hours").toLowerCase();

      const units = {
        minutes: 60000,
        hours: 3600000,
        days: 86400000,
        weeks: 604800000,
        months: 2592000000
      };

      const permanent = type === "permanent" || type === "perm";

      if (!/^[A-Z0-9_-]{3,80}$/.test(customKey)) {
        return res.status(400).json({
          success: false,
          message: "La key personalizada debe tener entre 3 y 80 caracteres y solo usar letras, números, guiones o guiones bajos."
        });
      }

      if (!permanent && !units[type]) {
        return res.status(400).json({
          success: false,
          message: "Duración inválida"
        });
      }

      const createdAt = Date.now();
      const expiresAt = permanent ? null : createdAt + units[type];
      const id = crypto.randomUUID();

      try {
        await pool.query(
          "INSERT INTO keys (id, key_hash, key_ciphertext, type, created_at, expires_at) " +
          "VALUES ($1,$2,$3,$4,$5,$6)",
          [
            id,
            hashKey(customKey),
            encryptKey(customKey),
            permanent ? "permanent" : type,
            createdAt,
            expiresAt
          ]
        );
      } catch (error) {
        if (error.code === "23505") {
          return res.status(409).json({
            success: false,
            message: "Esa key ya existe. Elige otra key personalizada."
          });
        }
        throw error;
      }

      res.json({
        success: true,
        key: {
          id,
          key: customKey,
          type: permanent ? "permanent" : type,
          createdAt,
          expiresAt
        }
      });
    } catch (error) {
      console.error("Error generando key personalizada:", error);
      res.status(500).json({
        success: false,
        message: "No se pudo generar la key personalizada"
      });
    }
  }
);

// ============================================================
// LISTAR KEYS
// ============================================================

app.get(
  "/api/admin/keys",
  admin,
  async (req, res) => {
    try {
      const result = await pool.query(
        "SELECT " +
        "id, type, created_at, expires_at, " +
        "key_ciphertext, used_by, used_username, used_at, revoked " +
        "FROM keys ORDER BY created_at DESC"
      );

      res.json({
        success: true,

        keys: result.rows.map(function (k) {
          return {
            id: k.id,

            key: decryptKey(k.key_ciphertext),

            type: k.type,

            createdAt: Number(k.created_at),

            expiresAt:
              k.expires_at === null
                ? null
                : Number(k.expires_at),

            usedBy: k.used_by,

            usedUsername: k.used_username,

            usedAt:
              k.used_at === null
                ? null
                : Number(k.used_at),

            revoked: k.revoked,

            expired:
              !k.revoked &&
              k.expires_at !== null &&
              Number(k.expires_at) <= Date.now()
          };
        })
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "No se pudieron obtener las keys"
      });
    }
  }
);

// ============================================================
// REVOCAR KEY
// ============================================================

app.post(
  "/api/admin/keys/:id/revoke",
  admin,
  async (req, res) => {
    try {
      const result = await pool.query(
        "UPDATE keys SET revoked = TRUE WHERE id = $1",
        [req.params.id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          success: false,
          message: "Key no encontrada"
        });
      }

      res.json({
        success: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "No se pudo revocar la key"
      });
    }
  }
);

// ============================================================
// ACTIVAR KEY
// ============================================================

app.post(
  "/api/admin/keys/:id/activate",
  admin,
  async (req, res) => {
    try {
      const result = await pool.query(
        "UPDATE keys SET revoked = FALSE WHERE id = $1 RETURNING id",
        [req.params.id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          success: false,
          message: "Key no encontrada"
        });
      }

      await writeKeyLog({
        keyId: req.params.id,
        action: "activate",
        success: true,
        message: "Key activada por administrador"
      });

      res.json({ success: true });
    } catch (error) {
      console.error(error);
      res.status(500).json({
        success: false,
        message: "No se pudo activar la key"
      });
    }
  }
);

// ============================================================
// EXTENDER KEY
// ============================================================

app.post(
  "/api/admin/keys/:id/extend",
  admin,
  async (req, res) => {
    try {
      const days = Math.max(
        1,
        Math.min(3650, Number(req.body?.days || 1))
      );

      if (!Number.isFinite(days)) {
        return res.status(400).json({
          success: false,
          message: "Cantidad de días inválida"
        });
      }

      const result = await pool.query(
        "SELECT id, type, expires_at, revoked FROM keys WHERE id = $1 LIMIT 1",
        [req.params.id]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message: "Key no encontrada"
        });
      }

      const key = result.rows[0];

      if (key.type === "permanent" || key.expires_at === null) {
        return res.status(400).json({
          success: false,
          message: "La key ya es permanente"
        });
      }

      const currentExpiry = Number(key.expires_at);
      const base = Math.max(currentExpiry, Date.now());
      const newExpiry = base + days * 86400000;

      await pool.query(
        "UPDATE keys SET expires_at = $1 WHERE id = $2",
        [newExpiry, req.params.id]
      );

      await writeKeyLog({
        keyId: req.params.id,
        action: "extend",
        success: true,
        message: "Key extendida " + days + " día(s)"
      });

      res.json({
        success: true,
        days,
        expiresAt: newExpiry
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({
        success: false,
        message: "No se pudo extender la key"
      });
    }
  }
);

// ============================================================
// ELIMINAR TODAS LAS KEYS REVOCADAS
// ============================================================
app.delete(
  "/api/admin/keys/revoked",
  admin,
  async (req, res) => {
    try {
      const result = await pool.query("DELETE FROM keys WHERE revoked = TRUE");
      res.json({ success: true, deleted: result.rowCount });
    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, message: "No se pudieron eliminar las keys revocadas" });
    }
  }
);

// ============================================================
// ELIMINAR KEY
// ============================================================

app.delete(
  "/api/admin/keys/:id",
  admin,
  async (req, res) => {
    try {
      const result = await pool.query(
        "DELETE FROM keys WHERE id = $1",
        [req.params.id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          success: false,
          message: "Key no encontrada"
        });
      }

      res.json({
        success: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "No se pudo eliminar la key"
      });
    }
  }
);

// ============================================================
// VALIDAR KEY
// ============================================================

app.post(
  "/api/keys/validate",
  async (req, res) => {
    try {
      if (!(await isApiEnabled())) {
        return res.status(503).json({
          valid: false,
          permanent: false,
          apiEnabled: false,
          message: "La API está temporalmente desactivada"
        });
      }

      const code = String(
        req.body?.code || ""
      ).trim();

      const userId = String(
        req.body?.userId || ""
      ).trim();

      const username = String(
        req.body?.username || userId
      ).trim();

      if (!code) {
        return res.json({
          valid: false,
          permanent: false,
          message: "Key vacía"
        });
      }

      if (!userId) {
        return res.json({
          valid: false,
          permanent: false,
          message: "Usuario de Roblox requerido"
        });
      }

      /*
       * ========================================================
       * IMPORTANTE:
       *
       * YA NO SE CONSULTA LA WHITELIST.
       *
       * CUALQUIER USUARIO PUEDE VALIDAR UNA KEY VÁLIDA.
       * ========================================================
       */

      const keyResult = await pool.query(
        "SELECT * FROM keys " +
        "WHERE key_hash = $1 LIMIT 1",
        [hashKey(code)]
      );

      if (!keyResult.rows.length) {
        await writeKeyLog({
          robloxUserId: userId,
          robloxUsername: username,
          action: "validate",
          success: false,
          message: "Key inválida"
        });

        return res.json({
          valid: false,
          permanent: false,
          whitelisted: true,
          message: "Key inválida"
        });
      }

      const key = keyResult.rows[0];

      // ========================================================
      // KEY REVOCADA
      // ========================================================

      if (key.revoked) {
        await writeKeyLog({
          keyId: key.id,
          robloxUserId: userId,
          robloxUsername: username,
          action: "validate",
          success: false,
          message: "Key revocada"
        });

        return res.json({
          valid: false,
          permanent: false,
          message: "Key revocada"
        });
      }

      // ========================================================
      // EXPIRACIÓN
      // ========================================================

      /*
       * SOLO COMPROBAMOS expires_at.
       *
       * NUNCA hacemos:
       *
       * key.expires_at = Date.now() + ...
       *
       * ni UPDATE de expires_at.
       *
       * Por eso volver a poner la key NO reinicia
       * el contador.
       */

      if (
        key.expires_at !== null &&
        Number(key.expires_at) <= Date.now()
      ) {
        await writeKeyLog({
          keyId: key.id,
          robloxUserId: userId,
          robloxUsername: username,
          action: "validate",
          success: false,
          message: "Key expirada"
        });

        return res.json({
          valid: false,
          permanent: false,
          expired: true,
          message: "Key expirada"
        });
      }

      // ========================================================
      // TRIAL
      // ========================================================

      if (key.type === "trial") {
        const used = await pool.query(
          "SELECT id FROM trial_uses " +
          "WHERE key_id = $1 " +
          "AND roblox_user_id = $2 LIMIT 1",
          [key.id, userId]
        );

        if (used.rows.length) {
          return res.json({
            valid: false,
            permanent: false,
            trial: true,
            message:
              "Ya utilizaste tu key de prueba."
          });
        }

        await pool.query(
          "INSERT INTO trial_uses (" +
          "id, key_id, roblox_user_id, " +
          "roblox_username, used_at" +
          ") VALUES ($1,$2,$3,$4,$5)",
          [
            crypto.randomUUID(),
            key.id,
            userId,
            username,
            Date.now()
          ]
        );

        await writeKeyLog({
          keyId: key.id,
          robloxUserId: userId,
          robloxUsername: username,
          action: "trial",
          success: true,
          message: "Trial activada"
        });

        return res.json({
          valid: true,
          permanent: false,
          trial: true,
          message: "Key de prueba activada",

          /*
           * Esta es la fecha original.
           * No se modifica.
           */
          expiresAt:
            key.expires_at === null
              ? null
              : Number(key.expires_at)
        });
      }

      // ========================================================
      // KEY VINCULADA A OTRO USUARIO
      // ========================================================

      if (
        key.used_by &&
        String(key.used_by) !== userId
      ) {
        return res.json({
          valid: false,
          permanent: false,
          message:
            "Esta key ya está vinculada a otro usuario"
        });
      }

      // ========================================================
      // PRIMER USO
      // ========================================================

      /*
       * Solo guardamos quién utilizó la key.
       *
       * IMPORTANTE:
       * NO tocamos expires_at.
       */

      if (!key.used_by) {
        await pool.query(
          "UPDATE keys SET " +
          "used_by = $1, " +
          "used_username = $2, " +
          "used_at = $3 " +
          "WHERE id = $4",
          [
            userId,
            username,
            Date.now(),
            key.id
          ]
        );
      }

      await writeKeyLog({
        keyId: key.id,
        robloxUserId: userId,
        robloxUsername: username,
        action: "validate",
        success: true,
        message: "Key válida"
      });

      return res.json({
        valid: true,

        permanent:
          key.type === "permanent",

        trial: false,

        message: "Key válida",

        /*
         * ESTA FECHA ES LA MISMA QUE SE GUARDÓ
         * CUANDO SE CREÓ LA KEY.
         */
        expiresAt:
          key.expires_at === null
            ? null
            : Number(key.expires_at)
      });

    } catch (error) {
      console.error(
        "Error validando key:",
        error
      );

      res.status(500).json({
        valid: false,
        permanent: false,
        message: "Error interno del servidor"
      });
    }
  }
);

// ============================================================
// WHITELIST CHECK
// ============================================================

app.post(
  "/api/whitelist/check",
  async (req, res) => {
    /*
     * La whitelist ya no es necesaria para validar keys.
     * Se mantiene este endpoint para evitar romper
     * tu script actual de Roblox.
     */

    const userId = String(
      req.body?.robloxUserId || ""
    ).trim();

    res.json({
      whitelisted: true,
      username: userId || null
    });
  }
);

// ============================================================
// AGREGAR WHITELIST
// ============================================================

app.post(
  "/api/whitelist",
  admin,
  async (req, res) => {
    try {
      const id = String(
        req.body?.robloxUserId || ""
      ).trim();

      const username = String(
        req.body?.robloxUsername || id
      ).trim();

      if (!id) {
        return res.status(400).json({
          success: false,
          message: "User ID requerido"
        });
      }

      await pool.query(
        "INSERT INTO whitelist (" +
        "roblox_user_id, roblox_username, created_at" +
        ") VALUES ($1,$2,$3) " +
        "ON CONFLICT (roblox_user_id) " +
        "DO UPDATE SET roblox_username = EXCLUDED.roblox_username",
        [
          id,
          username,
          Date.now()
        ]
      );

      res.json({
        success: true,
        message: "Usuario agregado"
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "No se pudo agregar el usuario"
      });
    }
  }
);

// ============================================================
// LISTAR WHITELIST
// ============================================================

app.get(
  "/api/whitelist",
  admin,
  async (req, res) => {
    try {
      const result = await pool.query(
        "SELECT roblox_user_id, " +
        "roblox_username, created_at " +
        "FROM whitelist " +
        "ORDER BY created_at DESC"
      );

      res.json(
        result.rows.map(function (x) {
          return {
            robloxUserId:
              x.roblox_user_id,

            robloxUsername:
              x.roblox_username,

            createdAt:
              Number(x.created_at)
          };
        })
      );
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "No se pudo obtener la whitelist"
      });
    }
  }
);

// ============================================================
// ELIMINAR WHITELIST
// ============================================================

app.delete(
  "/api/admin/whitelist/:userId",
  admin,
  async (req, res) => {
    try {
      const result = await pool.query(
        "DELETE FROM whitelist " +
        "WHERE roblox_user_id = $1",
        [String(req.params.userId)]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          success: false,
          message: "Usuario no encontrado"
        });
      }

      res.json({
        success: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "No se pudo eliminar el usuario"
      });
    }
  }
);

// ============================================================
// API CONTROL
// ============================================================

app.get(
  "/api/admin/api-status",
  admin,
  async (req, res) => {
    try {
      res.json({
        success: true,
        enabled: await isApiEnabled()
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({
        success: false,
        message: "No se pudo obtener el estado de la API"
      });
    }
  }
);

app.post(
  "/api/admin/api-status",
  admin,
  async (req, res) => {
    try {
      const enabled = Boolean(req.body?.enabled);
      await setSetting("api_enabled", enabled ? "true" : "false");

      await writeKeyLog({
        action: enabled ? "api_on" : "api_off",
        success: true,
        message: enabled
          ? "API activada por administrador"
          : "API desactivada por administrador"
      });

      res.json({
        success: true,
        enabled
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({
        success: false,
        message: "No se pudo cambiar el estado de la API"
      });
    }
  }
);

// ============================================================
// STATS
// ============================================================

app.get(
  "/api/admin/stats",
  admin,
  async (req, res) => {
    try {
      const keys = await pool.query(
        "SELECT COUNT(*)::int AS count " +
        "FROM keys"
      );

      const active = await pool.query(
        "SELECT COUNT(*)::int AS count " +
        "FROM keys " +
        "WHERE revoked = FALSE " +
        "AND (" +
        "expires_at IS NULL " +
        "OR expires_at > $1" +
        ")",
        [Date.now()]
      );

      const revoked = await pool.query(
        "SELECT COUNT(*)::int AS count " +
        "FROM keys " +
        "WHERE revoked = TRUE"
      );

      const whitelist = await pool.query(
        "SELECT COUNT(*)::int AS count " +
        "FROM whitelist"
      );

      const logs = await pool.query(
        "SELECT COUNT(*)::int AS count " +
        "FROM key_logs"
      );

      res.json({
        success: true,

        totalKeys:
          keys.rows[0].count,

        activeKeys:
          active.rows[0].count,

        revokedKeys:
          revoked.rows[0].count,

        whitelistUsers:
          whitelist.rows[0].count,

        totalLogs:
          logs.rows[0].count
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Error obteniendo estadísticas"
      });
    }
  }
);

// ============================================================
// LOGS
// ============================================================

app.get(
  "/api/admin/logs",
  admin,
  async (req, res) => {
    try {
      const limit = Math.max(
        1,
        Math.min(
          200,
          Number(req.query.limit || 100)
        )
      );

      const result = await pool.query(
        "SELECT " +
        "id, key_id, roblox_user_id, " +
        "roblox_username, action, success, " +
        "message, created_at " +
        "FROM key_logs " +
        "ORDER BY created_at DESC " +
        "LIMIT $1",
        [limit]
      );

      res.json({
        success: true,

        logs: result.rows.map(function (x) {
          return {
            id: x.id,

            keyId: x.key_id,

            robloxUserId:
              x.roblox_user_id,

            robloxUsername:
              x.roblox_username,

            action:
              x.action,

            success:
              x.success,

            message:
              x.message,

            createdAt:
              Number(x.created_at)
          };
        })
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "No se pudieron obtener los logs"
      });
    }
  }
);

// ============================================================
// TRIAL
// ============================================================

async function ensureTrialKey() {
  const configuredKey =
    process.env.TEST_KEY ||
    "X23-TRIAL-30MIN";

  const existing = await pool.query(
    "SELECT id FROM keys " +
    "WHERE key_hash = $1 LIMIT 1",
    [hashKey(configuredKey)]
  );

  /*
   * Si ya existe, NO se crea otra.
   *
   * Esto también evita reiniciar el contador
   * de la trial después de reiniciar Render.
   */

  if (existing.rows.length) {
    return;
  }

  const createdAt = Date.now();

  await pool.query(
    "INSERT INTO keys (" +
    "id, key_hash, type, created_at, expires_at" +
    ") VALUES ($1,$2,$3,$4,$5)",
    [
      crypto.randomUUID(),

      hashKey(configuredKey),

      "trial",

      createdAt,

      createdAt + 30 * 60 * 1000
    ]
  );

  console.log("[TRIAL] Key creada");
}

// ============================================================
// OBTENER TRIAL
// ============================================================

app.get(
  "/api/trial",
  async (req, res) => {
    try {
      const configuredKey =
        process.env.TEST_KEY ||
        "X23-TRIAL-30MIN";

      const result = await pool.query(
        "SELECT type, created_at, " +
        "expires_at, revoked " +
        "FROM keys " +
        "WHERE key_hash = $1 LIMIT 1",
        [hashKey(configuredKey)]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message:
            "Key de prueba no disponible"
        });
      }

      const key = result.rows[0];

      res.json({
        success: true,

        key: configuredKey,

        type: "trial",

        createdAt:
          Number(key.created_at),

        expiresAt:
          key.expires_at === null
            ? null
            : Number(key.expires_at),

        revoked:
          key.revoked,

        expired:
          !key.revoked &&
          key.expires_at !== null &&
          Number(key.expires_at) <= Date.now()
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "No se pudo obtener la trial"
      });
    }
  }
);

// ============================================================
// FRONTEND
// ============================================================

app.use(function (req, res, next) {
  if (
    req.method === "GET" &&
    !req.path.startsWith("/api/")
  ) {
    return res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }

  next();
});

// ============================================================
// INICIAR SERVIDOR
// ============================================================

async function startServer() {
  try {
    await initDB();

    await ensureTrialKey();

    app.listen(
      PORT,
      "0.0.0.0",
      function () {
        console.log(
          "[SERVER] API escuchando en puerto " +
          PORT
        );

        console.log(
          "[SERVER] Base de datos: CONECTADA"
        );

        console.log(
          "[SERVER] Whitelist: NO OBLIGATORIA"
        );

        console.log(
          "[SERVER] Logs de keys: ACTIVADOS"
        );

        console.log(
          "[SERVER] Trial: ACTIVADA"
        );

        console.log(
          "[SERVER] Tiempo de keys: FIJO"
        );

        console.log(
          "[SERVER] Validar nuevamente NO reinicia el tiempo"
        );
      }
    );

  } catch (error) {
    console.error(
      "[SERVER] No se pudo inicializar la DB:"
    );

    console.error(error);

    process.exit(1);
  }
}

startServer();
