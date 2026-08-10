```js
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

// ============================================================
// CONFIGURACIÓN
// ============================================================

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Yerim";

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.randomBytes(32).toString("hex");

// ============================================================
// DATABASE
// ============================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

// Sesiones de administrador
const sessions = new Map();

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(express.json({ limit: "100kb" }));

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

// ============================================================
// DATABASE INIT
// ============================================================

async function initDB() {
  const createKeysTable = [
    "CREATE TABLE IF NOT EXISTS keys (",
    "id UUID PRIMARY KEY,",
    "key_hash TEXT UNIQUE NOT NULL,",
    "type TEXT NOT NULL,",
    "created_at BIGINT NOT NULL,",
    "expires_at BIGINT,",
    "used_by TEXT,",
    "used_username TEXT,",
    "used_at BIGINT,",
    "revoked BOOLEAN NOT NULL DEFAULT FALSE",
    ")"
  ].join("\n");

  const createWhitelistTable = [
    "CREATE TABLE IF NOT EXISTS whitelist (",
    "roblox_user_id TEXT PRIMARY KEY,",
    "roblox_username TEXT,",
    "created_at BIGINT NOT NULL",
    ")"
  ].join("\n");

  await pool.query(createKeysTable);
  await pool.query(createWhitelistTable);

  console.log("Base de datos inicializada correctamente");
}

// ============================================================
// KEY FUNCTIONS
// ============================================================

function hashKey(key) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(String(key).trim().toUpperCase())
    .digest("hex");
}

function makeKey() {
  const raw = crypto
    .randomBytes(18)
    .toString("base64url")
    .toUpperCase();

  const part1 = raw.slice(0, 6);
  const part2 = raw.slice(6, 12);
  const part3 = raw.slice(12, 18);

  return "X23-" + part1 + "-" + part2 + "-" + part3;
}

function sessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

// ============================================================
// ADMIN AUTH
// ============================================================

function admin(req, res, next) {
  const token = req.headers["x-admin-token"];

  if (!token || !sessions.has(token)) {
    return res.status(401).json({
      success: false,
      message: "No autorizado"
    });
  }

  next();
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
// HEALTH
// ============================================================

app.get("/health", function (req, res) {
  res.json({
    ok: true,
    service: "roblox-key-api"
  });
});

// ============================================================
// ADMIN LOGIN
// ============================================================

app.post("/api/admin/login", function (req, res) {
  if (!passwordMatches(req.body?.password)) {
    return res.status(401).json({
      success: false,
      message: "Contraseña incorrecta"
    });
  }

  const token = sessionToken();

  sessions.set(token, {
    createdAt: Date.now()
  });

  res.json({
    success: true,
    token: token
  });
});

// ============================================================
// ADMIN LOGOUT
// ============================================================

app.post("/api/admin/logout", admin, function (req, res) {
  const token = req.headers["x-admin-token"];

  sessions.delete(token);

  res.json({
    success: true
  });
});

// ============================================================
// GENERAR KEYS
// ============================================================

app.post(
  "/api/admin/keys/generate",
  admin,
  async function (req, res) {
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

      const createdAt = Date.now();

      const expiresAt = permanent
        ? null
        : createdAt + units[type];

      const generated = [];

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        for (let i = 0; i < amount; i++) {
          const key = makeKey();

          const insertQuery = [
            "INSERT INTO keys",
            "(id, key_hash, type, created_at, expires_at)",
            "VALUES ($1, $2, $3, $4, $5)"
          ].join(" ");

          await client.query(
            insertQuery,
            [
              crypto.randomUUID(),
              hashKey(key),
              permanent ? "permanent" : type,
              createdAt,
              expiresAt
            ]
          );

          generated.push({
            key: key,
            type: permanent
              ? "permanent"
              : type,
            expiresAt: expiresAt
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
// LISTAR KEYS
// ============================================================

app.get(
  "/api/admin/keys",
  admin,
  async function (req, res) {
    try {
      const result = await pool.query(
        [
          "SELECT",
          "id,",
          "type,",
          "created_at,",
          "expires_at,",
          "used_by,",
          "used_username,",
          "used_at,",
          "revoked",
          "FROM keys",
          "ORDER BY created_at DESC"
        ].join(" ")
      );

      res.json({
        success: true,
        keys: result.rows.map(function (k) {
          return {
            id: k.id,
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
  async function (req, res) {
    try {
      const result = await pool.query(
        "UPDATE keys SET revoked=TRUE WHERE id=$1",
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
// ELIMINAR KEY
// ============================================================

app.delete(
  "/api/admin/keys/:id",
  admin,
  async function (req, res) {
    try {
      const result = await pool.query(
        "DELETE FROM keys WHERE id=$1",
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
// IMPORTANTE:
// Una key válida SIEMPRE necesita whitelist.
// ============================================================

app.post(
  "/api/keys/validate",
  async function (req, res) {
    try {
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

      // --------------------------------------------------------
      // PRIMERO: comprobar whitelist
      // --------------------------------------------------------

      const whitelistResult = await pool.query(
        [
          "SELECT roblox_user_id, roblox_username",
          "FROM whitelist",
          "WHERE roblox_user_id=$1"
        ].join(" "),
        [userId]
      );

      if (!whitelistResult.rows.length) {
        return res.json({
          valid: false,
          permanent: false,
          whitelisted: false,
          message:
            "NO TE ENCUENTRAS EN WHITELIST CONTACTATE CON EL VENDEDOR EH ADMIN PARA PODER ACCEDER"
        });
      }

      // --------------------------------------------------------
      // SEGUNDO: comprobar key
      // --------------------------------------------------------

      const keyResult = await pool.query(
        [
          "SELECT * FROM keys",
          "WHERE key_hash=$1",
          "LIMIT 1"
        ].join(" "),
        [hashKey(code)]
      );

      if (!keyResult.rows.length) {
        return res.json({
          valid: false,
          permanent: false,
          whitelisted: true,
          message: "Key inválida"
        });
      }

      const k = keyResult.rows[0];

      // --------------------------------------------------------
      // KEY REVOCADA
      // --------------------------------------------------------

      if (k.revoked) {
        return res.json({
          valid: false,
          permanent: false,
          whitelisted: true,
          message: "Key revocada"
        });
      }

      // --------------------------------------------------------
      // KEY EXPIRADA
      // --------------------------------------------------------

      if (
        k.expires_at !== null &&
        Number(k.expires_at) <= Date.now()
      ) {
        return res.json({
          valid: false,
          permanent: false,
          whitelisted: true,
          message: "Key expirada"
        });
      }

      // --------------------------------------------------------
      // KEY YA VINCULADA A OTRO USUARIO
      // --------------------------------------------------------

      if (
        k.used_by &&
        String(k.used_by) !== userId
      ) {
        return res.json({
          valid: false,
          permanent: false,
          whitelisted: true,
          message:
            "Esta key ya está vinculada a otro usuario"
        });
      }

      // --------------------------------------------------------
      // VINCULAR KEY AL USUARIO
      // --------------------------------------------------------

      if (!k.used_by) {
        await pool.query(
          [
            "UPDATE keys",
            "SET used_by=$1,",
            "used_username=$2,",
            "used_at=$3",
            "WHERE id=$4"
          ].join(" "),
          [
            userId,
            username,
            Date.now(),
            k.id
          ]
        );
      }

      // --------------------------------------------------------
      // KEY CORRECTA
      // --------------------------------------------------------

      res.json({
        valid: true,
        permanent:
          k.type === "permanent",
        whitelisted: true,
        message: "Key válida",
        expiresAt:
          k.expires_at === null
            ? null
            : Number(k.expires_at)
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
  async function (req, res) {
    try {
      const robloxUserId = String(
        req.body?.robloxUserId || ""
      ).trim();

      if (!robloxUserId) {
        return res.json({
          whitelisted: false,
          username: null
        });
      }

      const result = await pool.query(
        [
          "SELECT roblox_user_id, roblox_username",
          "FROM whitelist",
          "WHERE roblox_user_id=$1"
        ].join(" "),
        [robloxUserId]
      );

      res.json({
        whitelisted:
          result.rows.length > 0,

        username:
          result.rows[0]?.roblox_username ||
          null
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        whitelisted: false,
        username: null
      });
    }
  }
);

// ============================================================
// AGREGAR A WHITELIST
// ============================================================

app.post(
  "/api/whitelist",
  async function (req, res) {
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
        [
          "INSERT INTO whitelist",
          "(roblox_user_id, roblox_username, created_at)",
          "VALUES ($1, $2, $3)",
          "ON CONFLICT (roblox_user_id)",
          "DO UPDATE SET",
          "roblox_username=EXCLUDED.roblox_username"
        ].join(" "),
        [
          id,
          username,
          Date.now()
        ]
      );

      res.json({
        success: true,
        message:
          "✓ " +
          username +
          " agregado a la whitelist"
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "No se pudo agregar a la whitelist"
      });
    }
  }
);

// ============================================================
// LISTAR WHITELIST
// ============================================================

app.get(
  "/api/whitelist",
  async function (req, res) {
    try {
      const result = await pool.query(
        [
          "SELECT",
          "roblox_user_id,",
          "roblox_username,",
          "created_at",
          "FROM whitelist",
          "ORDER BY created_at DESC"
        ].join(" ")
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
// ELIMINAR DE WHITELIST
// ============================================================

app.delete(
  "/api/admin/whitelist/:userId",
  admin,
  async function (req, res) {
    try {
      const result = await pool.query(
        "DELETE FROM whitelist WHERE roblox_user_id=$1",
        [String(req.params.userId)]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          success: false,
          message:
            "Usuario no encontrado"
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
// STATS
// ============================================================

app.get(
  "/api/admin/stats",
  admin,
  async function (req, res) {
    try {
      const keysResult = await pool.query(
        "SELECT COUNT(*)::int AS count FROM keys"
      );

      const activeResult = await pool.query(
        [
          "SELECT COUNT(*)::int AS count",
          "FROM keys",
          "WHERE revoked=FALSE",
          "AND (expires_at IS NULL OR expires_at > $1)"
        ].join(" "),
        [Date.now()]
      );

      const revokedResult = await pool.query(
        [
          "SELECT COUNT(*)::int AS count",
          "FROM keys",
          "WHERE revoked=TRUE"
        ].join(" ")
      );

      const whitelistResult = await pool.query(
        "SELECT COUNT(*)::int AS count FROM whitelist"
      );

      res.json({
        success: true,

        totalKeys:
          keysResult.rows[0].count,

        activeKeys:
          activeResult.rows[0].count,

        revokedKeys:
          revokedResult.rows[0].count,

        whitelistUsers:
          whitelistResult.rows[0].count
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Error obteniendo estadísticas"
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
// START SERVER
// ============================================================

initDB()
  .then(function () {
    app.listen(
      PORT,
      "0.0.0.0",
      function () {
        console.log(
          "API escuchando en puerto " +
          PORT
        );

        console.log(
          "Whitelist obligatoria: ACTIVADA"
        );
      }
    );
  })
  .catch(function (error) {
    console.error(
      "No se pudo inicializar la DB:",
      error
    );

    process.exit(1);
  });
```
