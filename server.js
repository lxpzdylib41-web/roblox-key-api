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

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  console.error("ERROR: DATABASE_URL NO ESTÁ CONFIGURADA");
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

// ============================================================
// SESIONES
// ============================================================

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
// BASE DE DATOS
// ============================================================

async function initDB() {
  const createKeysTable = `
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
  `;

  const createWhitelistTable = `
    CREATE TABLE IF NOT EXISTS whitelist (
      roblox_user_id TEXT PRIMARY KEY,
      roblox_username TEXT,
      created_at BIGINT NOT NULL
    );
  `;

  const createLogsTable = `
    CREATE TABLE IF NOT EXISTS key_logs (
      id UUID PRIMARY KEY,
      key_id UUID,
      roblox_user_id TEXT,
      roblox_username TEXT,
      action TEXT NOT NULL,
      success BOOLEAN NOT NULL DEFAULT FALSE,
      message TEXT,
      created_at BIGINT NOT NULL
    );
  `;

  const createTrialTable = `
    CREATE TABLE IF NOT EXISTS trial_uses (
      id UUID PRIMARY KEY,
      key_id UUID NOT NULL,
      roblox_user_id TEXT NOT NULL,
      roblox_username TEXT,
      used_at BIGINT NOT NULL,
      UNIQUE(key_id, roblox_user_id)
    );
  `;

  await pool.query(createKeysTable);
  await pool.query(createWhitelistTable);
  await pool.query(createLogsTable);
  await pool.query(createTrialTable);

  console.log("[DB] Base de datos inicializada correctamente");
}

// ============================================================
// FUNCIONES DE KEY
// ============================================================

function hashKey(key) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(
      String(key)
        .trim()
        .toUpperCase()
    )
    .digest("hex");
}

function makeKey() {
  const raw = crypto
    .randomBytes(18)
    .toString("base64url")
    .toUpperCase();

  return `X23-${raw.slice(0, 6)}-${raw.slice(6, 12)}-${raw.slice(12, 18)}`;
}

function sessionToken() {
  return crypto
    .randomBytes(32)
    .toString("hex");
}

// ============================================================
// ADMIN
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
  const a = Buffer.from(
    String(input || "")
  );

  const b = Buffer.from(
    ADMIN_PASSWORD
  );

  return (
    a.length === b.length &&
    crypto.timingSafeEqual(a, b)
  );
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
      service: "roblox-key-api"
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
// LOGIN
// ============================================================

app.post(
  "/api/admin/login",
  (req, res) => {
    if (
      !passwordMatches(
        req.body?.password
      )
    ) {
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
      token
    });
  }
);

// ============================================================
// LOGOUT
// ============================================================

app.post(
  "/api/admin/logout",
  admin,
  (req, res) => {
    const token =
      req.headers["x-admin-token"];

    sessions.delete(token);

    res.json({
      success: true
    });
  }
);

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
          Number(
            req.body?.amount || 1
          )
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

      if (
        !permanent &&
        !units[type]
      ) {
        return res.status(400).json({
          success: false,
          message: "Duración inválida"
        });
      }

      const createdAt =
        Date.now();

      const expiresAt =
        permanent
          ? null
          : createdAt + units[type];

      const generated = [];

      const client =
        await pool.connect();

      try {
        await client.query(
          "BEGIN"
        );

        for (
          let i = 0;
          i < amount;
          i++
        ) {
          let key;
          let inserted = false;

          while (!inserted) {
            key = makeKey();

            try {
              await client.query(
                `
                INSERT INTO keys (
                  id,
                  key_hash,
                  type,
                  created_at,
                  expires_at
                )
                VALUES (
                  $1,
                  $2,
                  $3,
                  $4,
                  $5
                )
                `,
                [
                  crypto.randomUUID(),
                  hashKey(key),
                  permanent
                    ? "permanent"
                    : type,
                  createdAt,
                  expiresAt
                ]
              );

              inserted = true;
            } catch (error) {
              if (
                error.code ===
                "23505"
              ) {
                continue;
              }

              throw error;
            }
          }

          generated.push({
            key,
            type: permanent
              ? "permanent"
              : type,
            expiresAt
          });
        }

        await client.query(
          "COMMIT"
        );

        res.json({
          success: true,
          keys: generated
        });
      } catch (error) {
        await client.query(
          "ROLLBACK"
        );

        console.error(
          "Error generando keys:",
          error
        );

        res.status(500).json({
          success: false,
          message:
            "No se pudieron generar las keys"
        });
      } finally {
        client.release();
      }
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Error interno"
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
      const result =
        await pool.query(`
          SELECT
            id,
            type,
            created_at,
            expires_at,
            used_by,
            used_username,
            used_at,
            revoked
          FROM keys
          ORDER BY created_at DESC
        `);

      res.json({
        success: true,
        keys: result.rows.map(
          (k) => ({
            id: k.id,
            type: k.type,
            createdAt:
              Number(
                k.created_at
              ),
            expiresAt:
              k.expires_at === null
                ? null
                : Number(
                    k.expires_at
                  ),
            usedBy: k.used_by,
            usedUsername:
              k.used_username,
            usedAt:
              k.used_at === null
                ? null
                : Number(
                    k.used_at
                  ),
            revoked:
              k.revoked,
            expired:
              !k.revoked &&
              k.expires_at !==
                null &&
              Number(
                k.expires_at
              ) <= Date.now()
          })
        )
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "No se pudieron obtener las keys"
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
      const result =
        await pool.query(
          `
          UPDATE keys
          SET revoked = TRUE
          WHERE id = $1
          `,
          [req.params.id]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          success: false,
          message:
            "Key no encontrada"
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
          "No se pudo revocar la key"
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
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          DELETE FROM keys
          WHERE id = $1
          `,
          [req.params.id]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          success: false,
          message:
            "Key no encontrada"
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
          "No se pudo eliminar la key"
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
      const code = String(
        req.body?.code || ""
      ).trim();

      const userId = String(
        req.body?.userId || ""
      ).trim();

      const username = String(
        req.body?.username ||
          userId
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
          message:
            "Usuario de Roblox requerido"
        });
      }

      const whitelist =
        await pool.query(
          `
          SELECT
            roblox_user_id,
            roblox_username
          FROM whitelist
          WHERE roblox_user_id = $1
          `,
          [userId]
        );

      if (!whitelist.rows.length) {
        await writeKeyLog({
          robloxUserId: userId,
          robloxUsername: username,
          action: "validate",
          success: false,
          message:
            "Usuario no está en whitelist"
        });

        return res.json({
          valid: false,
          permanent: false,
          whitelisted: false,
          message:
            "NO TE ENCUENTRAS EN WHITELIST. CONTACTA AL VENDEDOR O ADMIN PARA PODER ACCEDER."
        });
      }

      const keyResult =
        await pool.query(
          `
          SELECT *
          FROM keys
          WHERE key_hash = $1
          LIMIT 1
          `,
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

      const key =
        keyResult.rows[0];

      if (key.revoked) {
        return res.json({
          valid: false,
          permanent: false,
          whitelisted: true,
          message: "Key revocada"
        });
      }

      if (
        key.expires_at !== null &&
        Number(
          key.expires_at
        ) <= Date.now()
      ) {
        return res.json({
          valid: false,
          permanent: false,
          whitelisted: true,
          message: "Key expirada"
        });
      }

      if (
        key.type ===
        "trial"
      ) {
        const used =
          await pool.query(
            `
            SELECT id
            FROM trial_uses
            WHERE key_id = $1
            AND roblox_user_id = $2
            LIMIT 1
            `,
            [
              key.id,
              userId
            ]
          );

        if (used.rows.length) {
          return res.json({
            valid: false,
            permanent: false,
            whitelisted: true,
            message:
              "Ya utilizaste tu key de prueba."
          });
        }

        await pool.query(
          `
          INSERT INTO trial_uses (
            id,
            key_id,
            roblox_user_id,
            roblox_username,
            used_at
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5
          )
          `,
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
          message:
            "Trial activada"
        });

        return res.json({
          valid: true,
          permanent: false,
          trial: true,
          whitelisted: true,
          message:
            "Key de prueba activada",
          expiresAt:
            key.expires_at === null
              ? null
              : Number(
                  key.expires_at
                )
        });
      }

      if (
        key.used_by &&
        String(
          key.used_by
        ) !== userId
      ) {
        return res.json({
          valid: false,
          permanent: false,
          whitelisted: true,
          message:
            "Esta key ya está vinculada a otro usuario"
        });
      }

      if (!key.used_by) {
        await pool.query(
          `
          UPDATE keys
          SET
            used_by = $1,
            used_username = $2,
            used_at = $3
          WHERE id = $4
          `,
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
        message:
          "Key válida"
      });

      return res.json({
        valid: true,
        permanent:
          key.type ===
          "permanent",
        trial: false,
        whitelisted: true,
        message:
          "Key válida",
        expiresAt:
          key.expires_at === null
            ? null
            : Number(
                key.expires_at
              )
      });
    } catch (error) {
      console.error(
        "Error validando key:",
        error
      );

      res.status(500).json({
        valid: false,
        permanent: false,
        message:
          "Error interno del servidor"
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
    try {
      const userId =
        String(
          req.body?.robloxUserId ||
            ""
        ).trim();

      if (!userId) {
        return res.json({
          whitelisted: false,
          username: null
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            roblox_user_id,
            roblox_username
          FROM whitelist
          WHERE roblox_user_id = $1
          `,
          [userId]
        );

      res.json({
        whitelisted:
          result.rows.length > 0,
        username:
          result.rows[0]
            ?.roblox_username ||
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
// AGREGAR WHITELIST
// ============================================================

app.post(
  "/api/whitelist",
  async (req, res) => {
    try {
      const id =
        String(
          req.body?.robloxUserId ||
            ""
        ).trim();

      const username =
        String(
          req.body?.robloxUsername ||
            id
        ).trim();

      if (!id) {
        return res.status(400).json({
          success: false,
          message:
            "User ID requerido"
        });
      }

      await pool.query(
        `
        INSERT INTO whitelist (
          roblox_user_id,
          roblox_username,
          created_at
        )
        VALUES (
          $1,
          $2,
          $3
        )
        ON CONFLICT (
          roblox_user_id
        )
        DO UPDATE SET
          roblox_username =
            EXCLUDED.roblox_username
        `,
        [
          id,
          username,
          Date.now()
        ]
      );

      res.json({
        success: true,
        message:
          `✓ ${username} agregado a la whitelist`
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
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            roblox_user_id,
            roblox_username,
            created_at
          FROM whitelist
          ORDER BY created_at DESC
        `);

      res.json(
        result.rows.map(
          (x) => ({
            robloxUserId:
              x.roblox_user_id,
            robloxUsername:
              x.roblox_username,
            createdAt:
              Number(
                x.created_at
              )
          })
        )
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
      const result =
        await pool.query(
          `
          DELETE FROM whitelist
          WHERE roblox_user_id = $1
          `,
          [
            String(
              req.params.userId
            )
          ]
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
  async (req, res) => {
    try {
      const keys =
        await pool.query(`
          SELECT COUNT(*)::int AS count
          FROM keys
        `);

      const active =
        await pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM keys
          WHERE revoked = FALSE
          AND (
            expires_at IS NULL
            OR expires_at > $1
          )
          `,
          [Date.now()]
        );

      const revoked =
        await pool.query(`
          SELECT COUNT(*)::int AS count
          FROM keys
          WHERE revoked = TRUE
        `);

      const whitelist =
        await pool.query(`
          SELECT COUNT(*)::int AS count
          FROM whitelist
        `);

      const logs =
        await pool.query(`
          SELECT COUNT(*)::int AS count
          FROM key_logs
        `);

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
      `
      INSERT INTO key_logs (
        id,
        key_id,
        roblox_user_id,
        roblox_username,
        action,
        success,
        message,
        created_at
      )
      VALUES (
        $1,
        $2,
        $3,
        $4,
        $5,
        $6,
        $7,
        $8
      )
      `,
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
    console.error(
      "No se pudo guardar log:",
      error
    );
  }
}

// ============================================================
// OBTENER LOGS
// ============================================================

app.get(
  "/api/admin/logs",
  admin,
  async (req, res) => {
    try {
      const limit =
        Math.max(
          1,
          Math.min(
            200,
            Number(
              req.query.limit ||
                100
            )
          )
        );

      const result =
        await pool.query(
          `
          SELECT
            id,
            key_id,
            roblox_user_id,
            roblox_username,
            action,
            success,
            message,
            created_at
          FROM key_logs
          ORDER BY created_at DESC
          LIMIT $1
          `,
          [limit]
        );

      res.json({
        success: true,
        logs:
          result.rows.map(
            (x) => ({
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
                Number(
                  x.created_at
                )
            })
          )
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

  const existing =
    await pool.query(
      `
      SELECT id
      FROM keys
      WHERE key_hash = $1
      LIMIT 1
      `,
      [hashKey(configuredKey)]
    );

  if (existing.rows.length) {
    return;
  }

  const createdAt =
    Date.now();

  await pool.query(
    `
    INSERT INTO keys (
      id,
      key_hash,
      type,
      created_at,
      expires_at
    )
    VALUES (
      $1,
      $2,
      $3,
      $4,
      $5
    )
    `,
    [
      crypto.randomUUID(),
      hashKey(configuredKey),
      "trial",
      createdAt,
      createdAt +
        30 * 60 * 1000
    ]
  );

  console.log(
    "[TRIAL] Key creada"
  );
}

app.get(
  "/api/trial",
  async (req, res) => {
    try {
      const configuredKey =
        process.env.TEST_KEY ||
        "X23-TRIAL-30MIN";

      const result =
        await pool.query(
          `
          SELECT
            type,
            created_at,
            expires_at,
            revoked
          FROM keys
          WHERE key_hash = $1
          LIMIT 1
          `,
          [hashKey(configuredKey)]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message:
            "Key de prueba no disponible"
        });
      }

      const key =
        result.rows[0];

      res.json({
        success: true,
        key: configuredKey,
        type: "trial",
        expiresAt:
          key.expires_at === null
            ? null
            : Number(
                key.expires_at
              ),
        revoked:
          key.revoked
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

app.use(
  (req, res, next) => {
    if (
      req.method === "GET" &&
      !req.path.startsWith(
        "/api/"
      )
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
  }
);

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
      () => {
        console.log(
          `[SERVER] API escuchando en puerto ${PORT}`
        );

        console.log(
          "[SERVER] Base de datos: CONECTADA"
        );

        console.log(
          "[SERVER] Whitelist obligatoria: ACTIVADA"
        );

        console.log(
          "[SERVER] Logs de keys: ACTIVADOS"
        );

        console.log(
          "[SERVER] Trial: ACTIVADA"
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
```
