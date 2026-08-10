```js
import {
  Client,
  GatewayIntentBits,
  REST,
  Routes,
  SlashCommandBuilder,
  EmbedBuilder
} from "discord.js";

// ============================================================
// CONFIGURACIÓN
// ============================================================

const DISCORD_TOKEN = process.env.DISCORD_TOKEN;

const CLIENT_ID =
  process.env.DISCORD_CLIENT_ID ||
  "1536312317300441089";F

const GUILD_ID =
  process.env.DISCORD_GUILD_ID ||
  "1524506931165659239";

const API_URL =
  (process.env.API_URL || "").replace(/\/+$/, "");

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || "";

const ADMIN_IDS = new Set([
  "1509299325727936685",
  "1531511171839037482"
]);

// ============================================================
// COMPROBAR VARIABLES
// ============================================================

if (!DISCORD_TOKEN) {
  console.error("❌ Falta DISCORD_TOKEN");
  process.exit(1);
}

if (!API_URL) {
  console.error("❌ Falta API_URL");
  process.exit(1);
}

if (!ADMIN_PASSWORD) {
  console.error("❌ Falta ADMIN_PASSWORD");
  process.exit(1);
}

// ============================================================
// CLIENTE DISCORD
// ============================================================

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds
  ]
});

// ============================================================
// COMANDOS
// ============================================================

const commands = [

  new SlashCommandBuilder()
    .setName("key")
    .setDescription("Administrar keys")

    .addSubcommand(sub =>
      sub
        .setName("generar")
        .setDescription("Generar keys")
        .addIntegerOption(opt =>
          opt
            .setName("cantidad")
            .setDescription("Cantidad de keys")
            .setRequired(true)
            .setMinValue(1)
            .setMaxValue(100)
        )
        .addStringOption(opt =>
          opt
            .setName("duracion")
            .setDescription("Duración de la key")
            .setRequired(true)
            .addChoices(
              { name: "Minutos", value: "minutes" },
              { name: "Horas", value: "hours" },
              { name: "Días", value: "days" },
              { name: "Semanas", value: "weeks" },
              { name: "30 días", value: "months" },
              { name: "Permanente", value: "permanent" }
            )
        )
    )

    .addSubcommand(sub =>
      sub
        .setName("listar")
        .setDescription("Listar todas las keys")
    )

    .addSubcommand(sub =>
      sub
        .setName("revocar")
        .setDescription("Revocar una key")
        .addStringOption(opt =>
          opt
            .setName("id")
            .setDescription("ID de la key")
            .setRequired(true)
        )
    )

    .addSubcommand(sub =>
      sub
        .setName("eliminar")
        .setDescription("Eliminar una key")
        .addStringOption(opt =>
          opt
            .setName("id")
            .setDescription("ID de la key")
            .setRequired(true)
        )
    ),

  new SlashCommandBuilder()
    .setName("whitelist")
    .setDescription("Administrar whitelist")

    .addSubcommand(sub =>
      sub
        .setName("agregar")
        .setDescription("Agregar usuario a whitelist")
        .addStringOption(opt =>
          opt
            .setName("userid")
            .setDescription("Roblox User ID")
            .setRequired(true)
        )
        .addStringOption(opt =>
          opt
            .setName("username")
            .setDescription("Roblox Username")
            .setRequired(true)
        )
    )

    .addSubcommand(sub =>
      sub
        .setName("eliminar")
        .setDescription("Eliminar usuario de whitelist")
        .addStringOption(opt =>
          opt
            .setName("userid")
            .setDescription("Roblox User ID")
            .setRequired(true)
        )
    )

    .addSubcommand(sub =>
      sub
        .setName("listar")
        .setDescription("Listar whitelist")
    ),

  new SlashCommandBuilder()
    .setName("stats")
    .setDescription("Mostrar estadísticas de la API"),

  new SlashCommandBuilder()
    .setName("help")
    .setDescription("Mostrar comandos disponibles"),

  new SlashCommandBuilder()
    .setName("ping")
    .setDescription("Comprobar estado del bot")

].map(command => command.toJSON());

// ============================================================
// SESIÓN ADMIN DE LA API
// ============================================================

let apiAdminToken = null;

async function getAdminToken() {

  if (apiAdminToken) {
    return apiAdminToken;
  }

  const response = await fetch(
    `${API_URL}/api/admin/login`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        password: ADMIN_PASSWORD
      })
    }
  );

  let data = {};

  try {
    data = await response.json();
  } catch {}

  if (
    !response.ok ||
    !data.success ||
    !data.token
  ) {
    throw new Error(
      data.message ||
      "No se pudo iniciar sesión en la API"
    );
  }

  apiAdminToken = data.token;

  return apiAdminToken;
}

// ============================================================
// PETICIÓN ADMIN A LA API
// ============================================================

async function adminApiRequest(
  endpoint,
  options = {}
) {

  const token = await getAdminToken();

  const response = await fetch(
    `${API_URL}${endpoint}`,
    {
      ...options,

      headers: {
        "Content-Type": "application/json",

        "x-admin-token": token,

        ...(options.headers || {})
      }
    }
  );

  if (response.status === 401) {

    apiAdminToken = null;

    const newToken =
      await getAdminToken();

    return adminApiRequest(
      endpoint,
      {
        ...options,

        headers: {
          ...(options.headers || {}),

          "x-admin-token": newToken
        }
      }
    );
  }

  let data = {};

  try {
    data = await response.json();
  } catch {}

  if (!response.ok) {

    throw new Error(
      data.message ||
      `API respondió ${response.status}`
    );
  }

  return data;
}

// ============================================================
// SEGURIDAD
// ============================================================

function isAdmin(userId) {
  return ADMIN_IDS.has(userId);
}

async function requireAdmin(interaction) {

  if (isAdmin(interaction.user.id)) {
    return true;
  }

  await interaction.reply({
    content:
      "❌ No tienes permiso para utilizar este comando.",
    ephemeral: true
  });

  return false;
}

// ============================================================
// REGISTRAR COMANDOS
// ============================================================

async function registerCommands() {

  const rest =
    new REST({ version: "10" })
      .setToken(DISCORD_TOKEN);

  console.log("🔄 Registrando comandos...");

  await rest.put(
    Routes.applicationGuildCommands(
      CLIENT_ID,
      GUILD_ID
    ),
    {
      body: commands
    }
  );

  console.log(
    "✅ Comandos registrados correctamente."
  );
}

// ============================================================
// READY
// ============================================================

client.once("ready", async () => {

  console.log(
    "======================================"
  );

  console.log(
    "🤖 ROBLOX KEY DISCORD BOT"
  );

  console.log(
    "======================================"
  );

  console.log(
    `Bot: ${client.user.tag}`
  );

  console.log(
    `Servidor: ${GUILD_ID}`
  );

  console.log(
    "Administradores:"
  );

  for (const id of ADMIN_IDS) {
    console.log(`- ${id}`);
  }

  try {

    await registerCommands();

  } catch (error) {

    console.error(
      "❌ Error registrando comandos:",
      error
    );
  }

  client.user.setPresence({
    activities: [
      {
        name: "Roblox Key API",
        type: 3
      }
    ],

    status: "online"
  });
});

// ============================================================
// INTERACCIONES
// ============================================================

client.on(
  "interactionCreate",
  async interaction => {

    if (!interaction.isChatInputCommand()) {
      return;
    }

    // --------------------------------------------------------
    // SOLO EL SERVIDOR CONFIGURADO
    // --------------------------------------------------------

    if (
      interaction.guildId !== GUILD_ID
    ) {

      return interaction.reply({
        content:
          "❌ Este bot no está autorizado para funcionar en este servidor.",
        ephemeral: true
      });
    }

    try {

      // ======================================================
      // PING
      // ======================================================

      if (
        interaction.commandName === "ping"
      ) {

        return interaction.reply({
          content:
            `🏓 Pong!\nLatencia: ${client.ws.ping}ms`,
          ephemeral: true
        });
      }

      // ======================================================
      // HELP
      // ======================================================

      if (
        interaction.commandName === "help"
      ) {

        const embed =
          new EmbedBuilder()

            .setTitle("🔑 X23 Key System")

            .setDescription(
              "Sistema de administración de keys conectado a Roblox."
            )

            .addFields(

              {
                name: "🔑 Keys",

                value:
                  "`/key generar`\n" +
                  "`/key listar`\n" +
                  "`/key revocar`\n" +
                  "`/key eliminar`"
              },

              {
                name: "👤 Whitelist",

                value:
                  "`/whitelist agregar`\n" +
                  "`/whitelist eliminar`\n" +
                  "`/whitelist listar`"
              },

              {
                name: "📊 Sistema",

                value:
                  "`/stats`\n" +
                  "`/ping`"
              }
            );

        return interaction.reply({
          embeds: [embed]
        });
      }

      // ======================================================
      // COMANDOS ADMIN
      // ======================================================

      if (
        interaction.commandName === "key" ||
        interaction.commandName === "whitelist" ||
        interaction.commandName === "stats"
      ) {

        if (
          !(await requireAdmin(interaction))
        ) {
          return;
        }
      }

      // ======================================================
      // KEY
      // ======================================================

      if (
        interaction.commandName === "key"
      ) {

        const subcommand =
          interaction.options.getSubcommand();

        // ----------------------------------------------------
        // GENERAR
        // ----------------------------------------------------

        if (
          subcommand === "generar"
        ) {

          await interaction.deferReply({
            ephemeral: true
          });

          const cantidad =
            interaction.options.getInteger(
              "cantidad"
            );

          const duracion =
            interaction.options.getString(
              "duracion"
            );

          const data =
            await adminApiRequest(
              "/api/admin/keys/generate",
              {
                method: "POST",

                body: JSON.stringify({
                  amount: cantidad,
                  type: duracion
                })
              }
            );

          if (
            !data.success ||
            !data.keys?.length
          ) {

            throw new Error(
              data.message ||
              "No se generaron las keys."
            );
          }

          const keysText =
            data.keys
              .map(k => `\`${k.key}\``)
              .join("\n");

          const embed =
            new EmbedBuilder()

              .setTitle(
                "🔑 Keys generadas"
              )

              .setDescription(
                keysText
              )

              .addFields({
                name: "Cantidad",
                value:
                  String(
                    data.keys.length
                  ),
                inline: true
              })

              .setTimestamp();

          return interaction.editReply({
            embeds: [embed]
          });
        }

        // ----------------------------------------------------
        // LISTAR
        // ----------------------------------------------------

        if (
          subcommand === "listar"
        ) {

          await interaction.deferReply({
            ephemeral: true
          });

          const data =
            await adminApiRequest(
              "/api/admin/keys"
            );

          if (
            !data.keys?.length
          ) {

            return interaction.editReply({
              content:
                "📭 No hay keys registradas."
            });
          }

          const lines =
            data.keys
              .slice(0, 25)
              .map(k => {

                let estado =
                  "🟢 Activa";

                if (k.revoked) {
                  estado =
                    "🔴 Revocada";
                }

                else if (k.expired) {
                  estado =
                    "🟠 Expirada";
                }

                else if (k.usedBy) {
                  estado =
                    "🔵 Usada";
                }

                return (
                  `**${k.type}** — ${estado}\n` +
                  `ID: \`${k.id}\`\n` +
                  `Usuario: ${k.usedUsername || "Ninguno"}`
                );
              })
              .join("\n\n");

          const embed =
            new EmbedBuilder()

              .setTitle("📋 Keys")

              .setDescription(
                lines
              )

              .setFooter({
                text:
                  `Mostrando hasta 25 keys de ${data.keys.length}`
              });

          return interaction.editReply({
            embeds: [embed]
          });
        }

        // ----------------------------------------------------
        // REVOCAR
        // ----------------------------------------------------

        if (
          subcommand === "revocar"
        ) {

          await interaction.deferReply({
            ephemeral: true
          });

          const id =
            interaction.options.getString(
              "id"
            );

          const data =
            await adminApiRequest(
              `/api/admin/keys/${encodeURIComponent(id)}/revoke`,
              {
                method: "POST"
              }
            );

          if (!data.success) {

            throw new Error(
              data.message ||
              "No se pudo revocar."
            );
          }

          return interaction.editReply({
            content:
              `✅ Key \`${id}\` revocada correctamente.`
          });
        }

        // ----------------------------------------------------
        // ELIMINAR
        // ----------------------------------------------------

        if (
          subcommand === "eliminar"
        ) {

          await interaction.deferReply({
            ephemeral: true
          });

          const id =
            interaction.options.getString(
              "id"
            );

          const data =
            await adminApiRequest(
              `/api/admin/keys/${encodeURIComponent(id)}`,
              {
                method: "DELETE"
              }
            );

          if (!data.success) {

            throw new Error(
              data.message ||
              "No se pudo eliminar."
            );
          }

          return interaction.editReply({
            content:
              `🗑️ Key \`${id}\` eliminada correctamente.`
          });
        }
      }

      // ======================================================
      // WHITELIST
      // ======================================================

      if (
        interaction.commandName === "whitelist"
      ) {

        const subcommand =
          interaction.options.getSubcommand();

        // ----------------------------------------------------
        // AGREGAR
        // ----------------------------------------------------

        if (
          subcommand === "agregar"
        ) {

          await interaction.deferReply({
            ephemeral: true
          });

          const userid =
            interaction.options.getString(
              "userid"
            );

          const username =
            interaction.options.getString(
              "username"
            );

          const data =
            await adminApiRequest(
              "/api/whitelist",
              {
                method: "POST",

                body: JSON.stringify({
                  robloxUserId: userid,
                  robloxUsername: username
                })
              }
            );

          return interaction.editReply({
            content:
              data.message ||
              `✅ ${username} agregado a whitelist.`
          });
        }

        // ----------------------------------------------------
        // ELIMINAR
        // ----------------------------------------------------

        if (
          subcommand === "eliminar"
        ) {

          await interaction.deferReply({
            ephemeral: true
          });

          const userid =
            interaction.options.getString(
              "userid"
            );

          const data =
            await adminApiRequest(
              `/api/admin/whitelist/${encodeURIComponent(userid)}`,
              {
                method: "DELETE"
              }
            );

          if (!data.success) {

            throw new Error(
              data.message ||
              "No se pudo eliminar."
            );
          }

          return interaction.editReply({
            content:
              `🗑️ Usuario \`${userid}\` eliminado de whitelist.`
          });
        }

        // ----------------------------------------------------
        // LISTAR
        // ----------------------------------------------------

        if (
          subcommand === "listar"
        ) {

          await interaction.deferReply({
            ephemeral: true
          });

          const response =
            await fetch(
              `${API_URL}/api/whitelist`
            );

          let data = [];

          try {
            data = await response.json();
          } catch {}

          if (!Array.isArray(data)) {
            data = data.users || [];
          }

          if (!data.length) {

            return interaction.editReply({
              content:
                "📭 La whitelist está vacía."
            });
          }

          const text =
            data
              .slice(0, 25)
              .map(x =>
                `👤 **${x.robloxUsername}**\n` +
                `ID: \`${x.robloxUserId}\``
              )
              .join("\n\n");

          const embed =
            new EmbedBuilder()

              .setTitle(
                "👥 Whitelist"
              )

              .setDescription(
                text
              )

              .setFooter({
                text:
                  `Total: ${data.length}`
              });

          return interaction.editReply({
            embeds: [embed]
          });
        }
      }

      // ======================================================
      // STATS
      // ======================================================

      if (
        interaction.commandName === "stats"
      ) {

        await interaction.deferReply({
          ephemeral: true
        });

        const data =
          await adminApiRequest(
            "/api/admin/stats"
          );

        const embed =
          new EmbedBuilder()

            .setTitle(
              "📊 Estadísticas"
            )

            .addFields(

              {
                name: "🔑 Total keys",
                value:
                  String(
                    data.totalKeys ?? 0
                  ),
                inline: true
              },

              {
                name: "🟢 Keys activas",
                value:
                  String(
                    data.activeKeys ?? 0
                  ),
                inline: true
              },

              {
                name: "🔴 Revocadas",
                value:
                  String(
                    data.revokedKeys ?? 0
                  ),
                inline: true
              },

              {
                name: "👥 Whitelist",
                value:
                  String(
                    data.whitelistUsers ?? 0
                  ),
                inline: true
              }
            )

            .setTimestamp();

        return interaction.editReply({
          embeds: [embed]
        });
      }

    } catch (error) {

      console.error(
        "❌ Error en comando:",
        error
      );

      const message =
        `❌ Error: ${
          error.message ||
          "Error desconocido"
        }`;

      if (
        interaction.deferred
      ) {

        return interaction
          .editReply({
            content: message
          })
          .catch(() => {});
      }

      if (
        !interaction.replied
      ) {

        return interaction
          .reply({
            content: message,
            ephemeral: true
          })
          .catch(() => {});
      }
    }
  }
);

// ============================================================
// ERRORES
// ============================================================

client.on(
  "error",
  error => {
    console.error(
      "Discord client error:",
      error
    );
  }
);

process.on(
  "unhandledRejection",
  error => {
    console.error(
      "Unhandled rejection:",
      error
    );
  }
);

process.on(
  "uncaughtException",
  error => {
    console.error(
      "Uncaught exception:",
      error
    );
  }
);

// ============================================================
// INICIAR BOT
// ============================================================

client.login(DISCORD_TOKEN);
```
