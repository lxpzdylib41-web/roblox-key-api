# X23 Roblox Key API

Panel administrativo para gestionar keys, usuarios, historial y el estado de la API.

## Mejoras incluidas

- Dashboard profesional azul/celeste con identidad X23 / Charizard X.
- Sesión administrativa firmada y persistente: no depende de un `Map` en memoria, por lo que un restart/deploy no invalida automáticamente la sesión.
- Gestión de keys: generar, revocar, activar y extender días.
- Historial de acciones de keys.
- Control de API ON/OFF persistente en PostgreSQL.
- El modo API OFF bloquea las validaciones de Roblox sin apagar el dashboard administrativo.
- El contador de las keys se mantiene fijo desde su creación; validar una key no reinicia su expiración.

## Variables de entorno

Configura en Render:

- `DATABASE_URL`
- `ADMIN_PASSWORD`
- `SESSION_SECRET`

`SESSION_SECRET` debe mantenerse estable entre deploys para conservar las sesiones existentes.

## Deploy

```bash
npm install
npm start
```

El servicio escucha en `0.0.0.0:$PORT`.
