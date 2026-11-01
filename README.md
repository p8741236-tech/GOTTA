# Gotta con cuentas reales

Servidor sin dependencias (Node 22+). Sirve la web de Gotta y guarda cuentas y progreso en **PostgreSQL**
(variable `DATABASE_URL`, p. ej. Neon) o, si no la defines, en **SQLite** dentro de `DATA_DIR`.

## Gratis: Render + Neon
1. neon.tech → crea cuenta y un proyecto (región Frankfurt). Copia la *connection string* (`postgresql://...neon.tech/...?sslmode=require`).
2. Render → New → Blueprint → este repositorio → pega esa cadena en `DATABASE_URL` → Apply.
3. Render gratis duerme el servicio tras ~15 min sin visitas y tarda ~1 min en despertar; las cuentas NO se pierden porque están en Neon.
   Para evitar el sueño, crea un monitor gratuito en uptimerobot.com que abra `https://TU-APP.onrender.com/healthz` cada 5 min.

## Probarlo en tu ordenador (necesita Node 22.13+ de nodejs.org)
Doble clic en `start.bat` (Windows) o `./start.sh` (Mac/Linux) y abre http://localhost:3000

    node server.js          # http://localhost:3000
    node test-api.mjs       # pruebas de la API

## Dejarlo online (elige UNA opción; ya vienen los ficheros listos)
- **Render**: `render.yaml` (Blueprint) · **Fly.io**: `fly.toml` · **VPS**: `docker-compose.yml` (con HTTPS automático vía Caddy).

## Detalles de despliegue (para entrar desde otro país / otro dispositivo)
Necesita un host que ejecute Node o Docker **con un disco persistente**. Sin disco persistente las cuentas se pierden al reiniciar.

- **Fly.io**: `fly launch` (usa el Dockerfile), `fly volumes create data --size 1`, monta el volumen en `/data`.
- **Render**: Web Service con Docker + *Disk* montado en `/data`.
- **VPS propio**: `docker build -t gotta . && docker run -d -p 80:3000 -v gotta-data:/data gotta` y un proxy con HTTPS (Caddy/nginx).

Variables: `PORT` (3000), `DATA_DIR` (./data), `TRUST_PROXY=1` si va detrás de un proxy/HTTPS (ya puesto en el Dockerfile).
Usa siempre HTTPS: la contraseña viaja al servidor al entrar. Haz copia periódica de `DATA_DIR/gotta.db`.

## Cómo funciona
- Contraseñas con scrypt + sal; sesiones con token aleatorio (se guarda solo su hash) que **nunca caducan**: solo se cierran al pulsar «Cerrar sesión» o al cambiar la contraseña.
- El progreso se guarda en la cuenta y se sincroniza solo (al jugar, al cerrar y al volver a la pestaña).
- Si dos dispositivos cambian el progreso a la vez, se fusiona (mayor nº de partidas y logros de ambos).
- Límite de intentos de login por IP y por correo. Cambiar la contraseña cierra las demás sesiones.
- No hay recuperación de contraseña por correo (haría falta un servicio SMTP).
