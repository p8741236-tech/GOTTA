FROM node:22-slim
WORKDIR /app
COPY package.json server.js pg.js ./
COPY public ./public
ENV NODE_ENV=production TRUST_PROXY=1
# Con DATABASE_URL (PostgreSQL, p. ej. Neon) las cuentas viven en esa base de datos.
# Sin DATABASE_URL usa SQLite en /data (monta un disco persistente ahí).
ENV DATA_DIR=/data
EXPOSE 3000
CMD ["node", "server.js"]
