# Railway build for the VIGIL frontend (Vite SPA).
# VITE_* values are baked into the static bundle at build time, so they are
# passed as build args (Railway exposes service variables as build args) and
# promoted to ENV before `npm run build`.
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .

ARG VITE_AUTH_URL
ARG VITE_API_URL
ARG VITE_CORRELATION_URL
ARG VITE_DETECTION_ENGINE_URL
ARG VITE_PLAYBOOK_ENGINE_URL
ARG VITE_REPORTING_URL
ARG VITE_DEV_TENANT_ID
ENV VITE_AUTH_URL=$VITE_AUTH_URL \
    VITE_API_URL=$VITE_API_URL \
    VITE_CORRELATION_URL=$VITE_CORRELATION_URL \
    VITE_DETECTION_ENGINE_URL=$VITE_DETECTION_ENGINE_URL \
    VITE_PLAYBOOK_ENGINE_URL=$VITE_PLAYBOOK_ENGINE_URL \
    VITE_REPORTING_URL=$VITE_REPORTING_URL \
    VITE_DEV_TENANT_ID=$VITE_DEV_TENANT_ID
RUN npm run build

FROM node:20-alpine
WORKDIR /app
RUN npm install -g serve@14
COPY --from=build /app/dist ./dist
# serve binds 0.0.0.0 (IPv4) — fine, the frontend is only reached via the
# public edge, never the IPv6 private network.
CMD ["sh", "-c", "serve -s dist -l ${PORT:-8080}"]
