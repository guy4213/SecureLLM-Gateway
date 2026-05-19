# ─── Stage 1: install production dependencies ────────────────────────────────
FROM node:20-alpine AS deps
WORKDIR /app

# dumb-init prevents zombie processes; needed in Alpine where tini is absent
RUN apk add --no-cache dumb-init

COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts

# ─── Stage 2: compile TypeScript ─────────────────────────────────────────────
FROM node:20-alpine AS build
WORKDIR /app

COPY package*.json tsconfig.json ./
RUN npm ci --ignore-scripts

COPY src/ ./src/
RUN npm run build

# ─── Stage 3: lean production image ──────────────────────────────────────────
FROM node:20-alpine AS production
WORKDIR /app

ENV NODE_ENV=production

# Copy dumb-init from deps stage
COPY --from=deps /usr/bin/dumb-init /usr/bin/dumb-init

# Copy only what runtime needs
COPY --from=deps  /app/node_modules ./node_modules
COPY --from=build /app/dist         ./dist

EXPOSE 3000

# Run as non-root for security
USER node

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://localhost:3000/healthz || exit 1

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]
