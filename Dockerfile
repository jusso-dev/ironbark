FROM node:22-alpine AS builder
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.server.json tsconfig.web.json vite.config.ts ./
COPY src ./src
COPY web ./web
COPY bin ./bin
RUN pnpm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=8788
ENV IRONBARK_DB_PATH=/data/ironbark.db
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --prod --frozen-lockfile
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/bin ./bin
RUN mkdir -p /data
EXPOSE 8788
CMD ["node", "--no-warnings", "dist/server/cli.js", "serve", "--host", "0.0.0.0", "--port", "8788"]
