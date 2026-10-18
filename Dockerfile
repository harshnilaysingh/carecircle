FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN npm install --global pnpm@11.25.0
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm exec prisma generate && pnpm run build

FROM build AS runtime
ENV NODE_ENV=production
RUN pnpm prune --prod
USER node
EXPOSE 3001
CMD ["node", "dist/server.js"]

# Run this target once as a controlled release task before shifting traffic:
# docker build --target migrate -t carecircle-migrate .
FROM build AS migrate
CMD ["pnpm", "exec", "prisma", "migrate", "deploy"]
