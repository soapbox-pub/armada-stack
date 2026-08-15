# ditto-relay ships no Dockerfile of its own, so this one lives here rather
# than in a repo this stack does not own.
#
# The build context is THIS repo; the relay source arrives as the named
# BuildKit context `relay-src`, wired in docker-compose.yml. That is why the
# COPY lines say `--from=relay-src`. Doing it the other way (context
# ../ditto-relay plus a `dockerfile:` pointing back out) would hardcode this
# directory's name into the build.
#
# Runtime is Bun and cannot be Node: src/server.ts imports `serve` from "bun",
# uses Bun's ServerWebSocket and server.requestIP(), and spawns Workers with
# the Bun-only `smol` option. `oven/bun:1` is what the relay's own CI runs.
FROM oven/bun:1

WORKDIR /app

# Manifest first, so a source-only change does not re-resolve dependencies.
COPY --from=relay-src /package.json /bun.lock ./
RUN bun install --frozen-lockfile

COPY --from=relay-src /tsconfig.json ./
COPY --from=relay-src /src ./src

# NOT optional. src/server.ts reads public/favicon.ico, public/icon.png and
# public/banner.jpg in a TOP-LEVEL await during module evaluation, so an image
# missing this directory does not degrade — it fails to boot.
COPY --from=relay-src /public ./public

# The COPYs are selective rather than `COPY . .` for one reason beyond size:
# the relay's config loader reads a `.env` file in the working directory and
# lets it WIN over the process environment. A stray .env baked into the image
# would silently override everything docker-compose.yml sets.

# No build step — Bun runs the TypeScript directly.
EXPOSE 13131

CMD ["bun", "run", "src/server.ts"]
