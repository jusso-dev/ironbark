# Contributing to Ironbark

Thank you for helping improve Ironbark!

## Local Development

```sh
pnpm install
pnpm run typecheck
pnpm test
pnpm run build
```

To run the API and Vite frontend concurrently in dev mode:

```sh
pnpm run dev:api   # http://127.0.0.1:8788
pnpm run dev:web   # http://127.0.0.1:5173
```

## Guidelines

- Keep unit tests deterministic and offline-safe (mock external HTTP calls via `FetchLike`).
- Remember Node's built-in `node:sqlite` enforces `DQS_DML=0` (use single-quoted `'...'` SQL string literals) and returns null-prototype objects.
- Never store raw credential values or secrets from SARIF/Secret Scanning outputs; store metadata counts only.
- Run `pnpm run typecheck && pnpm test && pnpm run build` before opening a pull request.
