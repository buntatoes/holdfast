# Holdfast console

Operator UI for allowing or denying agent tool calls. Works with `holdfast wrap`
and with proprietary `holdfast jail` / `holdfast swarm` sessions.

```bash
cd console
npm install
npm run dev
```

Serves on `http://0.0.0.0:43123`. Point it at the daemon with `NEXT_PUBLIC_HOLDFAST_API` (default `http://127.0.0.1:47821`).
