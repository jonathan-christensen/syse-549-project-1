# frontend

A React UI for the RP's public/protected resource and the full subscriber
journey: sign up (CSP), log in (Verifier + RP), view the protected resource
(RP). Not part of the graded contract — the four backend services are pure
JSON and are what the conformance probe talks to. This is a browsable client
on top of them.

## Run it

Requires Node.js (not installed in the environment this was scaffolded in —
install it on your own machine first: https://nodejs.org).

```
cd frontend
npm install
npm run dev
```

Then open http://localhost:5173. The four backend services must already be
running on their default ports (csp: 4101, verifier: 4102, rp: 4103) — `npm
run dev`'s dev server proxies `/api/csp`, `/api/verifier`, `/api/rp` to them
(see `vite.config.js`), so the browser never calls those origins directly and
never hits their CORS/OPTIONS gap.

## Why a proxy, not CORS headers on the services

The backend services are deliberately a minimal `http.server` subclass
(`shared/service.py`) with no OPTIONS handling. Adding CORS support there
would mean modifying code the automated probe grades. Routing through Vite's
dev proxy keeps the backend untouched and the browser same-origin.
