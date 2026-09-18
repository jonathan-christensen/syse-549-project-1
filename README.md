# Lab 1 — NIST SP 800-63-4 Figure 3, non-federated digital identity model

Four services, five steps, one subject moving through three roles, all inside a
single trust boundary. The model, the contract and the grading criteria are in
[`PROJECT_WORKFLOW.md`](PROJECT_WORKFLOW.md); this file is how to run it.

Python 3.8+ and the standard library. Nothing to install, no sudo, no database.

## Services and ports

Ports are `LAB1_PORT_BLOCK` plus a fixed offset, so one setting moves all four.

| Service | Offset | Port | Owner | Status |
|---|---|---|---|---|
| Subject agent | +0 | 4100 | Partner A | `/health`, `/transcript`, `/reset` only — **`POST /run` is missing** |
| CSP | +1 | 4101 | Partner A | `/health`, `/transcript`, `/reset` only — **no enrollment or binding yet** |
| Verifier | +2 | 4102 | Partner B | complete |
| Relying Party | +3 | 4103 | Partner B | complete |

Measured with `conformance_probe.py` against all four running locally:
**12 of 24 checks, 5.0/10**. Everything that does not need `POST /run` passes
(all `S-*`, all `P-*`, all `X-*`); all seven `H-*` and all four `N-*` fail for
the single reason that `POST /run` answers `404`, so no scenario ever executes.

The remaining twelve were checked separately: driving the Verifier and RP
through the sequence in [`docs/decisions.md`](docs/decisions.md#what-post-run-has-to-do-scenario-by-scenario)
with a throwaway driver (not in this repo — the Subject agent is Partner A's to
write) scores **24 of 24, 10/10**. So the gap is `POST /run` and the CSP's
enrollment and binding, and nothing else.

> **Before deploying:** team `hayagreeva-jonathan` has claimed **4100–4103** on
> the Canvas discussion, and `team.json` and `.env.example` carry that block.
> Two things still need doing on the server: confirm the range is actually
> reachable from campus — the firewall rule in the server notes admits
> `4000:4009` only — and set `HOST=0.0.0.0` in your `.env`, which currently
> says `127.0.0.1`. Both are step 2.0 of
> [`docs/deployment.md`](docs/deployment.md).

## Running it from a clean checkout

Step by step, including the server and the live demo:
**[`docs/deployment.md`](docs/deployment.md)**.

```bash
git clone <this repo> && cd syse-549-project-1
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(32))"   # once per token
$EDITOR .env        # paste one token into each of the two token settings
pip install -r requirements.txt   # Partner A's two services only
```

One `.env` configures all four services: Partner A's read `TEAM`, `HOST` and
`<SERVICE>_PORT`, and Partner B's read the same names when the `LAB1_`-prefixed
form is unset. Partner B's services and the test suite need no packages at all.

Then start each service in its own terminal (or under `tmux`/`nohup` on the
server — no sudo, everything from your home directory):

```bash
python3 -m subject.main          # port block + 0   (Partner A)
python3 -m csp.main              # port block + 1   (Partner A)
python3 -m services.verifier     # port block + 2   (Partner B)
python3 -m services.rp           # port block + 3   (Partner B)
```

Or start all four at once, one log per service under `run/`:

```bash
sh scripts/run_all.sh            # sh scripts/stop_all.sh to stop them
```

Both bind `0.0.0.0` by default. A service bound to `127.0.0.1` works on the
server and is invisible from campus, which is the second most common way to
fail the conformance probe.

Check they are up:

```bash
curl -s localhost:4102/health && curl -s localhost:4103/health
sh .claude/skills/lab1-conformance/scripts/smoke.sh team.json
```

## Tests

One command, all of it, never touching a running deployment:

```bash
python3 -m unittest discover -s tests -t .
```

The cross-review tests for Partner A's services skip with a printed reason
while those services are not running. To include them, point them at a
deployment:

```bash
LAB1_SUBJECT_URL=http://host:4100 LAB1_CSP_URL=http://host:4101 \
    python3 -m unittest discover -s tests -t .
```

## Conformance probe

```bash
python3 conformance_probe.py --config team.json --verbose
python3 conformance_probe.py --config team.json --json result.json
```

`result.json` must come from a run against the **deployed** system.

## The API, beyond the frozen contract

Every service exposes `GET /health`, `GET /transcript` and `POST /reset`. The
endpoints below are the team's own design choices, recorded in
[`docs/decisions.md`](docs/decisions.md).

**Verifier** (port block + 2)

| Endpoint | Caller | Purpose |
|---|---|---|
| `POST /binding` | CSP, with `X-Lab1-Binding-Token` | Hand over the `identifier -> scrypt record` binding (step 2) |
| `POST /authenticate` | Claimant | Prove control of the authenticator; returns a single-use assertion handle (step 4) |
| `POST /introspect` | RP, with `X-Lab1-Introspect-Token` | Redeem an assertion handle for the subscriber identifier (step 5) |

**Relying Party** (port block + 3)

| Endpoint | Caller | Purpose |
|---|---|---|
| `GET /` | anyone | The public resource — no credential of any kind |
| `GET /protected` | Claimant / Subscriber | `401` + `WWW-Authenticate` without a session (step 3), `200` with one (step 5) |
| `POST /session` | Subject | Exchange an assertion for a session, after the RP validates it with the Verifier |
| `POST /logout` | Subscriber | Revoke the session |

Session credentials are presented as `Authorization: Lab1-Session <token>`. A
request that is part of a scripted run carries its `run_id` in the `X-Run-Id`
header (or a `?run_id=` query parameter) so that `GET /protected`, which has no
body, still lands in the transcript under the right run.

## Who built what

**Partner A** owns the enrollment side: the Subject agent (the scripted flow,
the Applicant → Subscriber → Claimant transitions, `POST /run` and the five
scenarios) and the CSP (subscriber accounts, identity proofing policy,
authenticator issuance and secret hashing). **Partner B** owns the
authentication and access side: the Verifier (checking authenticator control
and issuing assertions) and the Relying Party (the public and protected
resources, the `401` challenge, and the session lifecycle), plus the shared
helpers in `shared/` and the negative tests for Partner A's two services in
`tests/test_partner_a_negative.py`. Each partner wrote the negative tests for
the other's services, and both can explain all four.
