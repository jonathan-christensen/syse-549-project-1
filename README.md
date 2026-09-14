# Lab 1 — NIST SP 800-63-4 Figure 3, non-federated digital identity model

Four services, five steps, one subject moving through three roles, all inside a
single trust boundary. The model, the contract and the grading criteria are in
[`PROJECT_WORKFLOW.md`](PROJECT_WORKFLOW.md); this file is how to run it.

Python 3.8+ and the standard library. Nothing to install, no sudo, no database.

## Services and ports

Ports are `LAB1_PORT_BLOCK` plus a fixed offset, so one setting moves all four.

| Service | Offset | Default port | Owner | Status |
|---|---|---|---|---|
| Subject agent | +0 | 4100 | Partner A | partial |
| CSP | +1 | 4101 | Partner A | implemented |
| Verifier | +2 | 4102 | Partner B | implemented |
| Relying Party | +3 | 4103 | Partner B | implemented |

> **Before deploying:** the port block and team name here are placeholders. Claim
> four consecutive ports in 4100–4199 on the Canvas discussion, then set
> `LAB1_TEAM` and `LAB1_PORT_BLOCK` in `.env` and update the URLs in `team.json`.

## Running it from a clean checkout

```bash
git clone <this repo> && cd syse-549-project-1
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(32))"   # once per token
$EDITOR .env        # paste one token into each of the two token settings
```

Then start each service in its own terminal (or under `tmux`/`nohup` on the
server — no sudo, everything from your home directory):

```bash
python3 -m services.subject      # port block + 0
python3 -m services.csp          # port block + 1
python3 -m services.verifier     # port block + 2
python3 -m services.rp           # port block + 3
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
