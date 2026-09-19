# Design-choice register

The `[R]` parts of this lab come from the contract and from NIST. Everything
below is a `[C]` choice — ours to make, record, and defend in the presentation.

Rows marked **Partner A** are the enrollment side's to settle; they are filled
in here with what Partner B's services assume, so that Partner A can confirm or
change them rather than discover them in integration.

| Decision | Ours | Why | Anchor |
|---|---|---|---|
| Language / framework / data store | Python 3, standard library only (`http.server`), state in memory | Runs without sudo and without installing anything on the shared server; no framework debug mode to leak a stack trace; the flow is reset between runs anyway, so a database would add risk without adding capability | §9 "no sudo, everything runs from your home directory" |
| What proofing means here; IAL modeled | **Partner A to confirm.** Assumed: self-asserted identity with a CSP-issued enrollment secret; we claim to model IAL1 and no higher | The lab is about the *shape* of Figure 3, not about document verification; claiming more than we implement would be the more serious error | SP 800-63A-4 (verify the IAL1 wording in the PDF before the presentation) |
| Authenticator type | A single CSP-issued random secret, presented once to the Verifier | The harness dictates it: `POST /run` hands the Subject a `canary` and says "this is the string to use as the authenticator secret", so the authenticator is a shared secret the CSP issues rather than one the subscriber chooses | SP 800-63B-4 §3.1 catalogs the types — confirm the exact subsection for a CSP-issued secret before quoting it |
| How the assertion travels to the RP | An **opaque, single-use handle** that the RP introspects by calling the Verifier (`POST /introspect`) | It makes `skip_verifier` impossible by construction rather than merely rejected: the handle carries no identity, so forging one gains nothing, and the RP cannot learn an identifier without asking the Verifier. A signed JWT would be equally defensible but hands us key management, `alg` confusion and clock skew to defend as well | §7 recommended minimal default |
| How sessions end | Expiry (`LAB1_SESSION_TTL_SECONDS`, default 600s), explicit revocation on `POST /logout`, and total loss on `POST /reset` | The replay scenario needs revocation to be real, not cosmetic; expiry bounds a stolen credential even if nobody logs out | §7 requirement 7 |
| What the protected resource is | The subscriber's own account record at `GET /protected` | A plausible reason to protect it: it is personal data about one subscriber, and it is the natural thing an authenticated subscriber would come to the RP for | §10 "plausible reason to protect it" |
| How the first administrator comes to exist | There is none, deliberately | This lab authenticates only — no authorization roles, no admin/viewer split. The bootstrap problem here is the *shared token* between services, not an admin account: the tokens are generated at deployment and placed in `.env`, so whoever can write that file is the trust anchor | §7 "No authorization roles" |

## Choices inside Partner B's two services

| Decision | Ours | Why |
|---|---|---|
| Secret storage | `hashlib.scrypt`, 16-byte random salt per record, N=2^14, r=8, p=1 (`shared/pwhash.py`) | A password hashing function, as required; a bare SHA-256 store is brute-forceable at speed once stolen. The CSP creates the record, the Verifier checks against it, and the secret itself never crosses the boundary |
| Where the secret is hashed | At the CSP; the Verifier only ever holds the record | Keeps the number of services that touch a secret at the minimum the model allows (CSP at issuance, Verifier at each check) |
| Authenticating the CSP → Verifier edge | Shared token in `X-Lab1-Binding-Token`, from `.env`, compared with `secrets.compare_digest` | Without it, anyone who can reach the Verifier can bind an authenticator to any identifier and become that subscriber. The Verifier trusts the CSP for bindings, so that trust needs a credential behind it |
| Authenticating the RP → Verifier edge | Shared token in `X-Lab1-Introspect-Token` | An unauthenticated introspection endpoint leaks subscriber identifiers and lets an outsider burn valid assertions |
| Where service-to-service calls go | Loopback (`127.0.0.1:<port>`), not the public URL in `team.json` | All four services run on one host. Sending the assertion out across the campus network and back would put the load-bearing edge of the design on an untrusted wire |
| Challenge scheme on the `401` | `WWW-Authenticate: Lab1-Session realm="lab1-rp"` (RP), `Lab1-Authenticator realm="lab1-verifier"` (Verifier) | RFC 9110 §15.5.2 requires a challenge on a `401`. The scheme name is ours: `Bearer` belongs to OAuth, and this is the non-federated model |
| Quiet denials | One status and one body for every authentication failure, plus equal work on the unknown-identifier path (`burn_equivalent_work`) | A failure must not reveal whether the account existed — including through the clock. Measured: 46.2 ms for an unknown identifier against 48.1 ms for a wrong secret |
| Rate limiting | 10 attempts per client address per 60s window on `POST /authenticate`, counted per address and cleared on success | Keyed on the address rather than the identifier so that knowing a subscriber's identifier cannot be used to lock them out. Loose on purpose: every legitimate request in this deployment comes from the same host as an attacker's would, so a tight limit locks the lab out of itself. See `docs/analysis.md` — this control is weak here and we say so rather than claiming otherwise |
| Session credentials | `secrets.token_urlsafe(32)`, expiring, revocable, and pinned to the address they were issued to (`LAB1_RP_PIN_SESSION_TO_CLIENT`) | A cryptographic random source is required; pinning costs a stolen bearer credential most of its value. The setting exists because a client whose address changes mid-session would be logged out |
| Transcript `step_name` values | `identity_proofing_and_enrollment`, `authenticator_enrollment_issuance`, `authentication_request`, `authentication_process`, `authenticated_session` | Only the step numbers are fixed by the contract. These are the five strings `conformance_probe.py` itself uses, so we match them even though the probe does not check them. They live in one table (`shared/transcript.py`) so all four services cannot drift apart |
| Transcript `detail` | Literal strings only, never a request field | Log decisions, never inputs. Enforced two ways: the writer rejects a detail that does not look like a plain description, and `tests/test_no_secret_logging.py` fails the build if any `detail=` is built from a runtime value |

## Cross-partner interfaces Partner A needs

1. **`POST /binding` on the Verifier**, at enrollment, with the
   `X-Lab1-Binding-Token` header and a body of
   `{"run_id", "identifier", "verifier_record"}`, where `verifier_record` is the
   output of `shared.pwhash.hash_secret(canary)`. It answers `201` on success,
   `409` if the identifier is already bound, `401` without the token.
2. **`X-Run-Id` on `GET /protected`**, so step 3 lands in the RP transcript
   under the run the harness gave the Subject agent.
3. **`POST /session` on the RP**, with `{"run_id", "assertion"}`, where the
   assertion is the handle `POST /authenticate` returned to the Claimant. It
   answers `201` with `{"session", "expires_at", "identifier"}`.
4. **`Authorization: Lab1-Session <token>`** on `GET /protected` and
   `POST /logout`.
5. **Identifiers** must match `^[a-z0-9][a-z0-9._-]{2,63}$` (`shared/validate.py`).

If any of these has to change, it changes in `PROJECT_WORKFLOW.md` §5 or here
first, then in code — §13's integration rule.

## What `POST /run` has to do, scenario by scenario

Measured with `conformance_probe.py` against all four services running: 12 of
24 checks pass today. Every one of the eleven failures — all seven `H-*` and
all four `N-*` — is the same failure, that `POST /run` on the Subject answers
`404`. Partner B's two services already answer every call below; this is the
sequence that closes the gap.

Thread the `run_id` the harness gave you into **every** call and every
transcript event, in all four services. `canary` is the authenticator secret —
use it, never log it.

**`happy_path` → `success`**

1. CSP creates the subscriber account. Record step 1 on the **CSP** transcript
   with `actor: "applicant"` — the probe reads the Applicant → Subscriber →
   Claimant progression off the `actor` field (`H-ROL`), and step 1 is the only
   place `applicant` appears.
2. CSP hashes the canary with `shared.pwhash.hash_secret(canary)` and `POST`s
   it to the Verifier's `/binding` with the `X-Lab1-Binding-Token` header.
   Record step 2 on the **CSP** transcript (`H-ST2` looks there, not at the
   Verifier).
3. Subject `GET`s the RP's `/protected` with `X-Run-Id` **and no session**, and
   expects `401`. This has to happen *before* authentication: the RP records
   step 3 here, and `H-ORD` sorts every event by timestamp, so a `/protected`
   call made only at the end puts step 3 after step 5 and fails the check.
4. Subject `POST`s the Verifier's `/authenticate` with
   `{run_id, identifier, authenticator_output: canary}` and gets back
   `{"assertion": ...}`. The Verifier records step 4 with `actor: "claimant"`.
5. Subject `POST`s the RP's `/session` with `{run_id, assertion}` and gets back
   `{"session": ...}`. The RP validates the assertion with the Verifier and
   records step 5.
6. Subject `GET`s `/protected` again with
   `Authorization: Lab1-Session <session>` and expects `200`.
7. Answer `{"run_id", "scenario", "outcome": "success", "detail": "protected resource returned HTTP 200"}`.

**`wrong_authenticator` → `denied`** — steps 1–3 as above, then authenticate
with anything other than the canary. The Verifier answers `401`; stop there and
report `denied`. Never call `/session`, so no step 5 succeeds.

**`unenrolled_claimant` → `denied`** — skip enrollment entirely and authenticate
with an identifier that was never bound. Same `401`, byte for byte, as a wrong
authenticator: that sameness is the point.

**`replay` → `denied`** — run the happy path to a working session, `POST` the
RP's `/logout` with `Authorization: Lab1-Session <session>`, then `GET`
`/protected` with that same credential again and expect `401`. A successful
step 5 earlier in this run is expected and allowed.

**`skip_verifier` → `denied`** — enroll and bind, then go straight to the RP's
`/session` with a self-made assertion (or an `identifier` and no assertion) and
never call the Verifier. The RP answers `401` because introspection fails;
report `denied`.

### It is written, and tested

`services/subject/flow.py` implements all five, standard library only, with no
FastAPI or pydantic dependency so it can be tested directly. `POST /run` then
reduces to:

```python
from shared.transcript import Transcript
from services.subject.flow import Flow

transcript = Transcript()          # module level, shared with /transcript and /reset
flow = Flow(transcript)            # peers resolved from .env, on loopback

@app.post("/run")
async def run(body: RunRequest):
    return JSONResponse(status_code=200,
                        content=flow.run(body.run_id, body.scenario, body.canary))
```

`GET /transcript` becomes `{"events": transcript.events()}` and `POST /reset`
calls `transcript.reset()`, so all four services use one writer and one
timestamp helper.

`tests/test_subject_flow.py` drives it against the real Verifier and RP with a
stand-in CSP that meets the enrollment contract above, and asserts what the
probe asserts: all five steps present at the service that owns each, ascending
by timestamp, the role progression in order, the canary absent from every
transcript, and each of the four negatives denied with no successful step 5.

**What the CSP still owes**, and the flow assumes:

| Endpoint | Request | Must do |
|---|---|---|
| `POST /apply` | `{run_id, email, plaintext}` | store `shared.pwhash.hash_secret(plaintext)`, record **step 1 with `actor: "applicant"`**, return `{token}`. `plaintext` is a real password for a human applicant, or the harness's canary for a scripted run. |
| `POST /subscribe` | `{run_id, email, token}` | mark subscribed, `POST` the stored record to the Verifier's `/binding` with `X-Lab1-Binding-Token`, record **step 2** |
| `GET /activate` | query: `email, token` | human-facing equivalent of `/subscribe`, answers HTML instead of JSON |
| `GET /transcript` | — | `{"events": [...]}` |

### On timestamp precision

`shared/timeutil.py` emits **microseconds**, not milliseconds. The probe sorts
events by the timestamp string alone, so two events a fraction of a millisecond
apart - the CSP recording step 2 and the Subject recording step 3 - tie, and
the tie is broken by the order the probe collected the transcripts in, which is
not chronological. At millisecond precision that inversion failed `H-ORD` on
most runs; it was caught by `tests/test_subject_flow.py`, not by reasoning.
