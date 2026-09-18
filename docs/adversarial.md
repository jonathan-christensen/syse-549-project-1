# The adversarial hour

Required by PROJECT_WORKFLOW.md §8.4. Run against **our own** services only —
the Verifier and RP on our claimed ports, never another team's.

Everything below was executed; the responses are what came back. Partner A's
Subject agent and CSP are not implemented yet, so the four probes that target
enrollment are listed at the end as not-yet-attempted rather than passed.

## What was tried

| # | Attack | Sent | Result |
|---|---|---|---|
| 1 | A made-up session credential | `Authorization: Lab1-Session ZZZ…` at `/protected` | `401` + `WWW-Authenticate` |
| 2 | A bearer token in the wrong scheme | `Authorization: Bearer not-a-real-token` | `401` — treated as no credential at all |
| 3 | Authenticate as an identifier never issued | `POST /authenticate` with `ghost-account` | `401 {"error":"authentication_failed"}` |
| 4 | Wrong authenticator for a real account | `POST /authenticate` with the wrong output | `401` — **byte-for-byte the same response as #3** |
| 5 | Mint a binding without the CSP token | `POST /binding`, no `X-Lab1-Binding-Token` | `401` |
| 6 | Redeem an assertion without the RP token | `POST /introspect`, no token | `401`, and the assertion was **not** consumed |
| 7 | Self-asserted identity at the RP | `POST /session` with `identifier`, no assertion | `401`, no session |
| 8 | Replay an assertion | the same handle exchanged twice | first `201`, second `401` |
| 9 | Replay a session after logout | logout, then reuse the credential | `401` |
| 10 | Use a session from another client | credential issued to `127.0.0.1`, presented from `127.0.0.9` | `401` |
| 11 | Online guessing | 12 wrong outputs from one address | ten `401`, then `429` |
| 12 | Malformed input | `{{{`, an unknown path, a wrong method | `400`, `404`, `405` — no trace, path or framework banner |
| 13 | Canary in the transcripts | full run with the canary as the secret | absent from every transcript |

### Timing, measured rather than assumed

An identifier that does not exist and a wrong secret for one that does must
cost the same, or the clock answers the question the response body refuses to.
Measured with a fresh source address per attempt, so the rate limiter never
engaged:

```
wrong secret, real account : 48.1 ms
unknown identifier         : 46.2 ms
difference                 :  1.9 ms  on a ~47 ms baseline
```

## The most interesting finding

**The rate limiter is close to useless here, and it hid a bug in our own
measurement before it admitted it.**

The first timing run reported 1 ms for an unknown identifier against 40 ms for
a wrong secret — an account-enumeration oracle, apparently, in code written
specifically to prevent one. It was not. Six requests from one address had
tripped our own rate limiter, and the "1 ms" was a `429` short-circuit. The
equalising code had been working the whole time.

Chasing that false positive produced the real finding. All four services run on
one host, and the Subject agent — which makes every legitimate authentication
attempt in the system — runs there too. Every request, honest or hostile,
arrives from the same address. So a per-address limit mostly denies *us*: a
probe run can lock itself out, and an attacker on the same host is
indistinguishable from the Subject agent. We raised the limit to ten, cleared
it on success and on `/reset`, and record it here as a weakness rather than
presenting it as a control.

The general lesson is the one worth four minutes of the presentation: a control
copied from a normal deployment can be worse than useless in an unusual one,
and an automated measurement reports a wrong number with exactly the confidence
it reports a right one.

## Second finding: the client pinning will not survive the deployment

Probe 10 passes because the RP pins a session to the address it was issued to.
Behind the campus nginx reverse proxy, every request reaches the RP from
`127.0.0.1`, so all clients become identical and the control silently stops
discriminating. It is not a vulnerability introduced by the proxy — the
credential was always a bearer credential — but it is a control that reads as
active while doing nothing, which is worse than not having it.

Either set `LAB1_RP_PIN_SESSION_TO_CLIENT=0` and say why, or read `X-Real-IP`,
which is only safe because the service is then loopback-only and cannot be
reached directly to spoof the header.

## Not yet attempted — needs Partner A's services

These are the enrollment-side probes from §8.4. They are written as executable
tests in `tests/test_partner_a_negative.py` and skip until the Subject agent
and CSP are running:

- enroll twice with the same identity
- bind an authenticator to somebody else's account
- a malformed enrollment body (must not answer `5xx`)
- the cheapest **social** attack on whatever proofing turns out to be — the one
  that needs no cryptography at all, and the one we expect to be the weakest
  point in the whole system
