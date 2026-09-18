# Written analysis — Lab 1, NIST SP 800-63-4 Figure 3

*Drafted by Partner B; Partner A edits. Sections marked **[A]** need the
enrollment side's detail once the Subject agent and CSP exist.*

## 1. What we built, mapped to Figure 3

Figure 3 of SP 800-63-4 is the non-federated model: a Credential Service
Provider, a Verifier and a Relying Party inside one trust boundary, with a
single subject moving through three roles as five numbered interactions take
place. We implemented the diagram literally — four processes, one per box, and
the subject as a scripted agent so that the role transitions are visible in
code rather than implied.

| Figure 3 element | Ours | Port |
|---|---|---|
| CSP | `services/csp` **[A]** | block + 1 |
| Verifier | `services/verifier` | block + 2 |
| Relying Party | `services/rp` | block + 3 |
| Subject (a human in the figure) | `services/subject` **[A]** | block + 0 |
| Trust boundary | One host, one organisation, no external identity provider | — |
| Arrows 1–5 | Five steps, each written to `/transcript` in every service that takes part | — |

The five steps as they actually run:

1. **Identity proofing and enrollment [A]** — the Applicant presents evidence to
   the CSP, which creates a subscriber account.
2. **Authenticator issuance** — the CSP issues an authenticator, hashes it with
   scrypt, and hands the Verifier the resulting record over
   `POST /binding`. The secret itself never crosses that boundary. This is where
   the Applicant becomes a Subscriber.
3. **Authentication request** — the Subscriber asks the RP for `/protected` and
   gets `401` with `WWW-Authenticate: Lab1-Session realm="lab1-rp"`. RFC 9110
   §15.5.2 requires that header on a `401`, and it is the single most forgotten
   line in this lab. Here the Subscriber becomes a Claimant.
4. **Authentication process** — the Claimant presents the authenticator output
   to the Verifier, which compares it against the CSP's record and, on success,
   mints an opaque single-use assertion handle.
5. **Authenticated session** — the Claimant hands the handle to the RP; the RP
   calls `POST /introspect` on the Verifier, and only the identifier that comes
   back in that response can become a session. `GET /protected` then returns
   `200`.

Ordering is provable rather than asserted: every event carries an ISO 8601 UTC
timestamp with millisecond precision from one shared helper
(`shared/timeutil.py`), so merging four transcripts by `ts` reconstructs the run.

## 2. The design decisions that mattered

The full register is in `docs/decisions.md`. Three choices carried the design.

**The assertion is an opaque, single-use handle, not a token that carries
identity.** This is the whole answer to `skip_verifier`. A signed JWT would have
been equally defensible on paper, but then the RP's decision would rest on
verifying a signature correctly, and the interesting failures — `alg` confusion,
a skipped `exp` check, the wrong key — move inside our own code. With a handle,
there is nothing to forge: the RP cannot learn an identifier except by asking
the Verifier, so "the RP concluded authenticated without the Verifier checking
anything" is not a bug we avoided, it is a state the program cannot reach.

**Service-to-service calls stay on loopback.** The Verifier → RP edge is the
load-bearing one, and it has no reason to leave the host all four services run
on. We found this the hard way: the first version resolved the Verifier through
the public URL in `team.json`, which sent internal traffic out across the campus
network and back — and hung for five seconds when that host was unreachable.

**Denials are uniform, including in the clock.** One status and one body for a
wrong secret, an unknown identifier and a malformed request, and the
unknown-identifier path does the same scrypt work as a real check before
refusing. Measured on the deployed services: 46.2 ms for an identifier that does
not exist against 48.1 ms for a wrong secret on one that does.

## 3. Two of the five steps an attacker defeats without breaking cryptography

**Step 1, identity proofing and enrollment.** Nothing here is cryptographic to
begin with, which is why it is the cheapest step to defeat. Our proofing is
self-asserted **[A]**: an applicant claims an identifier and the CSP creates the
account. An attacker does not need to break anything — they enroll. Even with a
stronger model (an invite code, an out-of-band enrollment token), the attack
does not become cryptographic, it becomes social: work out who can cause a code
to be issued and send them a plausible request. Every control downstream of step
1 then works perfectly, on an identity that was never verified. This is the
enrollment-fraud path, and it is how real breaches usually start.

**Step 5, the authenticated session.** The session credential is a bearer
credential: whoever holds it is treated as the subscriber, and reading one off
the wire is enough, because the lab is deployed over plain HTTP. No cryptography
is involved in the theft — the attacker copies a string. We pin each session to
the address it was issued to, which is a real cost to an attacker somewhere else
on campus and none at all to an attacker on the same host or behind the same
NAT. Logout revokes and the TTL expires, but both only bound the window; neither
prevents the copy.

A third, worth one slide: **step 4 by relay.** The authenticator here is a
secret the claimant sends to the Verifier. Anything that can persuade a claimant
to send it somewhere else authenticates the relayer just as well, and no
cryptography has been broken there either.

## 4. The weakest point, named plainly

**Enrollment.** Steps 2 through 5 are careful — secrets are salted and hashed
with scrypt, the assertion cannot be forged, sessions expire and can be revoked,
denials say nothing — and all of that care is spent enforcing a binding to an
identity nobody verified. The strongest authentication in the world answers "is
this the same party who enrolled?", never "is this party who they said they
were". An attacker who enrolls as somebody else gets a genuine authenticator, a
genuine assertion and a genuine session, and every transcript in the system says
`success`.

Second weakest, and the one we would fix first if this were real: the two shared
tokens in `.env` are static and long-lived, and whoever can read that file can
mint bindings at the Verifier — which is to say, become any subscriber. That
makes the host filesystem the actual trust anchor of the design.

There is deliberately **no account recovery path**. In a real system it would be
the front door with the weakest lock; we would rather say we have not built one
than build one late and have it quietly bypass step 4. SP 800-63B-4 prohibits
knowledge-based authentication ("what was your first pet"), so a recovery flow
would have to rest on something else — verify the prohibition's exact wording in
the PDF before saying so on a slide.

## 4b. The adversarial hour

Thirteen probes against our own services, with what each returned, is in
[`adversarial.md`](adversarial.md). The most interesting result was not a
break: our first "timing leak" turned out to be our own rate limiter firing,
and chasing that false positive produced the real finding — that per-address
rate limiting is close to useless in a deployment where every legitimate
request comes from the same host as an attacker's would.

## 5. Where the automated review was wrong

The six-question review is in `docs/security-review.md`, with a paragraph
judging its own output. The short version: the pass on question 2 is only worth
something because the architecture makes the failure unreachable — the same
review, run against a JWT design, would have produced the same verdict from the
same reading and been worth much less. And the review is soft on question 4 in
exactly the place a generic pass does not look: our rate limiting is nearly
useless in a deployment where every legitimate request arrives from the same
address as an attacker's would.

## 6. Where the AI misled us

The full log is `docs/ai-errors.md`. Three worth the presentation:

- It resolved an internal service-to-service call through the public campus URL,
  which worked in tests and hung in deployment. Running the thing found it;
  reading the code did not.
- It rated its own denial path as constant-time on inspection. Measuring it
  showed the first measurement was wrong for an unrelated reason (its own rate
  limiter, firing early), and the "finding" evaporated on a second look. An
  assistant is as confident when it is measuring the wrong thing as when it is
  right.
- It cannot verify NIST section numbers in this environment — the documents are
  not reachable from it. Every citation in these documents is therefore marked
  for checking against the PDF before the presentation, which is the discipline
  the lab asks for: quote or it does not exist.
