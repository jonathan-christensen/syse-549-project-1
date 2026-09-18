"""The Credential Service Provider — Figure 3, port block + 1. Partner A.

Owns the subscriber accounts and the authenticator. Two steps of the five:

  1. identity proofing and enrollment — POST /apply
  2. authenticator issuance and binding — POST /subscribe

Proofing here is control of an email address: an applicant supplies one and
gets back a token, and presenting that token is the evidence that makes them a
Subscriber. The authenticator secret is hashed with scrypt on arrival and never
stored in the clear; what crosses the boundary to the Verifier is that salted
digest, never the secret.

The CSP deliberately does NOT decide who is authenticated. That is the
Verifier's job, and keeping it there is what the skip_verifier scenario tests.
"""

from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn
import secrets
from dotenv import load_dotenv

# Before any configuration is read: a .env loaded afterwards has no effect.
load_dotenv()

from shared import config
from shared.httpjson import ServiceUnreachable, post_json
from shared.model import ApplicantRequest, ApplicantResponse, SubscriberRequest, SubscriberResponse
from shared.pwhash import hash_secret
from shared.transcript import Transcript
from shared.user_database import UserDatabase
from shared.validate import normalize_identifier

SERVICE = "csp"
TEAM = config.team_name()
HOST = config.bind_host()
PORT = config.port_for(SERVICE)
RELOAD = config.bool_setting("LAB1_UVICORN_RELOAD", False)

VERIFIER_URL = config.internal_endpoint_for("verifier")
BINDING_TOKEN = config.require_secret("LAB1_CSP_BINDING_TOKEN")

# One writer, one timestamp helper, shared with the other three services.
transcript = Transcript()

# NOTE ON `def` vs `async def`
#
# Every handler below is a plain `def`, deliberately. FastAPI runs a non-async
# path operation in a threadpool, while an `async def` handler runs ON the
# event loop - so a blocking call inside one freezes the whole service, every
# other request included. These handlers block: they hash with scrypt, they
# touch sqlite, and they call the other services over HTTP with a synchronous
# client. As `async def` that showed up as /health timing out rather than
# refusing, because the socket was accepted and then never answered.

app = FastAPI(title=SERVICE)

user_db = UserDatabase()

@app.get("/health")
def health():
    return { "service": SERVICE, "team": TEAM, "spec_version": "1.0" }

@app.get("/transcript")
def get_transcript():
    return JSONResponse(status_code=200, content={"events": transcript.events()})

@app.post("/reset")
def reset():
    # Total, not partial: a half reset leaves an account behind and the next
    # run passes for the wrong reason.
    user_db.reset()
    transcript.reset()
    return JSONResponse(status_code=200, content={"status": "ok"})

@app.post("/apply")
def apply(body: ApplicantRequest):
    """Step 1. Create the subscriber account and issue the enrollment token."""
    identifier = normalize_identifier(body.email)
    if identifier is None or not body.canary:
        transcript.record(
            run_id=body.run_id, step=1, actor="applicant", peer="csp",
            outcome="denied", detail="enrollment refused: malformed application",
        )
        return JSONResponse(status_code=400, content={"error": "invalid_request"})

    if user_db.is_subscribed(identifier):
        # Applying again for an account that already exists must not replace
        # its authenticator, or enrollment becomes an account-takeover path.
        transcript.record(
            run_id=body.run_id, step=1, actor="applicant", peer="csp",
            outcome="denied", detail="enrollment refused: identifier already claimed",
        )
        return JSONResponse(status_code=409, content={"error": "already_enrolled"})

    token = secrets.token_urlsafe(32)
    user_db.add_user(identifier, token, hash_secret(body.canary))

    # actor="applicant" is load bearing: the probe reads the Applicant ->
    # Subscriber -> Claimant progression off this field, and this is the only
    # event that carries the first of the three.
    transcript.record(
        run_id=body.run_id, step=1, actor="applicant", peer="csp",
        outcome="success", detail="evidence accepted, subscriber account created",
    )
    return JSONResponse(
        status_code=201,
        content=ApplicantResponse(token=token).model_dump(),
    )

@app.post("/subscribe")
def subscribe(body: SubscriberRequest):
    """Step 2. The applicant becomes a Subscriber and the authenticator is bound."""
    identifier = normalize_identifier(body.email)
    subscribed = identifier is not None and user_db.subscribe_user(identifier, body.token)

    if not subscribed:
        transcript.record(
            run_id=body.run_id, step=2, actor="csp", peer="applicant",
            outcome="denied", detail="issuance refused: enrollment token not accepted",
        )
        return JSONResponse(
            status_code=400,
            content=SubscriberResponse(status="error").model_dump(),
        )

    record = user_db.verifier_record(identifier)
    try:
        status, _ = post_json(
            VERIFIER_URL + "/binding",
            {"run_id": body.run_id, "identifier": identifier,
             "verifier_record": record},
            headers={"X-Lab1-Binding-Token": BINDING_TOKEN},
        )
    except ServiceUnreachable:
        # A CSP that cannot reach the Verifier has issued nothing usable.
        transcript.record(
            run_id=body.run_id, step=2, actor="csp", peer="verifier",
            outcome="denied", detail="issuance incomplete: verifier unreachable",
        )
        return JSONResponse(
            status_code=503,
            content=SubscriberResponse(status="error").model_dump(),
        )

    bound = status == 201
    transcript.record(
        run_id=body.run_id, step=2, actor="csp", peer="subscriber",
        outcome="success" if bound else "denied",
        detail="authenticator issued and bound to the subscriber account",
    )
    return JSONResponse(
        status_code=200 if bound else 502,
        content=SubscriberResponse(status="ok" if bound else "error").model_dump(),
    )

if __name__ == "__main__":
    uvicorn.run(
        "services.csp.main:app",
        host=HOST,
        port=PORT,
        reload=RELOAD
    )
