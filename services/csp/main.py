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

from html import escape

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
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
from shared.validate import (
    MAX_OUTPUT_LEN,
    MIN_OUTPUT_LEN,
    normalize_identifier,
    valid_authenticator_output,
)
from services.csp.email_service import EmailService

SERVICE = "csp"
TEAM = config.team_name()
HOST = config.bind_host()
PORT = config.port_for(SERVICE)

VERIFIER_URL = config.internal_endpoint_for("verifier")
BINDING_TOKEN = config.require_secret("LAB1_CSP_BINDING_TOKEN")
# The link mailed to an applicant has to resolve for them, not for us: the
# bind host is 0.0.0.0 on the wire but means nothing in a browser.
PUBLIC_URL = config.endpoint_for(SERVICE)

transcript = Transcript()

app = FastAPI(title=SERVICE)

user_db = UserDatabase()
email_service = EmailService(PUBLIC_URL)

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
    if identifier is None:
        transcript.record(
            run_id=body.run_id, step=1, actor="applicant", peer="csp",
            outcome="denied", detail="enrollment refused: malformed application",
        )
        return JSONResponse(status_code=400, content={"error": "invalid_request"})

    if not valid_authenticator_output(body.plaintext):
        # Rejected here, at the point of choice, so nobody enrolls with a
        # password that /authenticate would then never accept.
        transcript.record(
            run_id=body.run_id, step=1, actor="applicant", peer="csp",
            outcome="denied", detail="enrollment refused: password length not accepted",
        )
        return JSONResponse(status_code=400, content={
            "error": "invalid_password",
            "min_length": MIN_OUTPUT_LEN,
            "max_length": MAX_OUTPUT_LEN,
        })

    if user_db.is_subscribed(identifier):
        # Applying again for an account that already exists must not replace
        # its authenticator, or enrollment becomes an account-takeover path.
        transcript.record(
            run_id=body.run_id, step=1, actor="applicant", peer="csp",
            outcome="denied", detail="enrollment refused: identifier already claimed",
        )
        return JSONResponse(status_code=409, content={"error": "already_enrolled"})

    token = secrets.token_urlsafe(32)
    user_db.add_user(identifier, token, hash_secret(body.plaintext))
    email_service.send_activation(identifier, token)

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

def _complete_subscription(identifier, token, run_id):
    """Step 2. The applicant becomes a Subscriber and the authenticator is bound.

    Shared by the machine-facing POST /subscribe and the human-facing
    GET /activate below, so there is exactly one code path that ever finishes
    enrollment, whichever way a subscriber reaches it.
    """
    if identifier is None or not user_db.subscribe_user(identifier, token):
        transcript.record(
            run_id=run_id, step=2, actor="csp", peer="applicant",
            outcome="denied", detail="issuance refused: enrollment token not accepted",
        )
        return "invalid_token"

    record = user_db.verifier_record(identifier)
    try:
        status, _ = post_json(
            VERIFIER_URL + "/binding",
            {"run_id": run_id, "identifier": identifier, "verifier_record": record},
            headers={"X-Lab1-Binding-Token": BINDING_TOKEN},
        )
    except ServiceUnreachable:
        # A CSP that cannot reach the Verifier has issued nothing usable.
        transcript.record(
            run_id=run_id, step=2, actor="csp", peer="verifier",
            outcome="denied", detail="issuance incomplete: verifier unreachable",
        )
        return "verifier_unreachable"

    bound = status == 201
    transcript.record(
        run_id=run_id, step=2, actor="csp", peer="subscriber",
        outcome="success" if bound else "denied",
        detail="authenticator issued and bound to the subscriber account",
    )
    return "ok" if bound else "not_bound"

@app.post("/subscribe")
def subscribe(body: SubscriberRequest):
    """Step 2, for the Subject agent: JSON in, JSON out."""
    identifier = normalize_identifier(body.email)
    result = _complete_subscription(identifier, body.token, body.run_id)
    status_code = {
        "ok": 200, "invalid_token": 400,
        "verifier_unreachable": 503, "not_bound": 502,
    }[result]
    return JSONResponse(
        status_code=status_code,
        content=SubscriberResponse(status="ok" if result == "ok" else "error").model_dump(),
    )

def _activation_page(title: str, message: str) -> str:
    safe_title = escape(title)
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<title>%s</title></head><body><h1>%s</h1><p>%s</p></body></html>"
        % (safe_title, safe_title, escape(message))
    )

@app.get("/activate", response_class=HTMLResponse)
def activate(email: str, token: str):
    """Step 2, for a human: the link mailed by /apply, answered with a page.

    Not part of the machine contract — the Subject agent drives step 2
    through the JSON POST /subscribe above, not this endpoint.
    """
    identifier = normalize_identifier(email)
    result = _complete_subscription(identifier, token, None)
    if result == "ok":
        return HTMLResponse(_activation_page(
            "Account activated",
            "Your account is active. You can now sign in with your authenticator.",
        ))
    if result == "verifier_unreachable":
        return HTMLResponse(_activation_page(
            "Activation incomplete",
            "We could not finish setting up your account. Please try the link again shortly.",
        ), status_code=503)
    return HTMLResponse(_activation_page(
        "Activation failed",
        "This activation link is invalid or has already been used.",
    ), status_code=400)

if __name__ == "__main__":
    uvicorn.run(
        "services.csp.main:app",
        host=HOST,
        port=PORT,
    )
