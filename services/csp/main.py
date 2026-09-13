from fastapi import FastAPI
from fastapi.responses import JSONResponse
import os
import uvicorn
import secrets
import string
from dotenv import load_dotenv

from shared.model import VerifierResponse, SubscriberResponse, Event, EventResponse, ApplicantRequest, ApplicantResponse, VerifierRequest
from services.csp.user_database import UserDatabase
from services.csp.email_service import EmailService

load_dotenv()

SERVICE = "csp"
TEAM = os.getenv("TEAM")
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("CSP_PORT", "8000"))
BASE_URL = HOST + ":" + str(PORT)

app = FastAPI(title=SERVICE)

user_db = UserDatabase()
email_service = EmailService(BASE_URL)

events = EventResponse()

@app.get("/health")
async def health():
    return { "service": SERVICE, "team": TEAM, "spec_version": "1.0" }

@app.get("/transcript")
async def transcript():
    return JSONResponse(status_code=200, content= Event())

@app.post("/reset")
async def reset():
    user_db.reset()
    events.reset()
    return JSONResponse(status_code=200, content={"status": "ok"})

@app.post("/apply")
async def apply(body: ApplicantRequest):
    token=secrets.token_urlsafe(32)

    # Generate a 32 character alphanumeric token
    alphabet = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(alphabet) for _ in range(32))

    response = ApplicantResponse(
        token=None,
        message="success"
    )

    try:
        user_db.add_user(body.email, body.plaintext, token)
        email_service.send_activation(body.email, token)
        status_code = 200
        response.token = token
        response.message = "success"
    except ValueError as e:
        status_code = 400
        response.message = "user already subscribed"

    return JSONResponse(status_code=status_code, content=response.model_dump())

@app.get("/subscribe")
async def subscribe(email: str, token: str):
    response = SubscriberResponse(
        message="failure"
    )

    try:
        user_db.subscribe(email, token)
        status_code = 200
        response.message = "success"
    except LookupError as e:
        status_code = 400
        response.message = "user not found"
    except ValueError as e:
        status_code = 400
        response.message = "user already subscribed"
    except PermissionError as e:
        status_code = 400
        response.message = "invalid token"
    except Exception as e:
        status_code = 400
        response.message = "failure"

    return JSONResponse(
        status_code=status_code,
        content=response.model_dump()
    )

@app.post("/verify")
async def verify(body: VerifierRequest):
    status_code = 200

    response = VerifierResponse(
        verified=False,
        message="failure"
    )
    
    try:
        response.verified = user_db.verify(body.email, body.plaintext)

        if response.verified:
            status_code = 200
            response.message = "success"
        else:
            status_code = 400
            response.message = "failure"
    except LookupError as e:
        status_code = 400
        response.message = "user not found"
    except ValueError as e:
        status_code = 400
        response.message = "user already subscribed"
    except Exception as e:
        status_code = 400
        response.message = "failure"

    return JSONResponse(
        status_code=status_code,
        content=response.model_dump()
    )

if __name__ == "__main__":
    uvicorn.run(
        "services.csp.main:app",
        host=HOST,
        port=PORT,
        reload=True
    )
