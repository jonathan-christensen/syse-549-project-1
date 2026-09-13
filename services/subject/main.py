from fastapi import FastAPI
from fastapi.responses import JSONResponse
import os
from typing import List
import uvicorn
import requests
from dotenv import load_dotenv

from shared.model import RunRequest, RunResponse, EventResponse, SubscriberResponse, ApplicantRequest, ApplicantResponse

load_dotenv()

SERVICE = "subject"
TEAM = os.getenv("TEAM")
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("SUBJECT_PORT"))
CSP_URL =  HOST + ":" + os.getenv("CSP_PORT")

def become_applicant(email):
    request = ApplicantRequest(email=email)

    response = requests.post(
        CSP_URL + "/apply",
        json=request.model_dump(),
    )
    response.raise_for_status()

    return ApplicantResponse(**response.json())

def become_subscriber(email, token) -> SubscriberResponse:
    response = requests.get(
        CSP_URL + "/subscribe",
        params={"email": email, "token": token}
    )
    response.raise_for_status()

    return SubscriberResponse(**response.json())

def become_claimant() -> str:
    return

events = EventResponse()

app = FastAPI(title=SERVICE)

@app.get("/health")
async def health():
    return JSONResponse(status_code=200, content={ "service": SERVICE, "team": TEAM, "spec_version": "1.0" })

@app.get("/transcript")
async def transcript():
    EventResponse(events=transcript)
    return JSONResponse(status_code=200, content=events)

@app.post("/reset")
async def reset():
    events.reset()
    return JSONResponse(status_code=200, content={"status": "ok"})

@app.post("/run")
async def run(body: RunRequest):
    email = body.run_id

    token = become_applicant(email)
    become_subscriber(email, token)

    # event = Event(
    #     seq=1,
    #     run_id=body.run_id,
    #     step=1,
    #     step_name="step-1",
    #     actor=SERVICE,
    #     peer="relying-party",
    #     outcome="success",
    #     ts=Event.get_timestamp(),
    #     detail="Request processed without errors",
    # )

    # events.append(event)

    response = RunResponse(
        run_id="probe-happy_path-8f3a1c",
        scenario="happy_path",
        outcome="success",
        detail="Request processed without errors",
    )

    return JSONResponse(status_code=200, content=response)

if __name__ == "__main__":
    uvicorn.run(
        "services.subject.main:app",
        host=HOST,
        port=PORT,
        reload=True
    )
