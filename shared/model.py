"""Request and response shapes for the FastAPI services.

The transcript event shape is deliberately NOT here: it lives once, in
shared/transcript.py, with the writer that produces it and the one UTC
timestamp helper all four services use. Two definitions of the frozen event
shape is exactly the drift PROJECT_WORKFLOW.md section 10 warns about.
"""

from pydantic import BaseModel

# Run
class RunRequest(BaseModel):
    run_id: str
    scenario: str
    canary: str

class RunResponse(BaseModel):
    run_id: str
    scenario: str
    outcome: str
    detail: str

# Applicant
class ApplicantRequest(BaseModel):
    # run_id ties every transcript event to one probe run. plaintext is the
    # authenticator secret - a real password for a human applicant, or the
    # harness's canary value for a probe/test run; either way it is hashed
    # on arrival and never stored or logged in the clear.
    run_id: str
    email: str
    plaintext: str

class ApplicantResponse(BaseModel):
    token: str

# Subscriber
class SubscriberRequest(BaseModel):
    run_id: str
    email: str
    token: str

class SubscriberResponse(BaseModel):
    status: str
