import os
import sys
import smtplib
from email.mime.text import MIMEText
import re
import logging

logger = logging.getLogger("uvicorn.error")

class EmailService:
    def __init__(self, base_url):
        self.username = os.environ.get("EMAIL_USERNAME")
        self.password = os.environ.get("EMAIL_PASSWORD")
        self.base_url = base_url

        if not self.username:
            print("Warning: EMAIL_USERNAME not set. Email sending will be skipped.", file=sys.stderr)

        if not self.password:
            print("Warning: EMAIL_PASSWORD not set. Email sending will be skipped.", file=sys.stderr)

    @staticmethod
    def valid_email(email: str) -> bool:
        EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
        return bool(EMAIL_RE.match(email))

    def send_activation(self, email, token):
        if email == "example@example.com":
            logger.warning(f"Skipping activation email to '{email}': example email.")
            return False

        if not self.valid_email(email):
            logger.warning(f"Skipping activation email to '{email}': invalid email.")
            return False

        if not self.username or not self.password:
            logger.warning(f"Skipping activation email to '{email}': missing credentials.")
            return False

        url = f"http://{self.base_url}/subscribe?email={email}&token={token}"

        # msg = MIMEText(f"<a href='{url}'>Activate</a>", "html")
        msg = MIMEText(url)
        msg["Subject"] = "Activate Your SYSE 549 Account"
        msg["From"] = self.username
        msg["To"] = email

        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(self.username, self.password)
                server.send_message(msg)
            return True
        except Exception as e:
            print(f"Warning: failed to send activation email to {email}: {e}", file=sys.stderr)
            return False
