import os
import sys
import smtplib
from email.mime.text import MIMEText
from html import escape
from urllib.parse import urlencode
import re
import logging

logger = logging.getLogger("uvicorn.error")

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "templates", "activation_email.html")


class EmailService:
    def __init__(self, base_url):
        self.username = os.environ.get("EMAIL_USERNAME")
        self.password = os.environ.get("EMAIL_PASSWORD")
        # The public endpoint URL, scheme included (e.g. http://host:port) —
        # what a browser needs, not the host:port we bind to on the wire.
        self.base_url = base_url.rstrip("/")

        if not self.username:
            print("Warning: EMAIL_USERNAME not set. Email sending will be skipped.", file=sys.stderr)

        if not self.password:
            print("Warning: EMAIL_PASSWORD not set. Email sending will be skipped.", file=sys.stderr)

    @staticmethod
    def valid_email(email: str) -> bool:
        EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
        return bool(EMAIL_RE.match(email))

    def send_activation(self, email, token):
        if not self.valid_email(email):
            logger.warning(f"Skipping activation email to '{email}': invalid email.")
            return False

        if not self.username or not self.password:
            logger.warning(f"Skipping activation email to '{email}': missing credentials.")
            return False

        url = f"{self.base_url}/activate?{urlencode({'email': email, 'token': token})}"

        try:
            with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
                template = f.read()
        except OSError as e:
            print(f"Warning: could not read email template {TEMPLATE_PATH}: {e}", file=sys.stderr)
            return False
        html = template.replace("{{ACTIVATION_URL}}", escape(url))

        msg = MIMEText(html, "html")
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
