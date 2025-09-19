import smtplib, os
from email.mime.text import MIMEText

MAIL_HOST = os.getenv("MAIL_HOST")
MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
MAIL_USER = os.getenv("MAIL_USER")
MAIL_PASS = os.getenv("MAIL_PASS")
FROM = MAIL_USER

def send_mail(to_email: str, subject: str, body: str):
    if not (MAIL_HOST and MAIL_USER and MAIL_PASS):
        return False
    msg = MIMEText(body, "html", "utf-8")
    msg["Subject"] = subject
    msg["From"] = FROM
    msg["To"] = to_email
    with smtplib.SMTP(MAIL_HOST, MAIL_PORT) as s:
        s.starttls()
        s.login(MAIL_USER, MAIL_PASS)
        s.send_message(msg)
    return True
