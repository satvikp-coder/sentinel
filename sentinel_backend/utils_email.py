"""
Sentinel Backend - Email Utility
================================
Minimal SMTP email sender for OTP delivery.
Uses standard library 'smtplib' to avoid heavy dependencies.
"""

import os
import smtplib
import logging
import threading
from email.message import EmailMessage
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Logger setup
logger = logging.getLogger("sentinel.email")

def _send_email_thread(to_email: str, subject: str, body: str):
    """
    Internal function to send email via SMTP.
    Executed in a separate thread to avoid blocking.
    """
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USERNAME")
    smtp_pass = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM", smtp_user)

    if not all([smtp_server, smtp_port, smtp_user, smtp_pass]):
        print("[EMAIL] SMTP configuration missing. Email not sent.")
        return

    try:
        print(f"[EMAIL] Attempting to send email to {to_email}")
        
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = smtp_from
        msg['To'] = to_email

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        
        print(f"[EMAIL] Email sent successfully to {to_email}")
        
    except Exception as e:
        print(f"[EMAIL] Failed to send email: {str(e)}")

def send_otp_email(to_email: str, otp: str) -> bool:
    """
    Send OTP email to user.
    Non-blocking (threaded).
    """
    subject = "Sentinel Security - Your Login OTP"
    body = f"""
Hello,

Your One-Time Password (OTP) for Sentinel Security is:

{otp}

This code expires in 10 minutes.
If you did not request this, please ignore this email.

Security Command Center
"""
    # Launch in thread provided we are in a context where threads are safe (standard python/fastapi)
    thread = threading.Thread(target=_send_email_thread, args=(to_email, subject, body))
    thread.daemon = True
    thread.start()
    
    return True
