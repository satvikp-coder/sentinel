"""
Sentinel Backend - Email Utility
================================
Production-ready SMTP email sender for OTP delivery.
Supports Railway deployment with proper error handling and logging.
"""

import os
import smtplib
import ssl
import asyncio
from email.message import EmailMessage
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

# Thread pool for non-blocking email sends
_email_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="email_sender")


def _get_smtp_config() -> dict:
    """Get SMTP configuration from environment variables."""
    config = {
        "server": os.getenv("SMTP_SERVER", "smtp.gmail.com"),
        "port": int(os.getenv("SMTP_PORT", "587")),
        "username": os.getenv("SMTP_USERNAME"),
        "password": os.getenv("SMTP_PASSWORD"),
        "from_addr": os.getenv("SMTP_FROM"),
    }
    
    # Fallback: SMTP_FROM defaults to SMTP_USERNAME if not set
    if not config["from_addr"]:
        config["from_addr"] = config["username"]
    
    return config


def _validate_smtp_config(config: dict) -> tuple[bool, str]:
    """Validate SMTP configuration. Returns (is_valid, error_message)."""
    missing = []
    
    if not config["server"]:
        missing.append("SMTP_SERVER")
    if not config["port"]:
        missing.append("SMTP_PORT")
    if not config["username"]:
        missing.append("SMTP_USERNAME")
    if not config["password"]:
        missing.append("SMTP_PASSWORD")
    
    if missing:
        return False, f"Missing SMTP config: {', '.join(missing)}"
    
    return True, ""


def _send_email_sync(to_email: str, subject: str, body: str) -> tuple[bool, str]:
    """
    Synchronous email sending via SMTP.
    Returns (success, message).
    
    This function is designed to be run in a thread pool.
    """
    config = _get_smtp_config()
    
    # Step 1: Validate configuration
    is_valid, error_msg = _validate_smtp_config(config)
    if not is_valid:
        print(f"[EMAIL] ❌ Config error: {error_msg}")
        return False, error_msg
    
    print(f"[EMAIL] 📧 Starting email send to: {to_email}")
    print(f"[EMAIL] 📧 SMTP Server: {config['server']}:{config['port']}")
    print(f"[EMAIL] 📧 From: {config['from_addr']}")
    
    try:
        # Step 2: Create email message
        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = subject
        msg["From"] = config["from_addr"]
        msg["To"] = to_email
        
        print(f"[EMAIL] 📧 Message created, connecting to SMTP...")
        
        # Step 3: Connect to SMTP server with timeout
        with smtplib.SMTP(config["server"], config["port"], timeout=30) as server:
            print(f"[EMAIL] 📧 Connected to SMTP server")
            
            # Step 4: Upgrade to TLS
            server.ehlo()
            print(f"[EMAIL] 📧 EHLO sent")
            
            context = ssl.create_default_context()
            server.starttls(context=context)
            print(f"[EMAIL] 📧 STARTTLS successful")
            
            server.ehlo()
            
            # Step 5: Authenticate
            print(f"[EMAIL] 📧 Authenticating as: {config['username']}")
            server.login(config["username"], config["password"])
            print(f"[EMAIL] 📧 Authentication successful")
            
            # Step 6: Send email
            server.send_message(msg)
            print(f"[EMAIL] ✅ Email sent successfully to: {to_email}")
            
            return True, "Email sent successfully"
            
    except smtplib.SMTPAuthenticationError as e:
        error = f"SMTP Authentication failed: {e}. Check SMTP_USERNAME and SMTP_PASSWORD (use Gmail App Password)"
        print(f"[EMAIL] ❌ {error}")
        return False, error
        
    except smtplib.SMTPConnectError as e:
        error = f"SMTP Connection failed: {e}. Check SMTP_SERVER and SMTP_PORT"
        print(f"[EMAIL] ❌ {error}")
        return False, error
        
    except smtplib.SMTPServerDisconnected as e:
        error = f"SMTP Server disconnected: {e}"
        print(f"[EMAIL] ❌ {error}")
        return False, error
        
    except smtplib.SMTPException as e:
        error = f"SMTP Error: {e}"
        print(f"[EMAIL] ❌ {error}")
        return False, error
        
    except TimeoutError as e:
        error = f"SMTP Timeout: Connection to {config['server']}:{config['port']} timed out"
        print(f"[EMAIL] ❌ {error}")
        return False, error
        
    except Exception as e:
        error = f"Unexpected error sending email: {type(e).__name__}: {e}"
        print(f"[EMAIL] ❌ {error}")
        return False, error


def send_otp_email(to_email: str, otp: str) -> bool:
    """
    Send OTP email to user (non-blocking).
    Uses thread pool to avoid blocking FastAPI event loop.
    
    Returns True if email was queued (not if it was sent successfully).
    """
    subject = "🛡️ Sentinel Security - Your Login OTP"
    body = f"""Hello,

Your One-Time Password (OTP) for Sentinel Security is:

    {otp}

This code expires in 10 minutes.
If you did not request this, please ignore this email.

— Sentinel Security Command Center
"""
    
    print(f"[EMAIL] 📧 Queueing OTP email to: {to_email}")
    
    def _background_send():
        success, message = _send_email_sync(to_email, subject, body)
        if not success:
            print(f"[EMAIL] ⚠️ Background email failed: {message}")
    
    # Submit to thread pool (non-blocking)
    try:
        _email_executor.submit(_background_send)
        print(f"[EMAIL] 📧 Email queued successfully")
        return True
    except Exception as e:
        print(f"[EMAIL] ❌ Failed to queue email: {e}")
        return False


async def send_otp_email_async(to_email: str, otp: str) -> tuple[bool, str]:
    """
    Async version that waits for email to be sent.
    Use this when you need to know if the email was actually sent.
    """
    subject = "🛡️ Sentinel Security - Your Login OTP"
    body = f"""Hello,

Your One-Time Password (OTP) for Sentinel Security is:

    {otp}

This code expires in 10 minutes.
If you did not request this, please ignore this email.

— Sentinel Security Command Center
"""
    
    print(f"[EMAIL] 📧 Sending OTP email (async) to: {to_email}")
    
    # Run in thread pool to avoid blocking event loop
    loop = asyncio.get_event_loop()
    success, message = await loop.run_in_executor(
        _email_executor,
        _send_email_sync,
        to_email,
        subject,
        body
    )
    
    return success, message


def test_smtp_connection() -> tuple[bool, str]:
    """
    Test SMTP connection without sending an email.
    Useful for debugging configuration issues.
    """
    config = _get_smtp_config()
    
    is_valid, error_msg = _validate_smtp_config(config)
    if not is_valid:
        return False, error_msg
    
    try:
        print(f"[EMAIL] 🔍 Testing SMTP connection to {config['server']}:{config['port']}")
        
        with smtplib.SMTP(config["server"], config["port"], timeout=10) as server:
            server.ehlo()
            context = ssl.create_default_context()
            server.starttls(context=context)
            server.ehlo()
            server.login(config["username"], config["password"])
            
            print(f"[EMAIL] ✅ SMTP connection test successful")
            return True, "SMTP connection successful"
            
    except Exception as e:
        error = f"SMTP test failed: {type(e).__name__}: {e}"
        print(f"[EMAIL] ❌ {error}")
        return False, error
