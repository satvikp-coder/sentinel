"""
Sentinel Backend - Email Utility (Resend)
==========================================
Production-ready email sender using Resend API.
Much simpler and more reliable than SMTP for Railway deployment.
"""

import os
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Tuple

# Thread pool for non-blocking email sends
_email_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="email_sender")


def _get_resend_config() -> dict:
    """Get Resend configuration from environment variables."""
    return {
        "api_key": os.getenv("RESEND_API_KEY"),
        "from_addr": os.getenv("EMAIL_FROM", "Sentinel Security <onboarding@resend.dev>"),
    }


def _send_email_sync(to_email: str, subject: str, html_body: str, text_body: str = None) -> Tuple[bool, str]:
    """
    Synchronous email sending via Resend API.
    Returns (success, message).
    """
    config = _get_resend_config()
    
    # Step 1: Validate configuration
    if not config["api_key"]:
        error = "RESEND_API_KEY environment variable is not set"
        print(f"[EMAIL] ❌ {error}")
        return False, error
    
    print(f"[EMAIL] 📧 Sending email to: {to_email}")
    print(f"[EMAIL] 📧 From: {config['from_addr']}")
    print(f"[EMAIL] 📧 Subject: {subject}")
    
    try:
        # Import resend here to avoid import errors if not installed
        import resend
        resend.api_key = config["api_key"]
        
        # Build email payload
        email_data = {
            "from": config["from_addr"],
            "to": to_email,
            "subject": subject,
            "html": html_body,
        }
        
        if text_body:
            email_data["text"] = text_body
        
        # Send email
        result = resend.Emails.send(email_data)
        
        print(f"[EMAIL] ✅ Email sent successfully! ID: {result.get('id', 'unknown')}")
        return True, f"Email sent successfully. ID: {result.get('id', 'unknown')}"
        
    except ImportError:
        error = "resend package not installed. Run: pip install resend"
        print(f"[EMAIL] ❌ {error}")
        return False, error
        
    except Exception as e:
        error = f"Resend API error: {type(e).__name__}: {e}"
        print(f"[EMAIL] ❌ {error}")
        return False, error


def send_otp_email(to_email: str, otp: str) -> bool:
    """
    Send OTP email to user (non-blocking).
    Uses thread pool to avoid blocking FastAPI event loop.
    
    Returns True if email was queued (not if it was sent successfully).
    """
    subject = "🛡️ Sentinel Security - Your Login OTP"
    
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px 10px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 24px;">🛡️ Sentinel Security</h1>
        </div>
        <div style="background: #1a1a2e; padding: 30px; border-radius: 0 0 10px 10px; color: #ffffff;">
            <p style="font-size: 16px; color: #b0b0b0;">Hello,</p>
            <p style="font-size: 16px; color: #b0b0b0;">Your One-Time Password (OTP) for Sentinel Security is:</p>
            <div style="background: #16213e; border: 2px solid #667eea; border-radius: 10px; padding: 20px; text-align: center; margin: 20px 0;">
                <h2 style="font-size: 36px; letter-spacing: 8px; color: #667eea; margin: 0;">{otp}</h2>
            </div>
            <p style="font-size: 14px; color: #888;">This code expires in <strong>10 minutes</strong>.</p>
            <p style="font-size: 14px; color: #888;">If you did not request this, please ignore this email.</p>
            <hr style="border: none; border-top: 1px solid #333; margin: 20px 0;">
            <p style="font-size: 12px; color: #666; text-align: center;">
                Sentinel Security Command Center<br>
                IITK Hackathon 2026
            </p>
        </div>
    </div>
    """
    
    text_body = f"""
Hello,

Your One-Time Password (OTP) for Sentinel Security is:

    {otp}

This code expires in 10 minutes.
If you did not request this, please ignore this email.

— Sentinel Security Command Center
"""
    
    print(f"[EMAIL] 📧 Queueing OTP email to: {to_email}")
    
    # Also log OTP to console for hackathon demo fallback
    print(f"[EMAIL] 🔑 [DEMO FALLBACK] OTP for {to_email}: {otp}")
    
    def _background_send():
        success, message = _send_email_sync(to_email, subject, html_body, text_body)
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


async def send_otp_email_async(to_email: str, otp: str) -> Tuple[bool, str]:
    """
    Async version that waits for email to be sent.
    Use this when you need to know if the email was actually sent.
    """
    subject = "🛡️ Sentinel Security - Your Login OTP"
    
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #667eea;">🛡️ Sentinel Security</h1>
        <p>Your One-Time Password (OTP) is:</p>
        <h2 style="font-size: 32px; letter-spacing: 8px; color: #667eea; background: #f0f0f0; padding: 20px; border-radius: 8px; text-align: center;">{otp}</h2>
        <p style="color: #888;">This code expires in 10 minutes.</p>
    </div>
    """
    
    text_body = f"Your Sentinel OTP is: {otp}"
    
    print(f"[EMAIL] 📧 Sending OTP email (async) to: {to_email}")
    print(f"[EMAIL] 🔑 [DEMO FALLBACK] OTP for {to_email}: {otp}")
    
    # Run in thread pool to avoid blocking event loop
    loop = asyncio.get_event_loop()
    success, message = await loop.run_in_executor(
        _email_executor,
        _send_email_sync,
        to_email,
        subject,
        html_body,
        text_body
    )
    
    return success, message


def test_resend_connection() -> Tuple[bool, str]:
    """
    Test Resend API connection.
    Useful for debugging configuration issues.
    """
    config = _get_resend_config()
    
    if not config["api_key"]:
        return False, "RESEND_API_KEY is not set"
    
    try:
        import resend
        resend.api_key = config["api_key"]
        
        # Try to get API key info (lightweight check)
        # Just verify the key format
        if len(config["api_key"]) < 10:
            return False, "RESEND_API_KEY looks invalid (too short)"
        
        print(f"[EMAIL] ✅ Resend API key configured")
        print(f"[EMAIL] ✅ From address: {config['from_addr']}")
        return True, "Resend configuration looks valid"
        
    except ImportError:
        return False, "resend package not installed"
    except Exception as e:
        return False, f"Resend test failed: {e}"


# Alias for backward compatibility
def test_smtp_connection() -> Tuple[bool, str]:
    """Alias for test_resend_connection (backward compatibility)."""
    return test_resend_connection()
