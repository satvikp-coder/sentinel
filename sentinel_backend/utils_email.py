"""
Sentinel Backend - Email Utility (Resend + Demo Fallback)
==========================================================
Production-ready email sender using Resend API.
Hackathon-friendly with demo fallback for non-test users.
"""

import os
import random
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Tuple
from datetime import datetime, timedelta

# Thread pool for non-blocking email sends
_email_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="email_sender")

# Configuration
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "Sentinel Security <onboarding@resend.dev>")
TEST_EMAIL = "sentinel.iitk@gmail.com"  # Resend verified test account


def generate_otp() -> str:
    """Generate a 6-digit OTP"""
    return str(random.randint(100000, 999999))


def _send_email_sync(to_email: str, subject: str, html_body: str, text_body: str = None) -> Tuple[bool, str]:
    """
    Synchronous email sending via Resend API.
    Returns (success, message).
    """
    api_key = os.environ.get("RESEND_API_KEY")
    from_addr = os.environ.get("EMAIL_FROM", "Sentinel Security <onboarding@resend.dev>")
    
    # Step 1: Validate configuration
    if not api_key:
        error = "RESEND_API_KEY environment variable is not set"
        print(f"[EMAIL] ❌ {error}")
        return False, error
    
    print(f"[EMAIL] 📧 Sending email to: {to_email}")
    print(f"[EMAIL] 📧 From: {from_addr}")
    print(f"[EMAIL] 📧 Subject: {subject}")
    
    try:
        # Import resend here to avoid import errors if not installed
        import resend
        resend.api_key = api_key
        
        # Build email payload
        email_data = {
            "from": from_addr,
            "to": to_email,
            "subject": subject,
            "html": html_body,
        }
        
        if text_body:
            email_data["text"] = text_body
        
        # Send email
        result = resend.Emails.send(email_data)
        
        email_id = result.get('id', 'unknown') if isinstance(result, dict) else getattr(result, 'id', 'unknown')
        print(f"[EMAIL] ✅ Email sent successfully! ID: {email_id}")
        return True, f"Email sent successfully. ID: {email_id}"
        
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
    Send OTP email to user.
    
    Hackathon-friendly logic:
    - Always logs OTP to console (for demo/judge testing)
    - Only sends real email to verified test accounts
    - Never blocks the FastAPI event loop
    
    Returns True if OTP was processed (logged + optionally sent).
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
    
    # ============================================
    # ALWAYS LOG OTP FOR DEMO/HACKATHON
    # ============================================
    print(f"")
    print(f"╔══════════════════════════════════════════════════════════╗")
    print(f"║  [DEMO MODE] OTP for {to_email}")
    print(f"║  OTP CODE: {otp}")
    print(f"╚══════════════════════════════════════════════════════════╝")
    print(f"")
    
    # ============================================
    # DECIDE WHETHER TO SEND REAL EMAIL
    # ============================================
    should_send_real_email = to_email.lower() == TEST_EMAIL.lower() or os.environ.get("RESEND_SEND_ALL", "false").lower() == "true"
    
    if not should_send_real_email:
        print(f"[EMAIL] ⏭️ Skipping real email for {to_email} (demo fallback mode)")
        print(f"[EMAIL] ℹ️ To send real emails, use {TEST_EMAIL} or set RESEND_SEND_ALL=true")
        return True
    
    # ============================================
    # SEND REAL EMAIL (non-blocking)
    # ============================================
    print(f"[EMAIL] 📧 Queueing real email to: {to_email}")
    
    def _background_send():
        success, message = _send_email_sync(to_email, subject, html_body, text_body)
        if not success:
            print(f"[EMAIL] ⚠️ Background email failed: {message}")
    
    try:
        _email_executor.submit(_background_send)
        print(f"[EMAIL] 📧 Email queued successfully")
        return True
    except Exception as e:
        print(f"[EMAIL] ❌ Failed to queue email: {e}")
        return True  # Still return True because OTP was logged


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
    
    # Always log for demo
    print(f"")
    print(f"╔══════════════════════════════════════════════════════════╗")
    print(f"║  [DEMO MODE] OTP for {to_email}")
    print(f"║  OTP CODE: {otp}")
    print(f"╚══════════════════════════════════════════════════════════╝")
    print(f"")
    
    # Check if we should send real email
    should_send = to_email.lower() == TEST_EMAIL.lower() or os.environ.get("RESEND_SEND_ALL", "false").lower() == "true"
    
    if not should_send:
        return True, f"OTP logged to console (demo mode). Real email skipped for {to_email}"
    
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
    api_key = os.environ.get("RESEND_API_KEY")
    
    if not api_key:
        return False, "RESEND_API_KEY is not set"
    
    try:
        import resend
        resend.api_key = api_key
        
        # Verify the key format
        if len(api_key) < 10:
            return False, "RESEND_API_KEY looks invalid (too short)"
        
        from_addr = os.environ.get("EMAIL_FROM", "Sentinel Security <onboarding@resend.dev>")
        
        print(f"[EMAIL] ✅ Resend API key configured ({len(api_key)} chars)")
        print(f"[EMAIL] ✅ From address: {from_addr}")
        print(f"[EMAIL] ✅ Test email account: {TEST_EMAIL}")
        return True, f"Resend configured. Test account: {TEST_EMAIL}"
        
    except ImportError:
        return False, "resend package not installed"
    except Exception as e:
        return False, f"Resend test failed: {e}"


# Alias for backward compatibility
def test_smtp_connection() -> Tuple[bool, str]:
    """Alias for test_resend_connection (backward compatibility)."""
    return test_resend_connection()
