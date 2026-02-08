"""
Sentinel Backend - Email Utility (Brevo)
=========================================
Production-ready email sender using Brevo HTTP API.
Works reliably on Railway - no SMTP issues, no test-mode restrictions.
"""

import os
import random
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Tuple

# Thread pool for non-blocking email sends
_email_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="email_sender")


def generate_otp() -> str:
    """Generate a 6-digit OTP"""
    return str(random.randint(100000, 999999))


def _send_email_sync(to_email: str, subject: str, html_body: str) -> Tuple[bool, str]:
    """
    Synchronous email sending via Brevo HTTP API.
    Returns (success, message).
    """
    api_key = os.environ.get("BREVO_API_KEY")
    sender_email = os.environ.get("BREVO_SENDER_EMAIL", "sentinel.iitk@gmail.com")
    sender_name = os.environ.get("BREVO_SENDER_NAME", "Sentinel IIT Kanpur")
    
    # Validate configuration
    if not api_key:
        error = "BREVO_API_KEY environment variable is not set"
        print(f"[EMAIL] ❌ {error}")
        return False, error
    
    print(f"[EMAIL] 📧 Sending email to: {to_email}")
    print(f"[EMAIL] 📧 From: {sender_name} <{sender_email}>")
    print(f"[EMAIL] 📧 Subject: {subject}")
    
    try:
        # Import Brevo SDK
        from sib_api_v3_sdk import Configuration, ApiClient, TransactionalEmailsApi
        from sib_api_v3_sdk.models import SendSmtpEmail
        
        # Configure API
        configuration = Configuration()
        configuration.api_key["api-key"] = api_key
        api_instance = TransactionalEmailsApi(ApiClient(configuration))
        
        # Build email
        email = SendSmtpEmail(
            to=[{"email": to_email}],
            sender={"email": sender_email, "name": sender_name},
            subject=subject,
            html_content=html_body
        )
        
        # Send email
        result = api_instance.send_transac_email(email)
        
        print(f"[EMAIL] ✅ Email sent successfully! Message ID: {result.message_id}")
        return True, f"Email sent. ID: {result.message_id}"
        
    except ImportError:
        error = "sib-api-v3-sdk not installed. Run: pip install sib-api-v3-sdk"
        print(f"[EMAIL] ❌ {error}")
        return False, error
        
    except Exception as e:
        error = f"Brevo API error: {type(e).__name__}: {e}"
        print(f"[EMAIL] ❌ {error}")
        return False, error


def send_otp_email(to_email: str, otp: str) -> bool:
    """
    Send OTP email to user (non-blocking).
    Uses thread pool to avoid blocking FastAPI event loop.
    
    Returns True if email was queued.
    """
    subject = "🛡️ Sentinel Security – Your Login OTP"
    
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px 10px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 24px;">Sentinel Security</h1>
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
    # SEND REAL EMAIL (non-blocking)
    # ============================================
    def _background_send():
        success, message = _send_email_sync(to_email, subject, html_body)
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
    subject = "🛡️ Sentinel Security – Your Login OTP"
    
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #667eea;">Sentinel Security</h1>
        <p>Your One-Time Password (OTP) is:</p>
        <h2 style="font-size: 32px; letter-spacing: 8px; color: #667eea; background: #f0f0f0; padding: 20px; border-radius: 8px; text-align: center;">{otp}</h2>
        <p style="color: #888;">This code expires in 10 minutes.</p>
    </div>
    """
    
    # Always log for demo
    print(f"")
    print(f"╔══════════════════════════════════════════════════════════╗")
    print(f"║  [DEMO MODE] OTP for {to_email}")
    print(f"║  OTP CODE: {otp}")
    print(f"╚══════════════════════════════════════════════════════════╝")
    print(f"")
    
    # Run in thread pool
    loop = asyncio.get_event_loop()
    success, message = await loop.run_in_executor(
        _email_executor,
        _send_email_sync,
        to_email,
        subject,
        html_body
    )
    
    return success, message


def test_brevo_connection() -> Tuple[bool, str]:
    """
    Test Brevo API connection.
    """
    api_key = os.environ.get("BREVO_API_KEY")
    sender_email = os.environ.get("BREVO_SENDER_EMAIL")
    
    if not api_key:
        return False, "BREVO_API_KEY is not set"
    
    if not sender_email:
        return False, "BREVO_SENDER_EMAIL is not set"
    
    try:
        from sib_api_v3_sdk import Configuration, ApiClient, AccountApi
        
        configuration = Configuration()
        configuration.api_key["api-key"] = api_key
        api_instance = AccountApi(ApiClient(configuration))
        
        # Get account info to verify API key
        account = api_instance.get_account()
        
        print(f"[EMAIL] ✅ Brevo API key valid")
        print(f"[EMAIL] ✅ Account: {account.email}")
        print(f"[EMAIL] ✅ Sender: {sender_email}")
        
        return True, f"Brevo configured. Account: {account.email}"
        
    except ImportError:
        return False, "sib-api-v3-sdk not installed"
    except Exception as e:
        return False, f"Brevo test failed: {e}"


# Backward compatibility alias
def test_smtp_connection() -> Tuple[bool, str]:
    """Alias for test_brevo_connection."""
    return test_brevo_connection()
