"""
User Authentication Module
==========================
Simple user authentication with password hashing and admin seeding.
"""

import json
import hashlib
import os
from pathlib import Path
from typing import Optional, Dict
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta

# ============================================
# USER DATA FILE
# ============================================
DATA_FILE = Path(__file__).parent / "users.json"

# ============================================
# MODELS
# ============================================

class User(BaseModel):
    email: str
    password_hash: str
    role: str = "OPERATOR"
    created_at: str = None
    is_admin: bool = False

    def __init__(self, **data):
        if data.get('created_at') is None:
            data['created_at'] = datetime.utcnow().isoformat()
        super().__init__(**data)


class LoginRequest(BaseModel):
    email: str
    password: str


class SignupRequest(BaseModel):
    email: str
    password: str
    role: str = "OPERATOR"


class AuthResponse(BaseModel):
    success: bool
    message: str
    user: Optional[Dict] = None


# ============================================
# PASSWORD HASHING
# ============================================

def hash_password(password: str) -> str:
    """Hash password using SHA256 with salt"""
    salt = "sentinel_secure_salt_2024"
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash"""
    return hash_password(password) == password_hash


# ============================================
# USER STORAGE
# ============================================

def load_users() -> Dict[str, Dict]:
    """Load users from JSON file"""
    try:
        if DATA_FILE.exists():
            with open(DATA_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"CRITICAL ERROR loading users: {e}")
    return {}


def save_users(users: Dict[str, Dict]):
    """Save users to JSON file with flush"""
    try:
        # Atomic write pattern could be used, but keeping it simple as requested
        with open(DATA_FILE, 'w') as f:
            json.dump(users, f, indent=2)
            f.flush()
            os.fsync(f.fileno()) # Force write to disk
        print(f"SUCCESS: Saved {len(users)} users to {DATA_FILE}")
    except Exception as e:
        print(f"CRITICAL ERROR saving users: {e}")
        raise e


def get_user(email: str) -> Optional[User]:
    """Get user by email"""
    users = load_users()
    if email.lower() in users:
        return User(**users[email.lower()])
    return None


def create_user(email: str, password: str, role: str = "OPERATOR", is_admin: bool = False) -> User:
    """Create a new user"""
    users = load_users()
    
    user = User(
        email=email.lower(),
        password_hash=hash_password(password),
        role=role,
        is_admin=is_admin
    )
    
    users[email.lower()] = user.dict()
    save_users(users)
    return user


def user_exists(email: str) -> bool:
    """Check if user exists"""
    users = load_users()
    return email.lower() in users


# ============================================
# AUTHENTICATION
# ============================================

def login(email: str, password: str) -> AuthResponse:
    """Authenticate user"""
    user = get_user(email)
    
    if not user:
        return AuthResponse(
            success=False,
            message="You are not registered. Create an account to continue."
        )
    
    if not verify_password(password, user.password_hash):
        return AuthResponse(
            success=False,
            message="Invalid password. Please try again."
        )
    
    # Generate and send OTP (Non-blocking)
    otp = generate_otp()
    users = load_users()
    if email.lower() in users:
        users[email.lower()]["otp"] = otp
        users[email.lower()]["otp_expiry"] = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        save_users(users)
        try:
            send_otp_email(user.email, otp)
        except Exception as e:
            print(f"Failed to send OTP email: {e}")
    
    return AuthResponse(
        success=True,
        message="Login successful. OTP sent.",
        user={
            "email": user.email,
            "role": user.role,
            "is_admin": user.is_admin
        }
    )


def signup(email: str, password: str, role: str = "OPERATOR") -> AuthResponse:
    """Register new user"""
    if user_exists(email):
        return AuthResponse(
            success=False,
            message="User already exists. Please login instead."
        )
    
    # Validate password
    if len(password) < 8:
        return AuthResponse(success=False, message="Password must be at least 8 characters")
    if not any(c.isupper() for c in password):
        return AuthResponse(success=False, message="Password must contain an uppercase letter")
    if not any(c.islower() for c in password):
        return AuthResponse(success=False, message="Password must contain a lowercase letter")
    if not any(c.isdigit() for c in password):
        return AuthResponse(success=False, message="Password must contain a number")
    if not any(c in "!@#$%^&*(),.?\":{}|<>_-+=[]\\/'`~;" for c in password):
        return AuthResponse(success=False, message="Password must contain a special character")
    
    user = create_user(email, password, role)
    
    # Generate and send OTP (Non-blocking)
    otp = generate_otp()
    users = load_users()
    if email.lower() in users:
        users[email.lower()]["otp"] = otp
        users[email.lower()]["otp_expiry"] = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        save_users(users)
        try:
            send_otp_email(user.email, otp)
        except Exception as e:
            print(f"Failed to send OTP email: {e}")

    return AuthResponse(
        success=True,
        message="Account created successfully. OTP sent.",
        user={
            "email": user.email,
            "role": user.role,
            "is_admin": user.is_admin
        }
    )



# ============================================
# OTP LOGIC
# ============================================

from utils_email import send_otp_email
import random

def generate_otp() -> str:
    """Generate 6-digit OTP"""
    return str(random.randint(100000, 999999))

def verify_otp(email: str, otp: str) -> bool:
    """Verify OTP for user"""
    user = get_user(email)
    if not user:
        return False
        
    # Check if OTP matches and is not expired (simple match for now)
    # TODO: Add expiry check using datetime
    
    users = load_users()
    stored_data = users.get(email.lower(), {})
    stored_otp = stored_data.get("otp")
    
    if stored_otp and stored_otp == otp:
        # Clear OTP after successful use
        stored_data["otp"] = None 
        users[email.lower()] = stored_data
        save_users(users)
        return True
        
    return False

# ============================================
# SEED ADMIN USER
# ============================================

def seed_admin():
    """Seed the default admin user"""
    admin_email = "satvikb0301@gmail.com"
    admin_password = "Satvik@559975"
    
    if not user_exists(admin_email):
        create_user(
            email=admin_email,
            password=admin_password,
            role="ADMIN",
            is_admin=True
        )
        print(f"✅ Admin user seeded: {admin_email}")
    else:
        print(f"ℹ️ Admin user already exists: {admin_email}")


# Seed admin on module import
seed_admin()
