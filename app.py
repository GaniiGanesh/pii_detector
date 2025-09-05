import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import re
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
from collections import defaultdict
import io
import hashlib
import secrets
import sqlite3
import time
import os
import math
from datetime import datetime, timezone, timedelta

# ===================== PII DETECTION PATTERNS =====================
patterns = {
    # Aadhaar: exactly 12 digits, optional consistent separators, no leading/trailing digits
    # Detection is broad (allows 0/1 starts) so invalid ones are treated as false positives by validators
    # Matches either 12 contiguous digits or 4-4-4 with same separator (space or dash)
    "aadhaar": re.compile(r"(?<!\d)(?:\d{12}|(\d{4})([\-\s])\d{4}\2\d{4})(?![\d-])"),
    # Enhanced PAN pattern with word boundaries for better detection
    "pan": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    # RFC 5322 compliant email pattern (more comprehensive)
    "email": re.compile(r"\b[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b"),
    "phone": re.compile(r"\b[6-9]\d{9}\b")
}

def detect_pii(text):
    """Detect PII in text using the compiled patterns"""
    results = []
    safe_text = text or ""
    # Collect matches with spans for overlap resolution
    span_results = []  # (type, value, start, end)
    for pii_type, pattern in patterns.items():
        for m in pattern.finditer(safe_text):
            span_results.append((pii_type, m.group(0), m.start(), m.end()))

    if not span_results:
        return []

    # Never classify pure 12-digit sequences as credit cards
    span_results = [
        (t, v, s, e)
        for (t, v, s, e) in span_results
        if not (t == "credit_card" and len(re.sub(r"\D", "", v)) == 12)
    ]

    # Drop Aadhaar matches that are fully contained within any credit card match span
    credit_spans = [(s, e) for (t, _v, s, e) in span_results if t == "credit_card"]
    filtered_spans = []
    for (t, v, s, e) in span_results:
        if t == "aadhaar" and any(s >= cs and e <= ce for (cs, ce) in credit_spans):
            continue
        filtered_spans.append((t, v, s, e))

    # Also, if exact same string was detected as both types, prefer the more specific one
    # Here, prefer credit_card over aadhaar only when strings are identical
    values_by_type = {}
    for (t, v, _s, _e) in filtered_spans:
        values_by_type.setdefault(v, set()).add(t)
    final_list = []
    for (t, v, _s, _e) in filtered_spans:
        types_for_v = values_by_type.get(v, set())
        if "credit_card" in types_for_v and "aadhaar" in types_for_v:
            if t == "aadhaar":
                continue
        final_list.append((t, v))

    return final_list

# ---------------------------------------------------------
# 📌 Authentication System
# ---------------------------------------------------------
def init_db():
    """Initialize SQLite database for user authentication"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  username TEXT UNIQUE, 
                  password TEXT)''')
    
    # Create admin user if not exists, without hardcoding password in code
    c.execute("SELECT 1 FROM users WHERE username = ?", ("admin",))
    if c.fetchone() is None:
        # Prefer environment variable; otherwise generate a strong random password
        admin_plain = os.getenv("ADMIN_PASSWORD")
        if not admin_plain:
            admin_plain = secrets.token_urlsafe(12)
            # Best-effort notify the operator
            try:
                st.warning(f"Admin user created. Temporary password: {admin_plain}")
            except Exception:
                print(f"[SECURITY NOTICE] Admin user created with temporary password: {admin_plain}")
        admin_password_hash = hashlib.sha256(admin_plain.encode()).hexdigest()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                      ("admin", admin_password_hash))
        except sqlite3.IntegrityError:
            pass  # Race or already exists
    
    # Create table for de-identified data history
    c.execute('''CREATE TABLE IF NOT EXISTS deidentified_data
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT,
                  filename TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  filepath TEXT)''')
    
    # Create table for uploaded data tracking
    c.execute('''CREATE TABLE IF NOT EXISTS uploaded_data
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT,
                  original_filename TEXT,
                  file_size INTEGER,
                  row_count INTEGER,
                  column_count INTEGER,
                  upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  original_data_path TEXT)''')
    
    # Add original_data_path column if it doesn't exist (for existing databases)
    try:
        c.execute("ALTER TABLE uploaded_data ADD COLUMN original_data_path TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    

    # Create table for access logs
    c.execute('''CREATE TABLE IF NOT EXISTS access_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT,
                  action TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    
    conn.commit()
    conn.close()

def create_user(username, password):
    """Create a new user with hashed password"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Hash the password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                  (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists
    finally:
        conn.close()
def verify_user(username, password):
    """Verify user credentials"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Hash the provided password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", 
              (username, hashed_password))
    user = c.fetchone()
    conn.close()
    
    return user is not None

def get_all_users():
    """Get all users from the database (admin only)"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id, username, password FROM users")
    users = c.fetchall()
    conn.close()
    return users

def delete_user(user_id):
    """Delete a user from the database (admin only)"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    deleted = conn.total_changes > 0
    conn.close()
    return deleted

def save_deidentified_data(username, filename, filepath):
    """Save information about de-identified data"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    ist_time = get_ist_time()
    c.execute("INSERT INTO deidentified_data (username, filename, filepath, timestamp) VALUES (?, ?, ?, ?)",
              (username, filename, filepath, ist_time))
    conn.commit()
    conn.close()

def get_all_deidentified_data():
    """Get all de-identified data records (admin only)"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id, username, filename, timestamp, filepath FROM deidentified_data ORDER BY timestamp DESC")
    data = c.fetchall()
    conn.close()
    return data

def delete_deidentified_data(record_id):
    """Delete a de-identified data record (admin only)"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Get filepath before deleting
    c.execute("SELECT filepath FROM deidentified_data WHERE id = ?", (record_id,))
    result = c.fetchone()
    filepath = result[0] if result else None
    
    # Delete the record
    c.execute("DELETE FROM deidentified_data WHERE id = ?", (record_id,))
    conn.commit()
    deleted = conn.total_changes > 0
    conn.close()
    
    # Delete the actual file if it exists
    if filepath and os.path.exists(filepath):
        try:
            os.remove(filepath)
        except:
            pass  # Silently fail if file can't be deleted
    
    return deleted

def save_uploaded_data(username, original_filename, file_size, row_count, column_count, original_data_path):
    """Save information about uploaded data"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    ist_time = get_ist_time()
    c.execute("""INSERT INTO uploaded_data 
                 (username, original_filename, file_size, row_count, column_count, original_data_path, upload_timestamp) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)""",
              (username, original_filename, file_size, row_count, column_count, original_data_path, ist_time))
    conn.commit()
    conn.close()

def get_all_uploaded_data():
    """Get all uploaded data records (admin only)"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("""SELECT id, username, original_filename, file_size, row_count, column_count, 
                        upload_timestamp, original_data_path 
                 FROM uploaded_data ORDER BY upload_timestamp DESC""")
    data = c.fetchall()
    conn.close()
    return data

def save_access_log(username: str, action: str):
    """Save access log (login/signup/logout) with timestamp only."""
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        ist_time = get_ist_time()
        c.execute("INSERT INTO access_logs (username, action, timestamp) VALUES (?, ?, ?)", (username, action, ist_time))
        conn.commit()
        conn.close()
    except Exception:
        pass

def get_access_logs():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id, username, action, timestamp FROM access_logs WHERE username <> 'admin' ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def delete_all_access_logs():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("DELETE FROM access_logs WHERE username <> 'admin'")
    conn.commit()
    count = conn.total_changes
    conn.close()
    return count

def delete_uploaded_data(record_id):
    """Delete an uploaded data record (admin only)"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("DELETE FROM uploaded_data WHERE id = ?", (record_id,))
    conn.commit()
    deleted = conn.total_changes > 0
    conn.close()
    return deleted


def get_ist_time():
    """Get current time in Indian Standard Time"""
    ist = timezone(timedelta(hours=5, minutes=30))
    return datetime.now(ist).strftime('%Y-%m-%d %H:%M:%S')


def detect_device_browser():
    """Detect device and browser information.
    Tries to use streamlit-user-agent for accurate client-side detection; falls back to a simple heuristic.
    """
    try:
        # Prefer accurate client-side detection if the package is available
        from streamlit_user_agent import st_user_agent  # type: ignore
        ua = st_user_agent()
        # ua fields vary; normalize
        device_type = "Desktop"
        try:
            if getattr(ua, "is_mobile", False):
                device_type = "Mobile"
            elif getattr(ua, "is_tablet", False):
                device_type = "Tablet"
            else:
                device_type = "Desktop"
        except Exception:
            device_type = "Desktop"
        browser = getattr(ua, "browser", None) or getattr(ua, "browser_family", None) or "Unknown"
        return device_type, str(browser)
    except Exception:
        # Fallback: very rough heuristic based on a placeholder UA string
        user_agent = "Mozilla/5.0"
        device_type = "Desktop"
        if any(mobile in user_agent.lower() for mobile in ["android", "iphone", "ipad", "mobile"]):
            device_type = "Mobile"
        elif "tablet" in user_agent.lower() or "ipad" in user_agent.lower():
            device_type = "Tablet"
        browser = "Unknown"
        if "chrome" in user_agent.lower():
            browser = "Chrome"
        elif "firefox" in user_agent.lower():
            browser = "Firefox"
        elif "safari" in user_agent.lower() and "chrome" not in user_agent.lower():
            browser = "Safari"
        elif "edge" in user_agent.lower():
            browser = "Edge"
        elif "opera" in user_agent.lower():
            browser = "Opera"
        return device_type, browser


def create_session(username):
    """Create a new session for the user"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Create sessions table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT,
                  session_token TEXT,
                  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                  expires_at DATETIME)''')
    
    # Generate session token
    import hashlib
    import time
    session_token = hashlib.sha256(f"{username}{time.time()}".encode()).hexdigest()[:16]
    
    # Set expiration time (24 hours from now) and store as SQLite-friendly string
    from datetime import datetime, timedelta
    expires_at_str = (datetime.now() + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
    
    # Save session
    c.execute("INSERT INTO sessions (username, session_token, expires_at) VALUES (?, ?, ?)",
              (username, session_token, expires_at_str))
    
    # Clean up expired sessions
    c.execute("DELETE FROM sessions WHERE expires_at < datetime('now')")
    
    conn.commit()
    conn.close()
    
    return session_token

def verify_session(session_token, username):
    """Verify if a session token is valid"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    c.execute("SELECT * FROM sessions WHERE session_token = ? AND username = ? AND expires_at > datetime('now')",
              (session_token, username))
    session = c.fetchone()
    
    conn.close()
    return session is not None

def delete_session(session_token):
    """Delete a session token"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    c.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
    conn.commit()
    conn.close()


# Initialize the database
init_db()

# ---------------------------------------------------------
# 📌 Login Page
# ---------------------------------------------------------
def show_login_page():
    # Enhanced login page with better styling
    st.markdown("""
    <div style="text-align: center; padding: 2rem 0;">
        <h1 style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                   -webkit-background-clip: text; -webkit-text-fill-color: transparent; 
                   background-clip: text; font-size: 3rem; margin-bottom: 1rem;">
            PII De-Identification Tool
        </h1>
        <p style="font-size: 1.2rem; color: #666; margin-bottom: 2rem;">
            Secure • Fast • Reliable PII Detection & Anonymization
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    
    # Create tabs for Login and Sign Up with better styling
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    with tab1:
        st.markdown("### Welcome Back!")
        with st.form("login_form"):
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                username = st.text_input("Username", key="login_username", placeholder="Enter your username")
                password = st.text_input("Password", type="password", key="login_password", placeholder="Enter your password")
                remember_me = st.checkbox("Remember me", help="Keep me logged in across browser sessions")
                login_submitted = st.form_submit_button("Login", use_container_width=True)
            
            if login_submitted:
                if verify_user(username, password):
                    save_access_log(username, "Login")
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    
                    # Create session token for persistent login
                    session_token = create_session(username)
                    st.session_state.session_token = session_token
                    
                    # If remember me is checked, redirect with session token
                    if remember_me:
                        # Redirect with session token in URL
                        st.markdown(f"""
                        <script>
                        // Redirect with session token
                        const currentUrl = window.location.href.split('?')[0];
                        const newUrl = currentUrl + '?session_token={session_token}&username={username}';
                        window.location.href = newUrl;
                        </script>
                        """, unsafe_allow_html=True)
                        st.stop()
                    
                    st.success("Login successful! Welcome back!")
                    time.sleep(1)  # Short delay for better UX
                    st.rerun()
                else:
                    st.error("Invalid username or password. Please try again.")
    
    with tab2:
        st.markdown("### Create New Account")
        with st.form("signup_form"):
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                new_username = st.text_input("Choose a username", key="signup_username", placeholder="Enter a unique username")
                new_password = st.text_input("Choose a password", type="password", key="signup_password", placeholder="Create a strong password")
                confirm_password = st.text_input("Confirm password", type="password", key="confirm_password", placeholder="Re-enter your password")
                signup_submitted = st.form_submit_button("Create Account", use_container_width=True)
            
            if signup_submitted:
                if not new_username or not new_password:
                    st.error("Please fill in all fields")
                elif new_password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    if create_user(new_username, new_password):
                        save_access_log(new_username, "Signup")
                        st.success("Account created successfully! Please log in.")
                    else:
                        st.error("Username already exists. Please choose a different username.")

# ---------------------------------------------------------
# 📌 De-identification functions
# ---------------------------------------------------------
def anonymize_pii(pii_type, value):
    """Full anonymization for sensitive data"""
    # Map the pii_type to the pattern keys
    type_mapping = {
        "Credit Card": "credit_card",
        "Email": "email", 
        "Aadhaar": "aadhaar",
        "PAN": "pan",
        "Phone": "phone"
    }
    
    mapped_type = type_mapping.get(pii_type, pii_type.lower())
    
    if mapped_type == "credit_card":
        return mask_credit_card(value)
    elif mapped_type == "email":
        return mask_email(value)
    elif mapped_type == "aadhaar":
        return mask_aadhaar(value)
    elif mapped_type == "pan":
        return mask_pan(value)
    elif mapped_type == "phone":
        return mask_phone(value)
    else:
        return "[REDACTED]"

def pseudo_anonymize_pii(pii_type, value):
    """Pseudo-anonymization (fake but realistic values)"""
    # Map the pii_type to the pattern keys
    type_mapping = {
        "Credit Card": "credit_card",
        "Email": "email", 
        "Aadhaar": "aadhaar",
        "PAN": "pan",
        "Phone": "phone"
    }
    
    mapped_type = type_mapping.get(pii_type, pii_type.lower())
    
    # Use the efficient pseudo_anonymize function
    return pseudo_anonymize(value, mapped_type)

def _normalize_match_value(raw_value):
    """Normalize regex match values to a string.
    Handles cases where a tuple (full match, groups) may be passed inadvertently.
    """
    if raw_value is None:
        return ""
    if isinstance(raw_value, tuple):
        for part in raw_value:
            if isinstance(part, str) and part:
                return part
        return "".join(str(p) for p in raw_value if p)
    return str(raw_value)

def validate_pan(pan: str, surname: str = None) -> bool:
    """
    Comprehensive PAN validation based on official Income Tax Department rules:
    1. Basic format validation (10 characters: 5 letters + 4 digits + 1 letter)
    2. Entity type validation (4th character)
    3. Check digit validation (10th character)
    4. Business logic validation (position-specific rules)
    """
    if not pan or not isinstance(pan, str):
        return False
    
    # Remove spaces and convert to uppercase
    pan = pan.strip().upper()
    
    # Check length
    if len(pan) != 10:
        return False
    
    # Check basic pattern: 5 letters + 4 digits + 1 letter
    if not re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$", pan):
        return False
    
    # Check entity type (4th character) - Official PAN rules
    valid_entity_types = "ABCFGHLJPT"
    if pan[3] not in valid_entity_types:
        return False
    
    if pan[3] == 'P' and surname:
        if pan[4] != surname.strip().upper()[0]:
            return False
    # Additional business logic checks based on entity type
    #if pan[3] == 'P':  # Individual
        # For individual PANs, 5th character should be first letter of surname
        # This is usually a letter, but we can't validate the actual surname
        #if not pan[4].isalpha():
            #return False
    elif pan[3] == 'C':  # Company
        # For company PANs, 5th character should be first letter of company name
        if not pan[4].isalpha():
            return False
    elif pan[3] == 'F':  # Firm
        # For firm PANs, 5th character should be first letter of firm name
        if not pan[4].isalpha():
            return False
    elif pan[3] == 'H':  # HUF
        # For HUF PANs, 5th character should be first letter of HUF name
        if not pan[4].isalpha():
            return False
    elif pan[3] == 'A':  # AOP
        # For AOP PANs, 5th character should be first letter of AOP name
        if not pan[4].isalpha():
            return False
    elif pan[3] == 'T':  # Trust
        # For Trust PANs, 5th character should be first letter of trust name
        if not pan[4].isalpha():
            return False
    elif pan[3] == 'B':  # BOI
        # For BOI PANs, 5th character should be first letter of BOI name
        if not pan[4].isalpha():
            return False
    elif pan[3] == 'L':  # Local Authority
        # For Local Authority PANs, 5th character should be first letter of authority name
        if not pan[4].isalpha():
            return False
    elif pan[3] == 'J':  # Artificial Juridical Person
        # For AJP PANs, 5th character should be first letter of entity name
        if not pan[4].isalpha():
            return False
    elif pan[3] == 'G':  # Government
        # For Government PANs, 5th character should be first letter of government entity name
        if not pan[4].isalpha():
            return False
    
    # Validate check digit (10th character) using PAN check digit algorithm
    if not validate_pan_check_digit(pan):
        return False
    
    return True

def validate_pan_check_digit(pan: str) -> bool:
    """
    Validate PAN check digit using the official algorithm.
    The check digit is calculated based on the first 9 characters.
    """
    if len(pan) != 10:
        return False
    
    # Extract first 9 characters
    first_nine = pan[:9]
    
    # PAN check digit calculation algorithm
    # This is based on the official Income Tax Department algorithm
    weights = [1, 3, 7, 1, 3, 7, 1, 3, 7]
    sum_total = 0
    
    for i, char in enumerate(first_nine):
        if char.isalpha():
            # Convert letter to number (A=10, B=11, ..., Z=35)
            char_value = ord(char.upper()) - ord('A') + 10
        else:
            # It's a digit
            char_value = int(char)
        
        # Multiply by weight
        weighted_value = char_value * weights[i]
        
        # If result is two digits, add them together
        if weighted_value > 9:
            weighted_value = (weighted_value // 10) + (weighted_value % 10)
        
        sum_total += weighted_value
    
    # Calculate check digit
    check_digit_value = (10 - (sum_total % 10)) % 10
    
    # Convert check digit value to letter
    # 0=A, 1=B, 2=C, ..., 9=J
    expected_check_digit = chr(ord('A') + check_digit_value)
    
    # Compare with actual check digit
    return pan[9] == expected_check_digit

def get_pan_entity_type(pan: str) -> str:
    """Get entity type from PAN 4th character"""
    if not pan or len(pan) < 4:
        return "Unknown"
    
    entity_types = {
        'P': 'Individual',
        'C': 'Company',
        'H': 'HUF (Hindu Undivided Family)',
        'F': 'Firm',
        'A': 'Association of Persons (AOP)',
        'T': 'Trust',
        'B': 'Body of Individuals (BOI)',
        'L': 'Local Authority',
        'J': 'Artificial Juridical Person',
        'G': 'Government'
    }
    
    return entity_types.get(pan[3], "Unknown")

def get_pan_holder_name_initial(pan: str) -> str:
    """Get the name initial from PAN 5th character"""
    if not pan or len(pan) < 5:
        return "Unknown"
    
    return pan[4]

def get_pan_serial_number(pan: str) -> str:
    """Get the serial number from PAN (6th to 9th characters)"""
    if not pan or len(pan) < 9:
        return "Unknown"
    
    return pan[5:9]

def validate_email(email: str) -> bool:
    """
    Comprehensive email validation using multiple checks:
    1. Basic format validation
    2. Length validation
    3. Character validation
    4. Domain validation
    """
    if not email or not isinstance(email, str):
        return False
    
    # Remove whitespace
    email = email.strip()
    
    # Check length constraints
    if len(email) < 5 or len(email) > 254:  # RFC 5321 limits
        return False
    
    # Check for exactly one @ symbol
    if email.count('@') != 1:
        return False
    
    local_part, domain_part = email.split('@')
    
    # Local part validation
    if len(local_part) < 1 or len(local_part) > 64:  # RFC 5321 limits
        return False
    
    # Domain part validation
    if len(domain_part) < 1 or len(domain_part) > 253:
        return False
    
    # Check for consecutive dots
    if '..' in email:
        return False
    
    # Check for valid characters in local part
    valid_local_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.!#$%&'*+/=?^_`{|}~-")
    if not all(c in valid_local_chars for c in local_part):
        return False
    
    # Check for valid characters in domain part
    valid_domain_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
    if not all(c in valid_domain_chars for c in domain_part):
        return False
    
    # Domain must have at least one dot
    if '.' not in domain_part:
        return False
    
    # Domain cannot start or end with dot or hyphen
    if domain_part.startswith('.') or domain_part.endswith('.') or domain_part.startswith('-') or domain_part.endswith('-'):
        return False
    
    # TLD must be at least 2 characters
    tld = domain_part.split('.')[-1]
    if len(tld) < 2:
        return False
    
    return True

def is_valid_pii(pii_type: str, value: str) -> bool:
    """Validate detected PII candidates using stricter semantics.
    - Aadhaar: exactly 12 digits and must start with 2-9
    - PAN: pattern already strict
    - Credit Card: 13-16 digits after stripping separators + Luhn check
    - Email: basic email format
    - Phone: 10 digits starting with 6-9
    """
    # Ensure value is a string (regex operations expect str/bytes)
    value = _normalize_match_value(value)
    digits_only = re.sub(r"\D", "", value or "")
    
    # Map the pii_type to the pattern keys
    type_mapping = {
        "Credit Card": "credit_card",
        "Email": "email", 
        "Aadhaar": "aadhaar",
        "PAN": "pan",
        "Phone": "phone"
    }
    
    mapped_type = type_mapping.get(pii_type, pii_type.lower())
    
    if mapped_type == "aadhaar":
        # Aadhaar must be 12 digits, start with 2-9, and pass Verhoeff checksum
        return (
            len(digits_only) == 12
            and digits_only[0] in "23456789"
            and verhoeff_check(digits_only)
        )
    if mapped_type == "pan":
        return validate_pan(value)
    if mapped_type == "credit_card":
        return 13 <= len(digits_only) <= 19 and luhn_check(value)
    if mapped_type == "email":
        return validate_email(value)
    if mapped_type == "phone":
        return bool(re.fullmatch(r"[6-9][0-9]{9}", digits_only))
    return False

def any_true_pii(text: str) -> bool:
    """Ground truth check: does the text contain any VALID PII?
    Uses validators (e.g., Verhoeff, Luhn) rather than regex alone.
    """
    if not text:
        return False
    for pii_type, match in detect_pii(text):
        if is_valid_pii(pii_type, match):
            return True
    return False


# ===================== MASKING =====================
def luhn_check(card_number: str) -> bool:
    """
    Validate credit card number using Luhn algorithm.
    """
    # Remove spaces and dashes
    number = re.sub(r'[^0-9]', '', card_number)
    
    if not number.isdigit() or len(number) < 13:
        return False
    
    # Luhn algorithm
    digits = [int(d) for d in number]
    for i in range(len(digits) - 2, -1, -2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9
    
    return sum(digits) % 10 == 0

def verhoeff_check(number: str) -> bool:
    """
    Validate a numeric string using the Verhoeff algorithm (used by Aadhaar).
    Accepts only digits; caller should pre-strip separators.
    """
    if not number or not number.isdigit():
        return False

    d = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ]
    p = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ]

    checksum = 0
    # Process digits right-to-left
    for i, ch in enumerate(reversed(number)):
        checksum = d[checksum][p[(i % 8)][int(ch)]]
    return checksum == 0

def mask_aadhaar(aadhaar): 
    return aadhaar[:4] + "-XXXX-" + aadhaar[-4:] if len(re.sub(r"\D", "", aadhaar)) == 12 else aadhaar

def mask_pan(pan): 
    return pan[:5] + "****" + pan[-1:] if len(pan) == 10 else pan

def mask_credit_card(card_number: str) -> str:
    """Masks a credit card number, revealing only the last four digits."""
    digits_only = re.sub(r'[^0-9]', '', card_number)  # remove spaces/dashes
    if len(digits_only) < 13:  # Not a valid card length
        return card_number
    return f"XXXX-XXXX-XXXX-{digits_only[-4:]}"

def mask_email(email):
    try: 
        u, d = email.split("@")
        return "x"*len(u) + "@" + d
    except: 
        return email

def mask_phone(phone):
    digits = re.sub(r'\D', '', phone)
    if len(digits) == 10:
        return "XXXXXX" + digits[-4:]
    return "XXXXXXXXXX"

# ===================== PSEUDO-ANONYMIZATION =====================
pseudo_counters = {pii_type: 1 for pii_type in patterns}
pseudo_maps = {pii_type: {} for pii_type in patterns}

def pseudo_anonymize(value, pii_type):
    if value not in pseudo_maps[pii_type]:
        pseudo_maps[pii_type][value] = f"{pii_type}_{pseudo_counters[pii_type]}"
        pseudo_counters[pii_type] += 1
    return pseudo_maps[pii_type][value]

# ===================== ACCURACY =====================
def compute_accuracy(metrics):
    """Compute comprehensive accuracy metrics for PII detection"""
    accuracy_summary = {}
    
    for key, m in metrics.items():
        total = m["TP"] + m["TN"] + m["FP"] + m["FN"]
        
        if total == 0:
            accuracy_summary[key] = {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "specificity": 0.0,
                "total_samples": 0
            }
            continue
        
        # Basic accuracy
        accuracy = (m["TP"] + m["TN"]) / total * 100
        
        # Precision: TP / (TP + FP)
        precision = (m["TP"] / (m["TP"] + m["FP"]) * 100) if (m["TP"] + m["FP"]) > 0 else 0
        
        # Recall (Sensitivity): TP / (TP + FN)
        recall = (m["TP"] / (m["TP"] + m["FN"]) * 100) if (m["TP"] + m["FN"]) > 0 else 0
        
        # F1 Score: 2 * (precision * recall) / (precision + recall)
        f1_score = (2 * (precision * recall) / (precision + recall)) if (precision + recall) > 0 else 0
        
        # Specificity: TN / (TN + FP)
        specificity = (m["TN"] / (m["TN"] + m["FP"]) * 100) if (m["TN"] + m["FP"]) > 0 else 0
        
        accuracy_summary[key] = {
            "accuracy": round(accuracy, 2),
            "precision": round(precision, 2),
            "recall": round(recall, 2),
            "f1_score": round(f1_score, 2),
            "specificity": round(specificity, 2),
            "total_samples": total,
            "tp": m["TP"],
            "tn": m["TN"],
            "fp": m["FP"],
            "fn": m["FN"]
        }
    
    return accuracy_summary

def compute_overall_accuracy(metrics):
    """Compute overall system accuracy across all PII types"""
    total_tp = sum(m["TP"] for m in metrics.values())
    total_tn = sum(m["TN"] for m in metrics.values())
    total_fp = sum(m["FP"] for m in metrics.values())
    total_fn = sum(m["FN"] for m in metrics.values())
    
    total_samples = total_tp + total_tn + total_fp + total_fn
    
    if total_samples == 0:
        return {
            "overall_accuracy": 0.0,
            "overall_precision": 0.0,
            "overall_recall": 0.0,
            "overall_f1_score": 0.0,
            "overall_specificity": 0.0,
            "total_samples": 0
        }
    
    # Overall metrics
    overall_accuracy = (total_tp + total_tn) / total_samples * 100
    overall_precision = (total_tp / (total_tp + total_fp) * 100) if (total_tp + total_fp) > 0 else 0
    overall_recall = (total_tp / (total_tp + total_fn) * 100) if (total_tp + total_fn) > 0 else 0
    overall_f1_score = (2 * (overall_precision * overall_recall) / (overall_precision + overall_recall)) if (overall_precision + overall_recall) > 0 else 0
    overall_specificity = (total_tn / (total_tn + total_fp) * 100) if (total_tn + total_fp) > 0 else 0
    
    return {
        "overall_accuracy": round(overall_accuracy, 2),
        "overall_precision": round(overall_precision, 2),
        "overall_recall": round(overall_recall, 2),
        "overall_f1_score": round(overall_f1_score, 2),
        "overall_specificity": round(overall_specificity, 2),
        "total_samples": total_samples,
        "total_tp": total_tp,
        "total_tn": total_tn,
        "total_fp": total_fp,
        "total_fn": total_fn
    }

def get_accuracy_grade(accuracy_score):
    """Convert accuracy score to letter grade"""
    if accuracy_score >= 95:
        return "A+ (Excellent)"
    elif accuracy_score >= 90:
        return "A (Very Good)"
    elif accuracy_score >= 85:
        return "B+ (Good)"
    elif accuracy_score >= 80:
        return "B (Satisfactory)"
    elif accuracy_score >= 75:
        return "C+ (Average)"
    elif accuracy_score >= 70:
        return "C (Below Average)"
    elif accuracy_score >= 60:
        return "D (Poor)"
    else:
        return "F (Fail)"

def analyze_accuracy_trends(accuracy_data):
    """Analyze accuracy trends and provide insights"""
    insights = []
    
    # Find best performing PII type
    best_pii = max(accuracy_data.items(), key=lambda x: x[1]["accuracy"])
    insights.append(f"Best performing PII type: {best_pii[0]} ({best_pii[1]['accuracy']}% accuracy)")
    
    # Find worst performing PII type
    worst_pii = min(accuracy_data.items(), key=lambda x: x[1]["accuracy"])
    insights.append(f"Needs improvement: {worst_pii[0]} ({worst_pii[1]['accuracy']}% accuracy)")
    
    # Check for high false positive rates
    high_fp = [k for k, v in accuracy_data.items() if v["fp"] > v["tp"]]
    if high_fp:
        insights.append(f"High false positive rate: {', '.join(high_fp)}")
    
    # Check for high false negative rates
    high_fn = [k for k, v in accuracy_data.items() if v["fn"] > v["tp"]]
    if high_fn:
        insights.append(f"High false negative rate: {', '.join(high_fn)}")
    
    return insights

# ===================== PROCESS DATAFRAME =====================
def process_dataframe_with_report(df, pii_to_mask, report, metrics):
    """
    Processes a chunk of the dataframe and updates global report and metrics.
    """
    df_anonymized, df_pseudonymized = df.copy(), df.copy()
    identified_data, deidentified_data = pd.DataFrame(index=df.index, columns=df.columns), pd.DataFrame(index=df.index, columns=df.columns)

    for col in df.columns:
        for i, cell in enumerate(df[col].astype(str).str.strip()):
            # Fixed the error by ensuring the pattern object is used correctly.
            detected_flags = {key: bool(patterns[key].search(cell)) for key in patterns.keys()}
            
            actual_flags = {k:v if k in pii_to_mask else False for k,v in detected_flags.items()}

            for key in actual_flags:
                if actual_flags[key]: report[f"{key}_found"] += 1
                if actual_flags[key] and detected_flags[key]: metrics[key]["TP"] += 1
                elif not actual_flags[key] and detected_flags[key]: metrics[key]["FP"] += 1
                elif not actual_flags[key] and not detected_flags[key]: metrics[key]["TN"] += 1
                elif actual_flags[key] and not detected_flags[key]: metrics[key]["FN"] += 1

            # Anonymization
            anon_cell = cell
            if actual_flags.get("aadhaar"): anon_cell = mask_aadhaar(cell)
            elif actual_flags.get("pan"): anon_cell = mask_pan(cell)
            elif actual_flags.get("credit_card"):
                anon_cell = mask_credit_card(cell)
            elif actual_flags.get("email"): anon_cell = mask_email(cell)
            elif actual_flags.get("phone"): anon_cell = mask_phone(cell)
            
            df_anonymized.at[i, col] = anon_cell

            # Pseudonymization
            pseudo_cell = cell
            if any(actual_flags.values()):
                for key in actual_flags:
                    if actual_flags[key]:
                        pseudo_cell = pseudo_anonymize(cell, key)
                        break
            df_pseudonymized.at[i, col] = pseudo_cell
            
            identified_data.at[i, col] = cell if any(actual_flags.values()) else ""
            deidentified_data.at[i, col] = anon_cell if any(actual_flags.values()) else ""
            
    return df_anonymized, df_pseudonymized, identified_data, deidentified_data, report, metrics

# ---------------------------------------------------------
# 📌 PDF Report Generator
# ---------------------------------------------------------
def generate_accuracy_report_pdf(metrics, pii_detection_summary, username):
    """Generate a comprehensive accuracy report PDF"""
    
    # Calculate comprehensive metrics
    total_samples = metrics['TP'] + metrics['TN'] + metrics['FP'] + metrics['FN']
    accuracy = (metrics['TP'] + metrics['TN']) / total_samples if total_samples > 0 else 0
    precision = metrics['TP'] / (metrics['TP'] + metrics['FP']) if (metrics['TP'] + metrics['FP']) > 0 else 0
    recall = metrics['TP'] / (metrics['TP'] + metrics['FN']) if (metrics['TP'] + metrics['FN']) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    specificity = metrics['TN'] / (metrics['TN'] + metrics['FP']) if (metrics['TN'] + metrics['FP']) > 0 else 0
    error_rate = (metrics['FP'] + metrics['FN']) / total_samples if total_samples > 0 else 0
    
    # Create PDF filename
    accuracy_report_pdf = f"Accuracy_Report_{username}_{int(time.time())}.pdf"
    
    # Create PDF document
    doc = SimpleDocTemplate(accuracy_report_pdf, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []
    
    # Title
    elements.append(Paragraph("PII Detection Accuracy Report", styles["Title"]))
    elements.append(Spacer(1, 12))
    
    # Report metadata
    elements.append(Paragraph(f"Generated for: {username}", styles["Normal"]))
    elements.append(Paragraph(f"Generated on: {get_ist_time()}", styles["Normal"]))
    elements.append(Paragraph(f"Report Type: Accuracy Analysis", styles["Normal"]))
    elements.append(Spacer(1, 20))
    
    # Executive Summary
    elements.append(Paragraph("Executive Summary", styles["Heading2"]))
    elements.append(Paragraph(f"This report provides a comprehensive analysis of PII detection accuracy for the processed dataset. The system analyzed {total_samples:,} data points and achieved an overall accuracy of {accuracy:.2%}.", styles["Normal"]))
    elements.append(Spacer(1, 12))
    
    # Key Metrics Section
    elements.append(Paragraph("Key Performance Metrics", styles["Heading2"]))
    
    # Create metrics table
    metrics_data = [
        ['Metric', 'Value', 'Description'],
        ['Overall Accuracy', f"{accuracy:.2%}", 'Percentage of correct predictions'],
        ['Precision', f"{precision:.2%}", 'True positive rate'],
        ['Recall (Sensitivity)', f"{recall:.2%}", 'Detection rate for actual PII'],
        ['Specificity', f"{specificity:.2%}", 'True negative rate'],
        ['F1-Score', f"{f1_score:.2%}", 'Balanced measure of precision and recall'],
        ['Error Rate', f"{error_rate:.2%}", 'Percentage of incorrect predictions'],
        ['Total Samples', f"{total_samples:,}", 'Total data points analyzed']
    ]
    
    metrics_table = Table(metrics_data, colWidths=[2.5*inch, 1.5*inch, 3*inch])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.1725, 0.2392, 0.3137)),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), "LEFT"),
        ('FONTNAME', (0, 0), (-1, 0), "Helvetica-Bold"),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.Color(0.9255, 0.9412, 0.9451)),
        ('FONTNAME', (0, 1), (-1, -1), "Helvetica"),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 1, colors.Color(0.7412, 0.7647, 0.7804)),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    
    elements.append(metrics_table)
    elements.append(Spacer(1, 20))
    
    # Confusion Matrix Section
    elements.append(Paragraph("Confusion Matrix Analysis", styles["Heading2"]))
    
    confusion_data = [
        ['', 'Predicted PII', 'Predicted Non-PII'],
        ['Actual PII', f"{metrics['TP']}", f"{metrics['FN']}"],
        ['Actual Non-PII', f"{metrics['FP']}", f"{metrics['TN']}"]
    ]
    
    confusion_table = Table(confusion_data, colWidths=[2*inch, 2*inch, 2*inch])
    confusion_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.1725, 0.2392, 0.3137)),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), "CENTER"),
        ('FONTNAME', (0, 0), (-1, 0), "Helvetica-Bold"),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.Color(0.9255, 0.9412, 0.9451)),
        ('FONTNAME', (0, 1), (-1, -1), "Helvetica"),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 1, colors.Color(0.7412, 0.7647, 0.7804)),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    
    elements.append(confusion_table)
    elements.append(Spacer(1, 12))
    
    # Confusion Matrix Explanation
    elements.append(Paragraph("Confusion Matrix Legend:", styles["Heading3"]))
    elements.append(Paragraph(f"• True Positives (TP): {metrics['TP']} - Correctly identified PII instances", styles["Normal"]))
    elements.append(Paragraph(f"• True Negatives (TN): {metrics['TN']} - Correctly identified non-PII instances", styles["Normal"]))
    elements.append(Paragraph(f"• False Positives (FP): {metrics['FP']} - Incorrectly flagged non-PII as PII", styles["Normal"]))
    elements.append(Paragraph(f"• False Negatives (FN): {metrics['FN']} - Missed actual PII instances", styles["Normal"]))
    elements.append(Spacer(1, 20))
    
    # PII Detection Summary
    if pii_detection_summary:
        elements.append(Paragraph("PII Detection Summary", styles["Heading2"]))
        
        total_detections = sum(pii_detection_summary.values())
        elements.append(Paragraph(f"Total PII instances detected: {total_detections}", styles["Normal"]))
        elements.append(Paragraph(f"Columns containing PII: {len(pii_detection_summary)}", styles["Normal"]))
        elements.append(Spacer(1, 12))
        
        # PII Detection by Column Table
        elements.append(Paragraph("PII Detections by Column", styles["Heading3"]))
        
        pii_data = [['Column', 'PII Count']]
        for column, count in sorted(pii_detection_summary.items(), key=lambda x: x[1], reverse=True):
            pii_data.append([column, str(count)])
        
        pii_table = Table(pii_data, colWidths=[4*inch, 2*inch])
        pii_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.1725, 0.2392, 0.3137)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), "LEFT"),
            ('FONTNAME', (0, 0), (-1, 0), "Helvetica-Bold"),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.Color(0.9255, 0.9412, 0.9451)),
            ('FONTNAME', (0, 1), (-1, -1), "Helvetica"),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.Color(0.7412, 0.7647, 0.7804)),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(pii_table)
        elements.append(Spacer(1, 20))
    
    # Performance Analysis
    elements.append(Paragraph("Performance Analysis", styles["Heading2"]))
    
    if accuracy >= 0.95:
        performance_text = "Excellent Performance: The PII detection system is performing exceptionally well with high accuracy across all metrics."
    elif accuracy >= 0.90:
        performance_text = "Very Good Performance: The system is performing well with high accuracy and reliable detection."
    elif accuracy >= 0.85:
        performance_text = "Good Performance: The system is performing adequately with room for minor improvements."
    elif accuracy >= 0.80:
        performance_text = "Satisfactory Performance: The system meets basic requirements but could benefit from optimization."
    else:
        performance_text = "Needs Improvement: The system requires optimization to improve detection accuracy."
    
    elements.append(Paragraph(performance_text, styles["Normal"]))
    elements.append(Spacer(1, 12))
    
    # Recommendations
    elements.append(Paragraph("Recommendations", styles["Heading2"]))
    
    recommendations = []
    
    if precision < 0.80:
        recommendations.append("• Consider refining detection patterns to reduce false positives")
    
    if recall < 0.80:
        recommendations.append("• Improve detection patterns to catch more PII instances")
    
    if f1_score < 0.80:
        recommendations.append("• Balance precision and recall for optimal performance")
    
    if total_samples < 100:
        recommendations.append("• Test with larger datasets for more statistically significant results")
    
    if not recommendations:
        recommendations.append("• Continue monitoring performance with regular testing")
        recommendations.append("• Consider expanding to additional PII types if needed")
    
    for rec in recommendations:
        elements.append(Paragraph(rec, styles["Normal"]))
    
    elements.append(Spacer(1, 20))
    
    # Footer
    elements.append(Paragraph("Report Generated by PII De-Identification Tool", styles["Normal"]))
    elements.append(Paragraph(f"Generated on: {get_ist_time()}", styles["Normal"]))
    
    # Build PDF
    doc.build(elements)
    
    return accuracy_report_pdf

def generate_report(results_df, report_file_pdf, deidentified_csv, metrics):
    # Save De-identified CSV
    results_df.to_csv(deidentified_csv, index=False, encoding="utf-8")

    doc = SimpleDocTemplate(report_file_pdf, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    # Title and description
    elements.append(Paragraph("PII Detection & De-Identification Report", styles["Title"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("This report summarizes detected PII and applied de-identification techniques.", styles["Normal"]))
    elements.append(Spacer(1, 12))

    # Create table data with proper structure
    table_data = [results_df.columns.tolist()]
    
    # Add all rows from the dataframe
    for _, row in results_df.iterrows():
        table_data.append(row.tolist())

    # Create table with appropriate column widths and spacing
    col_count = len(results_df.columns)
    col_widths = [(doc.width - 40) / col_count] * col_count  # Add margin for spacing
    
    table = Table(table_data, colWidths=col_widths, repeatRows=1)
    
    # Apply table styling with better spacing
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.1725, 0.2392, 0.3137)),  # #2c3e50 in RGB
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
        ("BACKGROUND", (0, 1), (-1, -1), colors.Color(0.9255, 0.9412, 0.9451)),  # #ecf0f1 in RGB
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 1, colors.Color(0.7412, 0.7647, 0.7804)),  # #bdc3c7 in RGB
        ("LEFTPADDING", (0, 0), (-1, -1), 6),  # Add padding for better spacing
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),  # Add padding for better spacing
    ]))
    
    elements.append(table)
    
    # Add summary statistics
    elements.append(Spacer(1, 20))
    
    # Count PII fields
    pii_count = 0
    for col in results_df.columns:
        for value in results_df[col]:
            if isinstance(value, str) and ('XXXX' in value or '***' in value):
                pii_count += 1
    
    elements.append(Paragraph(f"Total PII fields de-identified: {pii_count}", styles["Normal"]))
    
    # Add comprehensive accuracy metrics to PDF report
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Comprehensive Accuracy Analysis", styles["Heading2"]))
    
    # Calculate comprehensive metrics
    total_samples = metrics['TP'] + metrics['TN'] + metrics['FP'] + metrics['FN']
    accuracy = (metrics['TP'] + metrics['TN']) / total_samples if total_samples > 0 else 0
    precision = metrics['TP'] / (metrics['TP'] + metrics['FP']) if (metrics['TP'] + metrics['FP']) > 0 else 0
    recall = metrics['TP'] / (metrics['TP'] + metrics['FN']) if (metrics['TP'] + metrics['FN']) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    specificity = metrics['TN'] / (metrics['TN'] + metrics['FP']) if (metrics['TN'] + metrics['FP']) > 0 else 0
    error_rate = (metrics['FP'] + metrics['FN']) / total_samples if total_samples > 0 else 0
    
    # Basic metrics
    elements.append(Paragraph("Basic Detection Metrics:", styles["Heading3"]))
    elements.append(Paragraph(f"True Positives (TP): {metrics['TP']}", styles["Normal"]))
    elements.append(Paragraph(f"True Negatives (TN): {metrics['TN']}", styles["Normal"]))
    elements.append(Paragraph(f"False Positives (FP): {metrics['FP']}", styles["Normal"]))
    elements.append(Paragraph(f"False Negatives (FN): {metrics['FN']}", styles["Normal"]))
    elements.append(Paragraph(f"Total Samples: {total_samples:,}", styles["Normal"]))
    elements.append(Spacer(1, 6))
    
    # Performance metrics
    elements.append(Paragraph("Performance Metrics:", styles["Heading3"]))
    elements.append(Paragraph(f"Overall Accuracy: {accuracy:.2%}", styles["Normal"]))
    elements.append(Paragraph(f"Precision: {precision:.2%}", styles["Normal"]))
    elements.append(Paragraph(f"Recall (Sensitivity): {recall:.2%}", styles["Normal"]))
    elements.append(Paragraph(f"Specificity: {specificity:.2%}", styles["Normal"]))
    elements.append(Paragraph(f"F1-Score: {f1_score:.2%}", styles["Normal"]))
    elements.append(Paragraph(f"Error Rate: {error_rate:.2%}", styles["Normal"]))
    elements.append(Spacer(1, 6))
    
    # Performance assessment
    elements.append(Paragraph("Performance Assessment:", styles["Heading3"]))
    if accuracy >= 0.95:
        elements.append(Paragraph("Excellent Performance: System performing exceptionally well!", styles["Normal"]))
    elif accuracy >= 0.90:
        elements.append(Paragraph("Very Good Performance: System performing well with high accuracy.", styles["Normal"]))
    elif accuracy >= 0.85:
        elements.append(Paragraph("Good Performance: System performing adequately with room for improvement.", styles["Normal"]))
    elif accuracy >= 0.80:
        elements.append(Paragraph("Satisfactory Performance: Consider reviewing detection patterns.", styles["Normal"]))
    else:
        elements.append(Paragraph("Needs Improvement: System requires optimization for better PII detection.", styles["Normal"]))
    
    
    doc.build(elements)

# ---------------------------------------------------------
# 📌 Admin Panel Functions
# ---------------------------------------------------------
def show_admin_panel():
    """Display admin panel with user management and data access"""
    st.title("Admin Panel")
    
    # Logout button
    if st.button("Logout", key="admin_logout"):
        try:
            save_access_log(st.session_state.get('username', 'Unknown'), "Logout")
        except Exception:
            pass
        
        # Delete session from database
        if st.session_state.get('session_token'):
            delete_session(st.session_state.session_token)
        
        # Clear session state and redirect to clean URL
        st.session_state.logged_in = False
        st.session_state.pop('username', None)
        st.session_state.pop('session_token', None)
        
        # Redirect to clean URL without parameters
        st.markdown("""
        <script>
        // Redirect to clean URL
        const currentUrl = window.location.href.split('?')[0];
        window.location.href = currentUrl;
        </script>
        """, unsafe_allow_html=True)
        st.stop()
    
    admin_tab1, admin_tab2, admin_tab3, admin_tab4 = st.tabs(["User Management", "Uploaded Data", "Processed Data", "User Logs"])
    
    with admin_tab1:
        st.write("User Management")
        users = get_all_users()
        
        st.write("Registered Users:")
        for user in users:
            col1, col2, col3 = st.columns([3, 5, 2])
            with col1:
                st.write(f"ID: {user[0]}")
            with col2:
                st.write(f"Username: {user[1]}")
            with col3:
                if user[1] != "admin":  # Prevent deleting the admin account
                    if st.button("Delete", key=f"delete_{user[0]}"):
                        if delete_user(user[0]):
                            st.success(f"User {user[1]} deleted!")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("Failed to delete user")
    
    with admin_tab2:
        # Get uploaded data first
        uploaded_records = get_all_uploaded_data()
        
        # Bulk actions for uploaded data
        colA, colB = st.columns([3, 1])
        with colA:
            st.write("**Uploaded Data Records**")
        with colB:
            if st.button("🧹 Clear All Uploaded Data", key="clear_all_uploaded"):
                if uploaded_records:
                    # Delete all uploaded data records
                    conn = sqlite3.connect('users.db')
                    c = conn.cursor()
                    c.execute("DELETE FROM uploaded_data")
                    deleted_count = conn.total_changes
                    conn.commit()
                    conn.close()
                    
                    # Delete all original data files
                    files_deleted = 0
                    for record in uploaded_records:
                        if record[7] and os.path.exists(record[7]):  # original_data_path
                            try:
                                os.remove(record[7])
                                files_deleted += 1
                            except:
                                pass
                    
                    st.success(f"Cleared {deleted_count} uploaded data records and {files_deleted} files.")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.info("No uploaded data to clear.")
        
        if not uploaded_records:
            st.info("No uploaded data found.")
        else:
            for record in uploaded_records:
                with st.expander(f"{record[2]} - {record[1]} ({record[6].split()[0]})", expanded=False):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.write(f"**User:** {record[1]}")
                        st.write(f"**File:** {record[2]}")
                        st.write(f"**Size:** {record[3] / 1024:.1f} KB")
                        st.write(f"**Rows:** {record[4]}, **Columns:** {record[5]}")
                        st.write(f"**Uploaded:** {record[6]} IST")
                    
                    with col2:
                        if record[7] and os.path.exists(record[7]):  # original_data_path
                            with open(record[7], "rb") as f:
                                st.download_button("Download Original", f, file_name=record[2], key=f"dl_orig_{record[0]}")
                        else:
                            st.write("File not available")
                        
                        if st.button("🗑️ Delete", key=f"del_upload_{record[0]}", use_container_width=True):
                            if delete_uploaded_data(record[0]):
                                # Also delete the file if it exists
                                if record[7] and os.path.exists(record[7]):
                                    try:
                                        os.remove(record[7])
                                    except:
                                        pass
                                st.success("Upload record deleted!")
                                time.sleep(1)
                                st.rerun()
                            else:
                                st.error("Failed to delete record")
    
    with admin_tab3:
        # Get processed data first
        data_records = get_all_deidentified_data()
        
        # Bulk actions for processed data
        colA, colB = st.columns([3, 1])
        with colA:
            st.write("**De-identified Data Records**")
        with colB:
            if st.button("🧹 Clear All Processed Data", key="clear_all_processed"):
                if data_records:
                    # Delete all processed data records
                    conn = sqlite3.connect('users.db')
                    c = conn.cursor()
                    c.execute("DELETE FROM deidentified_data")
                    deleted_count = conn.total_changes
                    conn.commit()
                    conn.close()
                    
                    # Delete all processed data files
                    files_deleted = 0
                    for record in data_records:
                        if record[4] and os.path.exists(record[4]):  # filepath
                            try:
                                os.remove(record[4])
                                files_deleted += 1
                            except:
                                pass
                    
                    st.success(f"Cleared {deleted_count} processed data records and {files_deleted} files.")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.info("No processed data to clear.")
        
        if not data_records:
            st.info("No de-identified data records found.")
        else:
            for record in data_records:
                col1, col2, col3, col4, col5, col6 = st.columns([1, 2, 3, 3, 2, 2])
                with col1:
                    st.write(f"ID: {record[0]}")
                with col2:
                    st.write(f"User: {record[1]}")
                with col3:
                    st.write(f"File: {record[2]}")
                with col4:
                    st.write(f"Time: {record[3]} IST")
                with col5:
                        if os.path.exists(record[4]):
                            with open(record[4], "rb") as f:
                                st.download_button("Download", f, file_name=record[2], key=f"dl_{record[0]}")
                        else:
                            st.write("File missing")
                with col6:
                        if st.button("Delete", key=f"del_data_{record[0]}"):
                            if delete_deidentified_data(record[0]):
                                st.success("Record deleted!")
                                time.sleep(1)
                                st.rerun()
                            else:
                                st.error("Failed to delete record")
    
    # TAB 4 (Admin Access Logs)
    with admin_tab4:
        st.write("**Access Logs (Admin only)**")
        colA, colB = st.columns([3, 1])

        with colA:
            st.caption("Login/Signup/Logout with timestamps")

        with colB:
            if st.button("🧹 Clear All Access Logs", key="clear_access_logs"):
                count = delete_all_access_logs()
                st.success(f"Cleared {count} access logs.")

            # Debug info right after clearing
                conn = sqlite3.connect('users.db')
                c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM access_logs")
                total_logs = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM access_logs WHERE username = 'admin'")
                admin_logs = c.fetchone()[0]
                conn.close()
                st.caption(f"Debug (after clear): Total = {total_logs}, Admin = {admin_logs}")

                time.sleep(1)
                st.rerun()

    # ✅ Keep this part inside tab4
            logs = get_access_logs()
            filtered_logs = [log for log in logs if log[2] in ("Signup", "Login", "Logout")]

        if not filtered_logs:
            st.info("No access logs found.")

        # Debug info when logs are empty
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM access_logs")
            total_logs = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM access_logs WHERE username = 'admin'")
            admin_logs = c.fetchone()[0]
            conn.close()
            st.caption(f"Debug (empty logs): Total = {total_logs}, Admin = {admin_logs}")

        else:
            st.write("**Recent User Activities:**")
        for log in filtered_logs:
            st.write(f" {log[3]} —  {log[1]} —  {log[2]}")

# ---------------------------------------------------------
# 📌 Main Application
# ---------------------------------------------------------
def main_app():
    st.set_page_config(page_title="PII De-Identification Tool", layout="wide", initial_sidebar_state="expanded")
    
    # Custom CSS for enhanced UI
    st.markdown("""
    <style>
    /* Main theme colors */
    :root {
        --primary-color: #1f77b4;
        --secondary-color: #ff7f0e;
        --success-color: #2ca02c;
        --danger-color: #d62728;
        --warning-color: #ff7f0e;
        --info-color: #17a2b8;
        --light-color: #f8f9fa;
        --dark-color: #343a40;
        --gradient-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        --gradient-success: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        --gradient-danger: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
    }
    
    /* Main container styling */
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    
    /* Header styling */
    .stApp > header {
        background: var(--gradient-primary);
        color: white;
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background: linear-gradient(180deg, #f8f9fa 0%, #e9ecef 100%);
    }
    
    /* Button styling */
    .stButton > button {
        background: var(--gradient-primary);
        color: white;
        border: none;
        border-radius: 10px;
        padding: 0.5rem 1rem;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
    }
    
    /* Success button */
    .stButton > button[kind="primary"] {
        background: var(--gradient-success);
    }
    
    /* Danger button */
    .stButton > button[kind="secondary"] {
        background: var(--gradient-danger);
    }
    
    /* Metric cards styling */
    .metric-card {
        background: white;
        padding: 1.5rem;
        border-radius: 15px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        border-left: 5px solid var(--primary-color);
        margin: 0.5rem 0;
        transition: all 0.3s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 15px rgba(0, 0, 0, 0.2);
    }
    
    /* TP card */
    .metric-tp {
        border-left-color: var(--success-color);
        background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
    }
    
    /* TN card */
    .metric-tn {
        border-left-color: var(--info-color);
        background: linear-gradient(135deg, #d1ecf1 0%, #bee5eb 100%);
    }
    
    /* FP card */
    .metric-fp {
        border-left-color: var(--warning-color);
        background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
    }
    
    /* FN card */
    .metric-fn {
        border-left-color: var(--danger-color);
        background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
    }
    
    /* File uploader styling */
    .stFileUploader > div {
        border: 2px dashed var(--primary-color);
        border-radius: 15px;
        padding: 2rem;
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        transition: all 0.3s ease;
    }
    
    .stFileUploader > div:hover {
        border-color: var(--secondary-color);
        background: linear-gradient(135deg, #e9ecef 0%, #dee2e6 100%);
    }
    
    /* Dataframe styling */
    .stDataFrame {
        border-radius: 10px;
        overflow: hidden;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    /* Progress bar styling */
    .stProgress > div > div > div {
        background: var(--gradient-primary);
        border-radius: 10px;
    }
    
    /* Alert styling */
    .stAlert {
        border-radius: 10px;
        border: none;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    
    /* Success alert */
    .stAlert[data-testid="stAlert"]:has(.stMarkdown:contains("✅")) {
        background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
        border-left: 5px solid var(--success-color);
    }
    
    /* Error alert */
    .stAlert[data-testid="stAlert"]:has(.stMarkdown:contains("❌")) {
        background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
        border-left: 5px solid var(--danger-color);
    }
    
    /* Info alert */
    .stAlert[data-testid="stAlert"]:has(.stMarkdown:contains("ℹ️")) {
        background: linear-gradient(135deg, #d1ecf1 0%, #bee5eb 100%);
        border-left: 5px solid var(--info-color);
    }
    
    /* Warning alert */
    .stAlert[data-testid="stAlert"]:has(.stMarkdown:contains("⚠️")) {
        background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
        border-left: 5px solid var(--warning-color);
    }
    
    /* Title styling */
    h1 {
        background: var(--gradient-primary);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        font-weight: 700;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    /* Subtitle styling */
    h2 {
        color: var(--primary-color);
        border-bottom: 3px solid var(--primary-color);
        padding-bottom: 0.5rem;
        margin-top: 2rem;
    }
    
    /* Animation for loading */
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
    }
    
    .loading {
        animation: pulse 2s infinite;
    }
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: #f1f1f1;
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: var(--primary-color);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: var(--secondary-color);
    }
    </style>
    """, unsafe_allow_html=True)
    
    # If admin, show full screen admin panel
    if st.session_state.username == "admin":
        show_admin_panel()
        return
    
    # Enhanced main title
    st.markdown("""
    <div style="text-align: center; padding: 1rem 0; margin-bottom: 2rem;">
        <h1 style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                   -webkit-background-clip: text; -webkit-text-fill-color: transparent; 
                   background-clip: text; font-size: 2.5rem; margin-bottom: 0.5rem;">
            Sensitive PII Detection & De-Identification Tool
        </h1>
        
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced sidebar with user info
    with st.sidebar:
        st.markdown("### User Dashboard")
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); 
                    padding: 1rem; border-radius: 10px; margin-bottom: 1rem;">
            <p style="margin: 0; font-weight: 600; color: #495057;">
                Welcome, <strong>{st.session_state.username}</strong>
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("Logout", use_container_width=True):
            try:
                save_access_log(st.session_state.get('username', 'Unknown'), "Logout")
            except Exception:
                pass
            
            # Delete session from database
            if st.session_state.get('session_token'):
                delete_session(st.session_state.session_token)
            
            # Clear session state and redirect to clean URL
            st.session_state.logged_in = False
            st.session_state.pop('username', None)
            st.session_state.pop('session_token', None)
            
            # Redirect to clean URL without parameters
            st.markdown("""
            <script>
            // Redirect to clean URL
            const currentUrl = window.location.href.split('?')[0];
            window.location.href = currentUrl;
            </script>
            """, unsafe_allow_html=True)
            st.stop()

        # Add some helpful info
        st.markdown("---")
        st.markdown("### Quick Stats")
        st.info("**Tip**: Upload CSV files to detect and anonymize PII data automatically")

    # ---------------- Enhanced File Upload ----------------
    st.markdown("### Upload Your Data")
    uploaded_file = st.file_uploader(
        "Choose a CSV file to analyze", 
        type=["csv"],
        help="Upload a CSV file containing data you want to scan for PII"
    )

    if uploaded_file:
        # Ensure we only persist an uploaded file once across Streamlit reruns
        if 'processed_upload_hashes' not in st.session_state:
            st.session_state.processed_upload_hashes = set()

        # Read bytes and hash to identify this exact content
        file_bytes = uploaded_file.getvalue()
        file_hash = hashlib.sha256(file_bytes).hexdigest()

        # Build DataFrame from in-memory bytes (safe for repeated reruns)
        df = pd.read_csv(io.BytesIO(file_bytes))

        if file_hash not in st.session_state.processed_upload_hashes:
            # Save original data for admin access
            original_data_path = f"Original_Data_{st.session_state.username}_{int(time.time())}.csv"
            df.to_csv(original_data_path, index=False)

            # Save upload info to database
            save_uploaded_data(
                username=st.session_state.username,
                original_filename=uploaded_file.name,
                file_size=uploaded_file.size,
                row_count=len(df),
                column_count=len(df.columns),
                original_data_path=original_data_path
            )

            # Log the upload action
            save_access_log(st.session_state.username, f"Uploaded: {uploaded_file.name}")

            # Mark processed so subsequent reruns (e.g., downloads) don't duplicate
            st.session_state.processed_upload_hashes.add(file_hash)
        
        # Enhanced data preview with progress
        st.markdown("### Data Preview")
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        status_text.text("Processing uploaded data...")
        progress_bar.progress(25)
        time.sleep(0.5)
        
        status_text.text("Analyzing data structure...")
        progress_bar.progress(50)
        time.sleep(0.5)
        
        status_text.text("Data loaded successfully!")
        progress_bar.progress(100)
        time.sleep(0.5)
        
        progress_bar.empty()
        status_text.empty()
        
        # Show data info
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Rows", len(df))
        with col2:
            st.metric("Columns", len(df.columns))
        with col3:
            st.metric("File Size", f"{uploaded_file.size / 1024:.1f} KB")
        
        st.dataframe(df, use_container_width=True)

        # ---------------- Enhanced Method Selection ----------------
        st.markdown("### Choose De-identification Method")
        method = st.radio(
            "Select your preferred anonymization approach:",
            ["Anonymization", "Pseudo-Anonymization"], 
            horizontal=True,
            help="Anonymization: Replaces with masked values (XXXX). Pseudo-Anonymization: Replaces with consistent fake values."
        )
        
        # Method is already clean without emojis, no need to split

        # ---------------- Create De-identified DataFrame ----------------
        deidentified_data = df.copy()
        pii_detection_summary = {}
        
        # Initialize metrics and data storage
        metrics = {
            'TP': 0,
            'TN': 0,
            'FP': 0,
            'FN': 0
        }
        
        # Store data for each metric type
        metric_data = {
            'TP': [],  # (row_idx, col_name, original_value, detected_pii)
            'TN': [],  # (row_idx, col_name, original_value)
            'FP': [],  # (row_idx, col_name, original_value, detected_pii)
            'FN': []   # (row_idx, col_name, original_value, actual_pii)
        }
        
        # Iterate cells
        for col in df.columns:
            for idx, value in enumerate(df[col].astype(str)):
                detections = detect_pii(value)
                has_ground_truth = any_true_pii(value)
                has_detection = bool(detections)

                if has_detection:
                    # Validate detections; if any valid detected piece exists → valid_detection
                    valid_detection = False
                    for pii_type, match in detections:
                        if is_valid_pii(pii_type, match):
                            valid_detection = True
                            break
                    
                    if valid_detection and has_ground_truth:
                        metrics['TP'] += 1
                        # Store TP data: (row_idx, col_name, original_value, detected_pii)
                        valid_detections = [d for d in detections if is_valid_pii(d[0], d[1])]
                        metric_data['TP'].append((idx, col, value, valid_detections))
                    elif valid_detection and not has_ground_truth:
                        metrics['FP'] += 1
                        # Store FP data: (row_idx, col_name, original_value, detected_pii)
                        valid_detections = [d for d in detections if is_valid_pii(d[0], d[1])]
                        metric_data['FP'].append((idx, col, value, valid_detections))
                    elif not valid_detection and has_ground_truth:
                        # Something detected but none valid; still a miss overall
                        metrics['FN'] += 1
                        # Store FN data: (row_idx, col_name, original_value, actual_pii)
                        metric_data['FN'].append((idx, col, value, "Actual PII present but not detected"))
                    else:
                        # Detected but not valid and no ground truth → do not count as TN, treat as FP
                        metrics['FP'] += 1
                        # Store FP data: (row_idx, col_name, original_value, detected_pii)
                        valid_detections = [d for d in detections if is_valid_pii(d[0], d[1])]
                        metric_data['FP'].append((idx, col, value, valid_detections))
                else:
                    if has_ground_truth:
                        metrics['FN'] += 1
                        # Store FN data: (row_idx, col_name, original_value, actual_pii)
                        metric_data['FN'].append((idx, col, value, "Actual PII present but not detected"))
                    else:
                        metrics['TN'] += 1
                        # Store TN data: (row_idx, col_name, original_value)
                        metric_data['TN'].append((idx, col, value))

                # Apply de-identification only for valid detections
                if has_detection:
                    original_value = value
                    detections.sort(key=lambda x: len(x[1]), reverse=True)
                    replaced_matches = set()
                    
                    for pii_type, match in detections:
                        if any(match in rm for rm in replaced_matches):
                            continue
                        
                        if not is_valid_pii(pii_type, match):
                            # Skip invalid detection (e.g., Aadhaar starting with 0/1)
                            continue
                        
                        if method == "Anonymization":
                            deidentified_value = anonymize_pii(pii_type, match)
                        else:
                            deidentified_value = pseudo_anonymize_pii(pii_type, match)
                        
                        original_value = original_value.replace(match, deidentified_value)
                        replaced_matches.add(match)
                        
                        # Update summary by column
                        pii_detection_summary[col] = pii_detection_summary.get(col, 0) + 1
                    
                    deidentified_data.at[idx, col] = original_value
                else:
                    deidentified_data.at[idx, col] = value

        # Enhanced de-identified data preview
        st.markdown("### De-Identified Data Preview")
        st.success("PII detection and de-identification completed successfully!")
        st.dataframe(deidentified_data, use_container_width=True)

        # ---------------- Enhanced Detection Metrics ----------------
        st.markdown("### Detection Performance Metrics")
        st.markdown("**Click on any metric below to view detailed data:**")

        # Enhanced metric buttons with better styling
        col1, col2, col3, col4 = st.columns(4)
        
        # Initialize session state for metric visibility
        if 'show_tp' not in st.session_state:
            st.session_state.show_tp = False
        if 'show_tn' not in st.session_state:
            st.session_state.show_tn = False
        if 'show_fp' not in st.session_state:
            st.session_state.show_fp = False
        if 'show_fn' not in st.session_state:
            st.session_state.show_fn = False
        
        with col1:
            st.markdown(f"""
            <div class="metric-card metric-tp" style="text-align: center; padding: 0.5rem;">
                <h4 style="margin: 0; color: #2ca02c; font-size: 0.9rem;">True Positives</h4>
                <h3 style="margin: 0.3rem 0; color: #2ca02c; font-size: 1.5rem;">{metrics['TP']}</h3>
                <p style="margin: 0; font-size: 0.7rem; color: #666;">Correctly detected PII</p>
            </div>
            """, unsafe_allow_html=True)
            if st.button(f"{'Hide Details' if st.session_state.show_tp else 'View Details'}", key="tp_button", help="Click to view correctly detected PII", use_container_width=True):
                # Close all others and toggle current
                st.session_state.show_tn = False
                st.session_state.show_fp = False
                st.session_state.show_fn = False
                st.session_state.show_tp = not st.session_state.show_tp
                st.rerun()
        
        with col2:
            st.markdown(f"""
            <div class="metric-card metric-tn" style="text-align: center; padding: 0.5rem;">
                <h4 style="margin: 0; color: #17a2b8; font-size: 0.9rem;">True Negatives</h4>
                <h3 style="margin: 0.3rem 0; color: #17a2b8; font-size: 1.5rem;">{metrics['TN']}</h3>
                <p style="margin: 0; font-size: 0.7rem; color: #666;">Correctly ignored non-PII</p>
            </div>
            """, unsafe_allow_html=True)
            if st.button(f"{'Hide Details' if st.session_state.show_tn else 'View Details'}", key="tn_button", help="Click to view correctly ignored non-PII", use_container_width=True):
                # Close all others and toggle current
                st.session_state.show_tp = False
                st.session_state.show_fp = False
                st.session_state.show_fn = False
                st.session_state.show_tn = not st.session_state.show_tn
                st.rerun()
        
        with col3:
            st.markdown(f"""
            <div class="metric-card metric-fp" style="text-align: center; padding: 0.5rem;">
                <h4 style="margin: 0; color: #ff7f0e; font-size: 0.9rem;">False Positives</h4>
                <h3 style="margin: 0.3rem 0; color: #ff7f0e; font-size: 1.5rem;">{metrics['FP']}</h3>
                <p style="margin: 0; font-size: 0.7rem; color: #666;">Incorrectly flagged non-PII</p>
            </div>
            """, unsafe_allow_html=True)
            if st.button(f"{'Hide Details' if st.session_state.show_fp else 'View Details'}", key="fp_button", help="Click to view incorrectly flagged non-PII", use_container_width=True):
                # Close all others and toggle current
                st.session_state.show_tp = False
                st.session_state.show_tn = False
                st.session_state.show_fn = False
                st.session_state.show_fp = not st.session_state.show_fp
                st.rerun()
        
        with col4:
            st.markdown(f"""
            <div class="metric-card metric-fn" style="text-align: center; padding: 0.5rem;">
                <h4 style="margin: 0; color: #d62728; font-size: 0.9rem;">False Negatives</h4>
                <h3 style="margin: 0.3rem 0; color: #d62728; font-size: 1.5rem;">{metrics['FN']}</h3>
                <p style="margin: 0; font-size: 0.7rem; color: #666;">Missed PII</p>
            </div>
            """, unsafe_allow_html=True)
            if st.button(f"{'Hide Details' if st.session_state.show_fn else 'View Details'}", key="fn_button", help="Click to view missed PII", use_container_width=True):
                # Close all others and toggle current
                st.session_state.show_tp = False
                st.session_state.show_tn = False
                st.session_state.show_fp = False
                st.session_state.show_fn = not st.session_state.show_fn
                st.rerun()
        
        # Display data based on clicked metrics
        if st.session_state.show_tp and metric_data['TP']:
            st.subheader("True Positives (TP) - Correctly Detected PII")
            tp_df = pd.DataFrame(metric_data['TP'], columns=['Row', 'Column', 'Original Value', 'Detected PII'])
            st.dataframe(tp_df, use_container_width=True)
        
        if st.session_state.show_tn and metric_data['TN']:
            st.subheader("True Negatives (TN) - Correctly Ignored Non-PII")
            tn_df = pd.DataFrame(metric_data['TN'], columns=['Row', 'Column', 'Original Value'])
            st.dataframe(tn_df, use_container_width=True)
        
        if st.session_state.show_fp and metric_data['FP']:
            st.subheader("False Positives (FP) - Incorrectly Flagged Non-PII")
            fp_df = pd.DataFrame(metric_data['FP'], columns=['Row', 'Column', 'Original Value', 'Detected PII'])
            st.dataframe(fp_df, use_container_width=True)
        
        if st.session_state.show_fn and metric_data['FN']:
            st.subheader("False Negatives (FN) - Missed PII")
            fn_df = pd.DataFrame(metric_data['FN'], columns=['Row', 'Column', 'Original Value', 'Issue'])
            st.dataframe(fn_df, use_container_width=True)
        
        # Summary cards for TP/TN/FP/FN removed per request

        # Calculate comprehensive accuracy metrics
        precision = metrics['TP'] / (metrics['TP'] + metrics['FP']) if (metrics['TP'] + metrics['FP']) > 0 else 0
        recall = metrics['TP'] / (metrics['TP'] + metrics['FN']) if (metrics['TP'] + metrics['FN']) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (metrics['TP'] + metrics['TN']) / (metrics['TP'] + metrics['TN'] + metrics['FP'] + metrics['FN']) if (metrics['TP'] + metrics['TN'] + metrics['FP'] + metrics['FN']) > 0 else 0
        specificity = metrics['TN'] / (metrics['TN'] + metrics['FP']) if (metrics['TN'] + metrics['FP']) > 0 else 0
        
        # Enhanced Performance Scores Section
        st.subheader("Comprehensive Accuracy Analysis")

        # Overall accuracy with grade
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Overall Accuracy", 
                f"{accuracy:.2%}", 
                "TP + TN / Total",
                help="Percentage of correct predictions (TP + TN) / Total"
            )
        
        with col2:
            st.metric(
                "Precision", 
                f"{precision:.2%}", 
                "TP / (TP + FP)",
                help="Percentage of positive predictions that were correct"
            )
        
        with col3:
            st.metric(
                "Recall (Sensitivity)", 
                f"{recall:.2%}", 
                "TP / (TP + FN)",
                help="Percentage of actual positives that were correctly identified"
            )
        
        with col4:
            st.metric(
                "Specificity", 
                f"{specificity:.2%}", 
                "TN / (TN + FP)",
                help="Percentage of actual negatives that were correctly identified"
            )
        
        # F1-Score and additional metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "F1-Score", 
                f"{f1_score:.2%}", 
                "Harmonic mean of precision and recall",
                help="Balanced measure of precision and recall"
            )
        
        with col2:
            total_samples = metrics['TP'] + metrics['TN'] + metrics['FP'] + metrics['FN']
            st.metric(
                "Total Samples", 
                f"{total_samples:,}", 
                "Processed data points",
                help="Total number of data points analyzed"
            )
        
        with col3:
            error_rate = (metrics['FP'] + metrics['FN']) / total_samples if total_samples > 0 else 0
            st.metric(
                "Error Rate", 
                f"{error_rate:.2%}", 
                "FP + FN / Total",
                help="Percentage of incorrect predictions"
            )
        
        with col4:
            positive_rate = (metrics['TP'] + metrics['FP']) / total_samples if total_samples > 0 else 0
            st.metric(
                "Detection Rate", 
                f"{positive_rate:.2%}", 
                "TP + FP / Total",
                help="Percentage of data points flagged as PII"
            )
        
        # Visualization of metrics
        fig, ax = plt.subplots(1, 2, figsize=(12, 4))
        
        # Metrics bar chart with modern colors
        metrics_names = ['TP', 'TN', 'FP', 'FN']
        metrics_values = [metrics['TP'], metrics['TN'], metrics['FP'], metrics['FN']]
        colors_list = ['#43e97b', '#4facfe', '#f093fb', '#f5576c']  # Green, Blue, Pink, Red
        bars = ax[0].bar(metrics_names, metrics_values, color=colors_list)
        ax[0].set_title('Detection Metrics', fontsize=14, fontweight='bold', color='#2c3e50')
        ax[0].set_ylabel('Count', fontsize=12, color='#34495e')
        ax[0].grid(True, alpha=0.3, linestyle='--')
        ax[0].set_facecolor('#f8f9fa')
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax[0].text(bar.get_x() + bar.get_width()/2., height + 0.1,
                      f'{int(height)}', ha='center', va='bottom', fontweight='bold', fontsize=10)
        
        # Performance scores pie chart with guard for zero/NaN values
        scores_raw = [precision, recall, f1_score]
        scores = [s for s in scores_raw if isinstance(s, (int, float)) and not math.isnan(s) and s > 0]
        colors_pie = ['#667eea', '#764ba2', '#f093fb']
        if scores:
            labels = []
            for s, name in zip(scores_raw, ['Precision', 'Recall', 'F1-Score']):
                if isinstance(s, (int, float)) and not math.isnan(s) and s > 0:
                    labels.append(f'{name}: {s:.2%}')
            wedges, texts, autotexts = ax[1].pie(scores, labels=labels, autopct='%1.1f%%', startangle=90,
                                                colors=colors_pie[:len(scores)], explode=[0.05] * len(scores))
            ax[1].set_title('Performance Scores', fontsize=14, fontweight='bold', color='#2c3e50')
        else:
            ax[1].axis('off')
            ax[1].text(0.5, 0.5, 'No score data', ha='center', va='center', fontsize=12, color='#2c3e50')
        
        # Enhance text styling
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(10)
            autotext.set_bbox(dict(boxstyle="round,pad=0.2", facecolor='black', alpha=0.7))
        
        for text in texts:
            text.set_fontsize(10)
            text.set_fontweight('600')
            text.set_color('#2c3e50')
        
        # Set background color
        fig.patch.set_facecolor('#f8f9fa')
        
        st.pyplot(fig)

        # ---------------- Enhanced Download Section ----------------
        st.markdown("### Download Results")
        
        # Create two columns for download buttons
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Generate & Download CSV", use_container_width=True, help="Download the de-identified data as CSV"):
                with st.spinner("Generating CSV file..."):
                    deidentified_csv = f"Deidentified_Data_{st.session_state.username}_{int(time.time())}.csv"
                    deidentified_data.to_csv(deidentified_csv, index=False)
                    
                    # Save record of this de-identified data
                    save_deidentified_data(st.session_state.username, deidentified_csv, deidentified_csv)
                    
                    st.success("De-identified CSV generated successfully!")
                    with open(deidentified_csv, "rb") as f:
                        st.download_button("Download De-identified CSV", f, file_name="Deidentified_Data.csv", mime="text/csv", use_container_width=True)
        
        with col2:
            if st.button("Generate & Download Accuracy Report", use_container_width=True, help="Download comprehensive accuracy analysis as PDF"):
                with st.spinner("Generating accuracy report..."):
                    try:
                        # Generate accuracy report PDF
                        accuracy_report_pdf = generate_accuracy_report_pdf(metrics, pii_detection_summary, st.session_state.username)
                        
                        st.success("Accuracy report generated successfully!")
                        with open(accuracy_report_pdf, "rb") as f:
                            st.download_button(
                                "Download Accuracy Report", 
                                f, 
                                file_name="Accuracy_Report.pdf", 
                                mime="application/pdf", 
                                use_container_width=True
                            )
                    except Exception as e:
                        st.error(f"Error generating accuracy report: {str(e)}")
                        st.info("Please try again or contact support if the issue persists.")

        # ---------------- Enhanced PII Detection Summary ----------------
        if pii_detection_summary:
            st.markdown("### PII Detection Summary")
            
            total_detections = sum(pii_detection_summary.values())
            
            # Enhanced summary with better styling
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total PII Detections", total_detections, help="Total number of PII instances found")
            with col2:
                st.metric("Columns with PII", len(pii_detection_summary), help="Number of columns containing PII")
            with col3:
                avg_detections = total_detections / len(pii_detection_summary) if pii_detection_summary else 0
                st.metric("Avg per Column", f"{avg_detections:.1f}", help="Average PII detections per column")
            
            # PII Detection by Column
            st.markdown("### PII Detection by Column")
            
            summary_df = pd.DataFrame.from_dict(pii_detection_summary, orient='index', columns=['Count'])
            summary_df = summary_df.sort_values('Count', ascending=False)
            st.dataframe(summary_df, use_container_width=True)
            
            # Enhanced Visualization
            col1, col2 = st.columns(2)
            
            with col1:
                 fig, ax = plt.subplots(figsize=(8, 8))
                 # Modern gradient colors for bar chart
                 colors = ['#667eea', '#764ba2', '#f093fb', '#f5576c', '#4facfe', '#00f2fe', '#43e97b', '#38f9d7']
                 bars = ax.bar(summary_df.index, summary_df['Count'], color=colors[:len(summary_df)])
                 ax.set_title("PII Detections by Column", fontsize=16, fontweight='bold', color='#2c3e50')
                 ax.set_ylabel("Count", fontsize=14, color='#34495e')
                 ax.set_xlabel("Columns", fontsize=14, color='#34495e')
                 plt.xticks(rotation=45, ha='right', fontsize=12)
                 plt.yticks(fontsize=12)
                 
                 # Add value labels on bars with better styling
                 for bar in bars:
                     height = bar.get_height()
                     ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                            f'{int(height)}', ha='center', va='bottom', fontweight='bold', fontsize=11, color='#2c3e50')
                 
                 # Add grid for better readability
                 ax.grid(True, alpha=0.3, linestyle='--')
                 ax.set_facecolor('#f8f9fa')
                 
                 plt.tight_layout()
                 st.pyplot(fig, use_container_width=True)
            
            with col2:
                 fig2, ax2 = plt.subplots(figsize=(8, 8))
                 # Modern pastel gradient colors for pie chart
                 colors = ['#667eea', '#764ba2', '#f093fb', '#f5576c', '#4facfe', '#00f2fe', '#43e97b', '#38f9d7']
                 wedges, texts, autotexts = ax2.pie(summary_df['Count'], labels=summary_df.index, 
                                                   autopct='%1.1f%%', colors=colors[:len(summary_df)], startangle=90,
                                                   explode=[0.05] * len(summary_df))
                 ax2.set_title("PII Distribution by Column", fontsize=16, fontweight='bold', color='#2c3e50')
                 
                 # Enhance text styling with better contrast
                 for autotext in autotexts:
                     autotext.set_color('white')
                     autotext.set_fontweight('bold')
                     autotext.set_fontsize(11)
                     autotext.set_bbox(dict(boxstyle="round,pad=0.3", facecolor='black', alpha=0.7))
                 
                 # Enhance label styling
                 for text in texts:
                     text.set_fontsize(12)
                     text.set_fontweight('600')
                     text.set_color('#2c3e50')
                 
                 # Add a subtle background
                 fig2.patch.set_facecolor('#f8f9fa')
                 
                 plt.tight_layout()
                 st.pyplot(fig2, use_container_width=True)
        else:
            st.info("No PII detected in the uploaded data. Your data appears to be clean!")

    else:
        # Enhanced empty state
        st.markdown("""
        <div style="text-align: center; padding: 3rem 0; color: #666;">
            <h3>Ready to Analyze Your Data</h3>
            <p style="font-size: 1.1rem; margin: 1rem 0;">
                Upload a CSV file to begin PII detection and de-identification
            </p>
            <p style="color: #999;">
                Supported formats: CSV files with text data
            </p>
        </div>
        """, unsafe_allow_html=True)

# ---------------------------------------------------------
# 📌 Main Application Flow
# ---------------------------------------------------------
def main():
    # Initialize session state for authentication
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'username' not in st.session_state:
        st.session_state.username = None
    if 'session_token' not in st.session_state:
        st.session_state.session_token = None
    
    # Check for existing session token in URL parameters
    query_params = st.query_params
    if 'session_token' in query_params and 'username' in query_params:
        session_token = query_params['session_token']
        username = query_params['username']
        
        # Verify the session token
        if session_token and username and verify_session(session_token, username):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.session_token = session_token
            # Clear URL parameters to avoid showing them
            st.query_params.clear()
            st.rerun()
        else:
            # Invalid session, clear URL parameters
            st.query_params.clear()
            st.rerun()
    
    # Show login page or main app based on authentication status
    if not st.session_state.logged_in:
        show_login_page()
    else:
        main_app()

if __name__ == "__main__":
    main()