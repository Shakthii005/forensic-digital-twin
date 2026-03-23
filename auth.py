"""
auth.py — Authentication & Session Management
Handles login, register, logout, role-based access control
"""

import streamlit as st
import database as db
from config import ROLE_PERMISSIONS, APP_NAME, APP_VERSION


# ── Session helpers ───────────────────────────────────────────────────────────

def get_current_user():
    """Returns current logged-in user dict or None."""
    token = st.session_state.get("auth_token")
    if not token:
        return None
    session = db.get_session(token)
    if not session:
        st.session_state.pop("auth_token", None)
        return None
    return db.get_user_by_id(session["user_id"])


def is_logged_in() -> bool:
    return get_current_user() is not None


def can(user: dict, permission: str) -> bool:
    if not user:
        return False
    return permission in ROLE_PERMISSIONS.get(user["role"], [])


def logout():
    token = st.session_state.get("auth_token")
    if token:
        db.delete_session(token)
    st.session_state.clear()
    st.rerun()


# ── Login / Register UI ───────────────────────────────────────────────────────

def show_auth_page():
    """Full-page login / register UI. Returns when user is authenticated."""

    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono&display=swap');
    html,body,[class*="css"]{font-family:'Inter',sans-serif!important;background:#030712!important;color:#f9fafb!important;}
    .stApp{background:#030712!important;}
    [data-testid="stSidebar"]{display:none!important;}
    [data-testid="collapsedControl"]{display:none!important;}
    #MainMenu,header,footer{visibility:hidden!important;}
    .block-container{padding-top:0!important;max-width:100%!important;}
    .stTextInput>div>div{background:#111827!important;border-color:#1f2937!important;border-radius:8px!important;color:#f9fafb!important;}
    .stTextInput input{color:#f9fafb!important;}
    .stButton>button{background:linear-gradient(135deg,#6366f1,#8b5cf6)!important;color:white!important;border:none!important;border-radius:8px!important;font-weight:600!important;font-size:14px!important;padding:10px 24px!important;width:100%!important;}
    .stButton>button:hover{opacity:0.9!important;}
    .stTabs [data-baseweb="tab"]{color:#6b7280!important;font-size:14px!important;}
    .stTabs [aria-selected="true"]{color:#6366f1!important;border-bottom-color:#6366f1!important;}
    div[data-testid="stForm"]{background:#0f172a;border:1px solid #1f2937;border-radius:16px;padding:32px;}
    .stAlert{border-radius:8px!important;}
    </style>
    """, unsafe_allow_html=True)

    # Hero section
    col_l, col_c, col_r = st.columns([1, 2, 1])
    with col_c:
        st.markdown("""
        <div style='text-align:center;padding:60px 0 32px;'>
          <div style='display:inline-flex;align-items:center;justify-content:center;
               width:64px;height:64px;background:linear-gradient(135deg,#6366f1,#8b5cf6);
               border-radius:16px;font-size:28px;margin-bottom:16px;
               box-shadow:0 0 30px rgba(99,102,241,0.4);'>🛡️</div>
          <div style='font-size:28px;font-weight:700;color:#f9fafb;margin-bottom:6px;'>
            Forensic Digital Twin Platform
          </div>
          <div style='font-size:13px;color:#4b5563;letter-spacing:2px;font-family:JetBrains Mono,monospace;'>
            REAL-TIME IoT SECURITY MONITORING
          </div>
          <div style='margin-top:12px;display:flex;justify-content:center;gap:16px;'>
            <span style='font-size:11px;color:#22c55e;background:rgba(34,197,94,0.1);
                  border:1px solid rgba(34,197,94,0.2);padding:3px 10px;border-radius:20px;'>
              ● 3 Devices Supported
            </span>
            <span style='font-size:11px;color:#6366f1;background:rgba(99,102,241,0.1);
                  border:1px solid rgba(99,102,241,0.2);padding:3px 10px;border-radius:20px;'>
              8-Layer Detection
            </span>
            <span style='font-size:11px;color:#f59e0b;background:rgba(245,158,11,0.1);
                  border:1px solid rgba(245,158,11,0.2);padding:3px 10px;border-radius:20px;'>
              v{APP_VERSION}
            </span>
          </div>
        </div>
        """.replace("{APP_VERSION}", APP_VERSION), unsafe_allow_html=True)

        tab_login, tab_register = st.tabs(["🔐  Sign In", "📝  Create Account"])

        # ── LOGIN ─────────────────────────────────────────────────────────────
        with tab_login:
            with st.form("login_form"):
                st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
                username = st.text_input("Username", placeholder="Enter your username")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
                submit = st.form_submit_button("Sign In →")

                if submit:
                    if not username or not password:
                        st.error("Please enter username and password.")
                    else:
                        user = db.get_user_by_username(username)
                        if user and db.verify_password(password, user["password_hash"]):
                            token = db.create_session(user["id"])
                            st.session_state["auth_token"] = token
                            st.success(f"Welcome back, {user['full_name'] or username}!")
                            st.rerun()
                        else:
                            st.error("Invalid username or password.")

            st.markdown("""
            <div style='text-align:center;margin-top:16px;padding:12px;background:#111827;
                 border:1px solid #1f2937;border-radius:8px;'>
              <div style='font-size:11px;color:#4b5563;margin-bottom:4px;'>DEFAULT CREDENTIALS</div>
              <div style='font-family:JetBrains Mono,monospace;font-size:12px;color:#6366f1;'>
                admin / admin123
              </div>
            </div>
            """, unsafe_allow_html=True)

        # ── REGISTER ──────────────────────────────────────────────────────────
        with tab_register:
            with st.form("register_form"):
                st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
                r_fullname = st.text_input("Full Name",  placeholder="Your full name")
                r_username = st.text_input("Username",   placeholder="Choose a username")
                r_email    = st.text_input("Email",      placeholder="your@email.com")
                r_password = st.text_input("Password",   type="password", placeholder="Min 6 characters")
                r_confirm  = st.text_input("Confirm Password", type="password", placeholder="Repeat password")
                st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
                r_submit   = st.form_submit_button("Create Account →")

                if r_submit:
                    if not all([r_fullname, r_username, r_email, r_password, r_confirm]):
                        st.error("All fields are required.")
                    elif len(r_password) < 6:
                        st.error("Password must be at least 6 characters.")
                    elif r_password != r_confirm:
                        st.error("Passwords do not match.")
                    else:
                        # Register under default org (org_id=1)
                        result = db.register_user(
                            org_id=1,
                            username=r_username,
                            email=r_email,
                            password=r_password,
                            role="analyst",
                            full_name=r_fullname
                        )
                        if result["ok"]:
                            st.success("Account created! Please sign in.")
                        else:
                            if "UNIQUE" in result.get("error", ""):
                                st.error("Username or email already exists.")
                            else:
                                st.error(f"Registration failed: {result['error']}")

        # Features row
        st.markdown("""
        <div style='display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-top:24px;'>
          <div style='background:#0f172a;border:1px solid #1f2937;border-radius:10px;padding:14px;text-align:center;'>
            <div style='font-size:20px;margin-bottom:6px;'>🔐</div>
            <div style='font-size:12px;font-weight:600;color:#d1d5db;'>RSA Signed</div>
            <div style='font-size:11px;color:#4b5563;'>Every packet verified</div>
          </div>
          <div style='background:#0f172a;border:1px solid #1f2937;border-radius:10px;padding:14px;text-align:center;'>
            <div style='font-size:20px;margin-bottom:6px;'>🧠</div>
            <div style='font-size:12px;font-weight:600;color:#d1d5db;'>AI Detection</div>
            <div style='font-size:11px;color:#4b5563;'>LSTM per device</div>
          </div>
          <div style='background:#0f172a;border:1px solid #1f2937;border-radius:10px;padding:14px;text-align:center;'>
            <div style='font-size:20px;margin-bottom:6px;'>📄</div>
            <div style='font-size:12px;font-weight:600;color:#d1d5db;'>Legal Evidence</div>
            <div style='font-size:11px;color:#4b5563;'>SHA-256 sealed PDF</div>
          </div>
        </div>
        """, unsafe_allow_html=True)
