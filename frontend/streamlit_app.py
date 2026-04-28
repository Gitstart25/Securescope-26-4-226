import streamlit as st
import requests
import pandas as pd
import base64

FLASK_URL = "http://127.0.0.1:5000"

st.set_page_config(
    page_title="SecureScope",
    layout="wide"
)

st.title("🔐 SecureScope - An Intelligent Web Security Assessment Framework")

# =================================================
# SESSION STATE
# =================================================
if "user_id" not in st.session_state:
    st.session_state.user_id = None

if "username" not in st.session_state:
    st.session_state.username = None


# =================================================
# SIDEBAR MENU
# =================================================
menu = ["Login", "Signup", "Dashboard"]
choice = st.sidebar.selectbox("Menu", menu)


# =================================================
# PDF PREVIEW FUNCTION
# =================================================
def show_pdf(pdf_bytes):
    base64_pdf = base64.b64encode(pdf_bytes).decode("utf-8")

    pdf_display = f"""
        <iframe
            src="data:application/pdf;base64,{base64_pdf}"
            width="100%"
            height="700"
            type="application/pdf">
        </iframe>
    """

    st.markdown(pdf_display, unsafe_allow_html=True)


# =================================================
# SIGNUP PAGE
# =================================================
if choice == "Signup":
    st.subheader("Create New Account")

    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Signup"):
        try:
            response = requests.post(
                f"{FLASK_URL}/signup",
                json={
                    "username": username,
                    "email": email,
                    "password": password
                }
            )

            result = response.json()

            if response.status_code == 200:
                st.success(result["message"])
            else:
                st.error(result["message"])

        except Exception as e:
            st.error("Backend error during signup")
            st.error(str(e))


# =================================================
# LOGIN PAGE
# =================================================
elif choice == "Login":
    st.subheader("Login")

    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        try:
            response = requests.post(
                f"{FLASK_URL}/login",
                json={
                    "email": email,
                    "password": password
                }
            )

            data = response.json()

            if "user_id" in data:
                st.session_state.user_id = data["user_id"]
                st.session_state.username = data["username"]

                st.success(f"Welcome, {data['username']}")
                st.rerun()

            else:
                st.error(data["message"])

        except Exception as e:
            st.error("Backend error during login")
            st.error(str(e))


# =================================================
# DASHBOARD PAGE
# =================================================
elif choice == "Dashboard":

    if not st.session_state.user_id:
        st.warning("Please login first")
        st.stop()

    st.subheader(f"Welcome, {st.session_state.username}")

    # =================================================
    # WEBSITE SCAN
    # =================================================
    st.markdown("## 🌐 Website Scan")

    target_url = st.text_input("Enter Target URL")

    if st.button("Start Scan"):
        if not target_url:
            st.warning("Please enter a URL")

        else:
            status_box = st.empty()

            try:
                status_box.info("🔄 Starting scan...")

                response = requests.post(
                    f"{FLASK_URL}/scan",
                    json={
                        "url": target_url,
                        "user_id": st.session_state.user_id
                    }
                )

                result = response.json()

                if "error" in result:
                    status_box.error(result["error"])

                elif "message" in result and result["message"] == "No alerts found":
                    status_box.warning("No vulnerabilities found")

                else:
                    status_box.info(
                        f"[+] Starting scan for: {result['target']}"
                    )

                    st.write(f"✔ ZAP Alerts Found: {result['total_alerts']}")
                    st.write(f"✔ Alerts Mapped: {result['mapped_alerts']}")
                    st.write(f"✔ True Positives Identified: {result['true_positives']}")
                    st.write("✔ Scan history saved")

                    st.success("✅ Scan Completed Successfully")

                    st.markdown("### Scan Summary")
                    st.write(f"**Target URL:** {result['target']}")
                    st.write(f"**Total Alerts:** {result['total_alerts']}")
                    st.write(f"**Mapped Alerts:** {result['mapped_alerts']}")
                    st.write(f"**True Positives:** {result['true_positives']}")

                    st.markdown("### Vulnerabilities Found")
                    st.json(result["results"])

            except Exception as e:
                status_box.error("Scan failed due to backend issue")
                st.error(str(e))

    # =================================================
    # PDF REPORT SECTION
    # =================================================
    st.markdown("## 📄 PDF Report")

    if st.button("Preview Latest PDF Report"):
        try:
            report_response = requests.get(
                f"{FLASK_URL}/download-report"
            )

            if report_response.status_code == 200:
                st.success("PDF Report Loaded Successfully")

                pdf_bytes = report_response.content

                st.download_button(
                    label="⬇ Download PDF Report",
                    data=pdf_bytes,
                    file_name="SecureScope_Report.pdf",
                    mime="application/pdf"
                )

                st.markdown("### PDF Preview")
                show_pdf(pdf_bytes)

            else:
                st.error("No report found. Please run a scan first.")

        except Exception as e:
            st.error("Failed to load PDF report")
            st.error(str(e))

    # =================================================
    # SCAN HISTORY
    # =================================================
    st.markdown("## 🕘 Scan History")

    if st.button("Load My Scan History"):
        try:
            history_response = requests.get(
                f"{FLASK_URL}/scan-history/{st.session_state.user_id}"
            )

            history = history_response.json()

            if not history:
                st.info("No scan history found")

            else:
                clean_history = []

                for item in history:
                    clean_history.append({
                        "Target URL": item["url"],
                        "Scan Time": item["timestamp"],
                        "Total Vulnerabilities": len(item["vulnerabilities"])
                    })

                df = pd.DataFrame(clean_history)

                st.dataframe(
                    df,
                    use_container_width=True
                )

        except Exception as e:
            st.error("Failed to load scan history")
            st.error(str(e))

    # =================================================
    # LOGOUT
    # =================================================
    st.markdown("## 🚪 Logout")

    if st.button("Logout"):
        st.session_state.user_id = None
        st.session_state.username = None

        st.success("Logged out successfully")
        st.rerun()