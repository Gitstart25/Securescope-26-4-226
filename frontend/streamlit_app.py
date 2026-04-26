import streamlit as st
import requests
import base64

# --------------------------------------------------
# CONFIG
# --------------------------------------------------
BACKEND_URL = "http://127.0.0.1:5000/scan"
DOWNLOAD_URL = "http://127.0.0.1:5000/download-report"

st.set_page_config(
    page_title="SecureScope Scanner",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 SecureScope – Vulnerability Scanner")
st.markdown("AIML-powered false positive filtering for OWASP ZAP scans")

# --------------------------------------------------
# INPUT
# --------------------------------------------------
url = st.text_input(
    "🌐 Enter Target URL",
    placeholder="https://example.com"
)

scan_btn = st.button("🚀 Start Scan")

# --------------------------------------------------
# SCAN
# --------------------------------------------------
if scan_btn and url:

    with st.spinner("Running OWASP ZAP scan... This may take a few minutes ⏳"):
        try:
            response = requests.post(
                BACKEND_URL,
                json={"url": url},
                timeout=None
            )

            data = response.json()

        except Exception as e:
            st.error(f"❌ Backend not reachable: {e}")
            st.stop()

    # --------------------------------------------------
    # ERROR HANDLING
    # --------------------------------------------------
    if "error" in data:
        st.error(f"❌ Scan Failed: {data.get('details', 'Unknown error')}")
        st.stop()

    # --------------------------------------------------
    # DATA EXTRACTION
    # --------------------------------------------------
    total_alerts = data.get("total_alerts", 0)
    mapped_alerts = data.get("mapped_alerts", 0)
    true_positives = data.get("true_positives", 0)
    results = data.get("results", [])

    # --------------------------------------------------
    # METRICS
    # --------------------------------------------------
    col1, col2, col3 = st.columns(3)

    col1.metric("🔔 Total Alerts", total_alerts)
    col2.metric("🔗 Mapped Alerts", mapped_alerts)
    col3.metric("✅ True Positives", true_positives)

    st.divider()

    # --------------------------------------------------
    # RESULTS DISPLAY
    # --------------------------------------------------
    if true_positives == 0:
        st.warning("⚠ No true positives detected.")
    else:
        st.success(f"✅ {true_positives} genuine vulnerabilities found")

        for i, alert in enumerate(results, 1):
            with st.expander(f"#{i} {alert.get('alert', 'Unknown Alert')}"):
                st.write(f"**Risk:** {alert.get('risk', 'NA')}")
                st.write(f"**CWE:** {alert.get('cweid', 'NA')}")
                st.write(f"**Parameter:** {alert.get('param', 'NA')}")
                st.write(f"**Evidence:** {alert.get('evidence', 'NA')}")
                st.write(f"**Confidence Score:** {alert.get('true_positive_score', 'NA')}")

    # --------------------------------------------------
    # PDF DOWNLOAD + PREVIEW (FIXED)
    # --------------------------------------------------
    st.divider()
    st.subheader("📄 Vulnerability Report")

    try:
        pdf_response = requests.get(DOWNLOAD_URL)

        if pdf_response.status_code == 200:
            pdf_bytes = pdf_response.content

            # ✅ Download button
            st.download_button(
                label="⬇ Download PDF Report",
                data=pdf_bytes,
                file_name="SecureScope_Report.pdf",
                mime="application/pdf"
            )

            # Convert to base64 for preview
            pdf_base64 = base64.b64encode(pdf_bytes).decode("utf-8")

            # ✅ Chrome-safe preview using EMBED
            st.markdown("#### 📄 PDF Preview")
            pdf_display = f"""
            <embed 
                src="data:application/pdf;base64,{pdf_base64}" 
                width="100%" 
                height="700px" 
                type="application/pdf">
            """
            st.markdown(pdf_display, unsafe_allow_html=True)

            # ✅ Open in new tab (backup)
            st.link_button("📂 Open Full PDF in New Tab", DOWNLOAD_URL)

            st.toast("📄 Report Ready!", icon="✅")

        else:
            st.error("❌ Failed to fetch PDF from backend")

    except Exception as e:
        st.error(f"❌ Error downloading PDF: {e}")

else:
    st.info("👆 Enter a URL and click 'Start Scan' to begin.")