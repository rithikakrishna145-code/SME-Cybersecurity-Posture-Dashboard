
"""
SME Cybersecurity Posture Dashboard
Run with:
py -3.12 -m streamlit run dashboard/app.py
"""

import json
import os
import hashlib
import hmac

import streamlit as st
import pandas as pd


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="SME Security Portal",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# DEMO LOGIN CREDENTIALS
# Change these for your demonstration.
# Do not use hardcoded credentials in production.
# --------------------------------------------------

DEMO_USER_ID = "admin"
DEMO_PASSWORD_HASH = hashlib.sha256(
    b"SME@12345"
).hexdigest()


RATING_COLORS = {
    "Strong": "#1E7A46",
    "Moderate": "#D98C3D",
    "Weak": "#C9622A",
    "Critical": "#B3261E"
}


# --------------------------------------------------
# LOGIN PAGE
# --------------------------------------------------

def show_login():

    if st.session_state.get("authenticated", False):
        return True

    st.markdown(
        """
        <style>
        .login-title {
            text-align: center;
            font-size: 34px;
            font-weight: 700;
            color: #1E7A46;
            margin-top: 35px;
        }
        .login-subtitle {
            text-align: center;
            font-size: 16px;
            color: #777777;
            margin-bottom: 25px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="login-title">🛡️ SME Security Portal</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="login-subtitle">'
        'Secure access to your company cybersecurity analysis'
        '</div>',
        unsafe_allow_html=True
    )

    left, center, right = st.columns([1, 1.2, 1])

    with center:

        with st.container(border=True):

            st.subheader("Welcome Back")
            st.write("Sign in to access the security dashboard.")

            with st.form("login_form"):

                user_id = st.text_input(
                    "User ID",
                    placeholder="Enter your User ID"
                )

                password = st.text_input(
                    "Password",
                    type="password",
                    placeholder="Enter your password"
                )

                submitted = st.form_submit_button(
                    "Login",
                    use_container_width=True,
                    type="primary"
                )

            if submitted:

                entered_hash = hashlib.sha256(
                    password.encode("utf-8")
                ).hexdigest()

                valid_user = hmac.compare_digest(
                    user_id,
                    DEMO_USER_ID
                )

                valid_password = hmac.compare_digest(
                    entered_hash,
                    DEMO_PASSWORD_HASH
                )

                if valid_user and valid_password:

                    st.session_state["authenticated"] = True
                    st.session_state["user_id"] = user_id

                    st.rerun()

                else:
                    st.error(
                        "Invalid User ID or password. Please try again."
                    )

            st.caption(
                "Authorized users only. Demo login is configured "
                "for the academic prototype."
            )

    return False


# --------------------------------------------------
# LOAD COMPANY REPORTS
# --------------------------------------------------

@st.cache_data
def load_reports():

    path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "data",
        "processed",
        "posture_reports.json"
    )

    with open(path, encoding="utf-8") as file:
        return json.load(file)


# --------------------------------------------------
# MAIN SECURITY DASHBOARD
# --------------------------------------------------

def main():

    st.title("🛡️ SME Security Posture Dashboard")

    st.caption(
        "Explainable security scoring with "
        "ML-driven anomaly detection"
    )

    # User information and logout
    st.sidebar.success(
        f"Logged in as: {st.session_state.get('user_id', 'User')}"
    )

    if st.sidebar.button("Logout", use_container_width=True):

        st.session_state["authenticated"] = False
        st.session_state.pop("user_id", None)

        st.rerun()

    try:
        reports = load_reports()

    except FileNotFoundError:

        st.error(
            "No posture reports found. Run the data generator "
            "and analysis pipeline first."
        )

        st.code(
            "py -3.12 src\\data_generator.py\n"
            "py -3.12 src\\run_pipeline.py"
        )

        return

    if not reports:
        st.warning("No company reports are available.")
        return

    # Company selection
    org_names = [report["org_name"] for report in reports]

    selected_org = st.sidebar.selectbox(
        "Select Organization",
        org_names
    )

    report = next(
        item for item in reports
        if item["org_name"] == selected_org
    )

    # All organization scores
    st.sidebar.markdown("---")
    st.sidebar.markdown("### All Organizations")

    for item in reports:

        color = RATING_COLORS.get(
            item.get("rating"),
            "#666666"
        )

        st.sidebar.markdown(
            f"<span style='color:{color}'>●</span> "
            f"{item['org_name']}: "
            f"**{item['total_score']}/100** "
            f"({item['rating']})",
            unsafe_allow_html=True
        )

    # Overall posture
    col1, col2, col3 = st.columns([1, 1, 2])

    with col1:
        st.metric(
            "Posture Score",
            f"{report['total_score']:.0f} / 100"
        )

    with col2:

        color = RATING_COLORS.get(
            report.get("rating"),
            "#666666"
        )

        st.markdown(
            f"<h3 style='color:{color}'>"
            f"{report['rating']}</h3>",
            unsafe_allow_html=True
        )

    with col3:
        st.write("Overall Security Score")
        st.progress(
            max(0.0, min(report["total_score"] / 100, 1.0))
        )

    # Category breakdown
    st.markdown("---")
    st.subheader("📊 Category Breakdown")

    cat_data = report["category_breakdown"]

    cat_df = pd.DataFrame([
        {
            "Category": category,
            "Score": values["awarded"],
            "Max": values["possible"]
        }
        for category, values in cat_data.items()
    ])

    st.bar_chart(
        cat_df.set_index("Category")["Score"]
    )

    cols = st.columns(max(1, len(cat_data)))

    for col, (category, values) in zip(cols, cat_data.items()):

        with col:
            st.metric(
                category,
                f"{values['awarded']:.1f} / "
                f"{values['possible']:.0f}"
            )

    # Detailed findings
    st.markdown("---")
    st.subheader("🔎 Detailed Security Findings")

    st.caption(
        "Review the checks contributing to the security assessment."
    )

    findings_df = pd.DataFrame(report["findings"])

    if not findings_df.empty:

        findings_df["Status"] = findings_df["passed"].apply(
            lambda value: "✅ Pass" if value else "❌ Fail"
        )

        display_df = findings_df[
            [
                "category",
                "check_name",
                "Status",
                "points_awarded",
                "points_possible",
                "detail"
            ]
        ]

        display_df.columns = [
            "Category",
            "Check",
            "Status",
            "Points Awarded",
            "Points Possible",
            "Detail"
        ]

        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No detailed findings are available.")

    # Machine-learning anomaly results
    
    # Machine-learning anomaly results
    st.markdown("---")
    st.subheader("🤖 Anomaly Detection (Isolation Forest)")

    ml_val = report.get("ml_validation")

    if ml_val:

        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "Precision",
            f"{ml_val['precision']:.3f}"
        )

        c2.metric(
            "Recall",
            f"{ml_val['recall']:.3f}"
        )

        c3.metric(
            "F1-Score",
            f"{ml_val['f1_score']:.3f}"
        )

        c4.metric(
            "Accuracy",
            f"{ml_val['accuracy']:.3f}"
        )

        st.caption(
            "Results are based on validation against injected "
            "synthetic anomalies."
        )

    else:
        st.info(
            "No ML validation metrics are available for this report."
        )



# --------------------------------------------------
# APPLICATION ENTRY POINT
# --------------------------------------------------

if show_login():
    main()
else:
    st.stop()
