
import streamlit as st
import joblib
import pandas as pd
import ipaddress
from pathlib import Path
from urllib.parse import urlparse

# ---------------- PAGE CONFIGURATION ----------------
st.set_page_config(
    page_title="TraceGuard | URL Risk Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- COMPACT UI STYLING ----------------
st.markdown("""
<style>
    .block-container {
        max-width: 1050px;
        padding-top: 1.2rem;
        padding-bottom: 0.8rem;
    }

    h1 {
        font-size: 2.3rem !important;
        margin-bottom: 0.15rem !important;
    }

    h2 {
        font-size: 1.45rem !important;
        margin-top: 0.5rem !important;
        margin-bottom: 0.4rem !important;
    }

    h3 {
        font-size: 1.15rem !important;
        margin-top: 0.4rem !important;
        margin-bottom: 0.3rem !important;
    }

    div.stButton > button,
    div.stFormSubmitButton > button {
        min-height: 2.8rem;
        font-weight: 600;
        border-radius: 8px;
    }

    div[data-testid="stMetric"] {
        padding: 0.6rem;
        border: 1px solid rgba(128, 128, 128, 0.25);
        border-radius: 10px;
    }

    hr {
        margin: 0.7rem 0 !important;
    }

    div[data-testid="stCaptionContainer"] {
        font-size: 0.78rem;
    }
</style>
""", unsafe_allow_html=True)


# ---------------- LOAD MODEL ----------------
MODEL_PATH = Path(__file__).parent / "models" / "traceguard_model.joblib"


@st.cache_resource
def load_model():
    saved_data = joblib.load(MODEL_PATH)
    return saved_data["model"], saved_data["feature_names"]


try:
    model, feature_names = load_model()
except Exception as error:
    st.error(f"Could not load the trained model: {error}")
    st.stop()


# ---------------- FEATURE EXTRACTION ----------------
suspicious_words = [
    "login", "verify", "account", "update",
    "secure", "banking", "password", "signin",
    "confirm", "wallet"
]


def normalize_url(url):
    url = str(url).strip()
    if "://" not in url:
        url = "http://" + url
    return url


def extract_features(url):
    raw_url = str(url).strip()
    parse_url = normalize_url(raw_url)

    try:
        parsed = urlparse(parse_url)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        scheme = parsed.scheme.lower()
    except (ValueError, TypeError):
        hostname = ""
        path = ""
        scheme = ""

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    shortener_domains = [
        "bit.ly", "tinyurl.com", "t.co",
        "goo.gl", "is.gd"
    ]

    uses_shortener = int(
        any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in shortener_domains
        )
    )

    lower_url = raw_url.lower()

    return [
        len(raw_url),
        len(hostname),
        len(path),
        raw_url.count("."),
        raw_url.count("-"),
        raw_url.count("@"),
        raw_url.count("?"),
        raw_url.count("="),
        raw_url.count("/"),
        int(scheme == "https"),
        has_ip,
        sum(word in lower_url for word in suspicious_words),
        uses_shortener
    ]


# ---------------- URL VALIDATION ----------------
def validate_url(url):
    candidate = normalize_url(url)

    try:
        parsed = urlparse(candidate)
        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and not any(c.isspace() for c in parsed.netloc)
        )
    except (ValueError, TypeError):
        return False


# ---------------- COMMON HOMEPAGE REFERENCES ----------------
# Illustrative reference values, not verified security scores.
KNOWN_HOMEPAGES = {
    "google.com": 1.0,
    "www.google.com": 1.0,
    "youtube.com": 2.0,
    "www.youtube.com": 2.0,
    "wikipedia.org": 1.0,
    "www.wikipedia.org": 1.0,
    "instagram.com": 3.0,
    "www.instagram.com": 3.0,
    "github.com": 2.0,
    "www.github.com": 2.0,
    "microsoft.com": 2.0,
    "www.microsoft.com": 2.0,
    "amazon.com": 3.0,
    "www.amazon.com": 3.0,
    "apple.com": 2.0,
    "www.apple.com": 2.0,
    "linkedin.com": 2.0,
    "www.linkedin.com": 2.0,
    "reddit.com": 3.0,
    "www.reddit.com": 3.0,
    "example.com": 1.0,
    "www.example.com": 1.0
}


def get_homepage_reference(url):
    candidate = url.strip()

    if "://" not in candidate:
        candidate = "https://" + candidate

    try:
        parsed = urlparse(candidate)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").rstrip("/")

        if (
            parsed.scheme == "https"
            and hostname in KNOWN_HOMEPAGES
            and path == ""
            and not parsed.query
            and not parsed.fragment
            and parsed.port in (None, 443)
        ):
            return KNOWN_HOMEPAGES[hostname]

    except (ValueError, TypeError):
        pass

    return None


# ---------------- HEADER ----------------
st.title("🛡️ TraceGuard")
st.caption("DIGITAL PRIVACY & PHISHING RISK ANALYZER")

st.write(
    "Analyze URL characteristics to estimate potential phishing "
    "and malicious-link risk. Submitted URLs are analyzed as text; "
    "this app does not visit the website."
)

st.divider()


# ---------------- URL ANALYZER ----------------
st.header("🔎 URL Risk Analysis")

with st.form("url_analysis_form"):
    url_input = st.text_input(
        "Enter a URL",
        placeholder="https://www.google.com/"
    )

    _, button_col, _ = st.columns([1, 1.2, 1])

    with button_col:
        analyze = st.form_submit_button(
            "🛡️ Analyze URL",
            type="primary",
            use_container_width=True
        )


if analyze:
    url_input = url_input.strip()

    if not url_input:
        st.warning("Please enter a URL first.")

    elif not validate_url(url_input):
        st.error(
            "Please enter a valid HTTP or HTTPS URL, "
            "such as https://www.google.com/"
        )

    else:
        st.divider()
        st.subheader("📊 Analysis Result")

        reference_risk = get_homepage_reference(url_input)

        if reference_risk is not None:
            risk_percentage = reference_risk

            st.success("Recognized website homepage")

            st.caption(
                "Illustrative homepage reference estimate, "
                "not a verified security assessment."
            )

        else:
            feature_values = extract_features(url_input)

            input_features = pd.DataFrame(
                [feature_values],
                columns=feature_names
            )

            try:
                if not hasattr(model, "predict_proba"):
                    st.error(
                        "This model cannot provide a risk probability."
                    )
                    st.stop()

                classes = list(model.classes_)

                if 1 not in classes:
                    st.error(
                        "The model does not contain the expected "
                        "malicious class."
                    )
                    st.stop()

                prediction = int(model.predict(input_features)[0])

                probabilities = model.predict_proba(input_features)[0]

                malicious_index = classes.index(1)

                risk_percentage = float(
                    probabilities[malicious_index] * 100
                )

                if prediction == 1:
                    st.error("⚠️ Potentially Malicious URL")
                else:
                    st.success(
                        "✅ Model classifies this URL as benign"
                    )

            except Exception as error:
                st.error(f"Could not analyze this URL: {error}")
                st.stop()

        # ---------------- RISK METRICS ----------------
        col1, col2 = st.columns(2)

        with col1:
            st.metric(
                "Estimated malicious risk",
                f"{risk_percentage:.2f}%"
            )

        with col2:
            if risk_percentage < 20:
                st.success("Lower estimated risk")
            elif risk_percentage < 50:
                st.warning("Moderate estimated risk")
            else:
                st.error("Higher estimated risk")

        st.caption(
            "Estimates may be incorrect. A low score does not "
            "guarantee that a website is safe."
        )

        # ---------------- STRUCTURAL INDICATORS ----------------
        st.subheader("🔍 URL Structural Indicators")

        feature_values = extract_features(url_input)

        indicators = {
            "URL length": feature_values[0],
            "Hostname length": feature_values[1],
            "Path length": feature_values[2],
            "Dot count": feature_values[3],
            "Hyphen count": feature_values[4],
            "Contains @ symbol": "Yes" if feature_values[5] else "No",
            "Question mark count": feature_values[6],
            "Equals sign count": feature_values[7],
            "Slash count": feature_values[8],
            "Uses HTTPS": "Yes" if feature_values[9] else "No",
            "IP address used as hostname": (
                "Yes" if feature_values[10] else "No"
            ),
            "Suspicious keyword matches": feature_values[11],
            "Recognized URL shortener": (
                "Yes" if feature_values[12] else "No"
            )
        }

        st.dataframe(
            pd.DataFrame(
                indicators.items(),
                columns=["Indicator", "Value"]
            ),
            use_container_width=True,
            hide_index=True,
            height=300
        )


# ---------------- PRIVACY HABITS CHECK ----------------
st.divider()
st.header("🔐 Digital Privacy Self-Check")
st.caption("Select the habits you currently follow.")

habits = [
    "I use unique passwords for important accounts.",
    "I enable two-factor authentication where available.",
    "I check the domain before entering passwords.",
    "I avoid clicking unexpected links in messages.",
    "I keep my browser and operating system updated."
]

selected_habits = []

left_col, right_col = st.columns(2)

for i, habit in enumerate(habits):
    target_col = left_col if i % 2 == 0 else right_col

    with target_col:
        if st.checkbox(habit, key=habit):
            selected_habits.append(habit)

if st.button("Check My Privacy Habits"):
    score = len(selected_habits)

    st.progress(score / len(habits))
    st.write(f"Privacy habits score: **{score}/5**")

    if score <= 2:
        st.warning(
            "Consider improving your account and browsing "
            "security habits."
        )
    elif score <= 4:
        st.info(
            "Good start! Review the habits you have not selected."
        )
    else:
        st.success(
            "Great! Continue maintaining these security habits."
        )


# ---------------- FOOTER ----------------
st.divider()

st.caption(
    "TraceGuard | Educational project | Predictions may be "
    "incorrect. Never rely on this tool alone to decide whether "
    "a link is safe."
)
