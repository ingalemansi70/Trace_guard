
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

    uses_shortener = int(
        any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in [
                "bit.ly", "tinyurl.com", "t.co",
                "goo.gl", "is.gd"
            ]
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
# Illustrative demo reference values, not verified security scores.
# Only exact homepages match; URLs with paths or query strings use the model.
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
st.subheader("Digital Privacy & Phishing Risk Analyzer")

st.write(
    "Analyze URL characteristics to estimate potential phishing "
    "and malicious-link risk. URLs are analyzed as text; this app "
    "does not open or visit the submitted website."
)

st.divider()


# ---------------- URL ANALYZER ----------------
st.header("🔎 URL Risk Analysis")

with st.form("url_analysis_form"):
    url_input = st.text_input(
        "Enter a URL",
        placeholder="Example: https://www.google.com/"
    )
    analyze = st.form_submit_button(
        "Analyze URL",
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
        st.subheader("Analysis Result")

        reference_risk = get_homepage_reference(url_input)

        if reference_risk is not None:
            risk_percentage = reference_risk
            st.success("Recognized website homepage")
            st.caption(
                "This is an illustrative homepage reference estimate, "
                "not a verified security assessment."
            )
        else:
            feature_values = extract_features(url_input)
            input_features = pd.DataFrame(
                [feature_values],
                columns=feature_names
            )

            try:
                prediction = int(model.predict(input_features)[0])
                classes = list(model.classes_)

                if not hasattr(model, "predict_proba") or 1 not in classes:
                    st.error(
                        "This model cannot provide a malicious-risk "
                        "probability for this input."
                    )
                    st.stop()

                probabilities = model.predict_proba(input_features)[0]
                malicious_index = classes.index(1)
                risk_percentage = float(
                    probabilities[malicious_index] * 100
                )

                if prediction == 1:
                    st.error("⚠️ Potentially Malicious URL")
                else:
                    st.success("✅ Model classifies this URL as benign")

            except Exception as error:
                st.error(f"Could not analyze this URL: {error}")
                st.stop()

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
            "Estimates may be incorrect. A low score does not guarantee "
            "that a website is safe."
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
            "IP address used as hostname": "Yes" if feature_values[10] else "No",
            "Suspicious keyword matches": feature_values[11],
            "Recognized URL shortener": "Yes" if feature_values[12] else "No"
        }

        st.dataframe(
            pd.DataFrame(
                indicators.items(),
                columns=["Indicator", "Value"]
            ),
            use_container_width=True,
            hide_index=True
        )


# ---------------- PRIVACY HABITS CHECK ----------------
st.divider()
st.header("🔐 Digital Privacy Self-Check")
st.write("Select the habits you currently follow.")

habits = [
    "I use unique passwords for important accounts.",
    "I enable two-factor authentication where available.",
    "I check the domain before entering passwords.",
    "I avoid clicking unexpected links in messages.",
    "I keep my browser and operating system updated."
]

selected_habits = []

for habit in habits:
    if st.checkbox(habit, key=habit):
        selected_habits.append(habit)

if st.button("Check My Privacy Habits"):
    score = len(selected_habits)
    st.progress(score / len(habits))
    st.write(f"Privacy habits score: **{score}/5**")

    if score <= 2:
        st.warning(
            "Consider improving your account and browsing security habits."
        )
    elif score <= 4:
        st.info("Good start! Review the habits you have not selected.")
    else:
        st.success(
            "Great! Continue maintaining these security habits."
        )


# ---------------- FOOTER ----------------
st.divider()
st.caption(
    "TraceGuard | Educational project | Predictions may be incorrect. "
    "Never rely on this tool alone to decide whether a link is safe."
)
