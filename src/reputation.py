import os
import sys
import ipaddress
import joblib

# Allow imports from the src directory
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from feature_builder import build_features


MODEL_PATH = os.path.join(
    os.path.dirname(CURRENT_DIR),
    "models",
    "phishing_model.pkl"
)


def check_basic_reputation(url):
    """
    Basic defensive reputation checks.

    This does NOT claim that a website is malicious.
    It only identifies simple risk indicators.
    """

    from urllib.parse import urlparse

    result = {
        "status": "UNKNOWN",
        "risk_score": 0,
        "reasons": []
    }

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            result["status"] = "SUSPICIOUS"
            result["risk_score"] = 50
            result["reasons"].append(
                "Hostname could not be extracted."
            )
            return result

        # Check whether hostname is an IP address
        try:
            ipaddress.ip_address(hostname)

            result["risk_score"] += 20
            result["reasons"].append(
                "URL uses an IP address instead of a domain name."
            )

        except ValueError:
            pass

        # Check HTTPS
        if parsed.scheme.lower() != "https":

            result["risk_score"] += 10
            result["reasons"].append(
                "Website does not use HTTPS."
            )

        # Determine status
        if result["risk_score"] == 0:
            result["status"] = "LOW_RISK"

        elif result["risk_score"] < 30:
            result["status"] = "REVIEW"

        else:
            result["status"] = "SUSPICIOUS"

        if not result["reasons"]:
            result["reasons"].append(
                "No obvious basic reputation indicators found."
            )

        return result

    except Exception as e:

        result["status"] = "UNKNOWN"
        result["reasons"].append(
            f"Reputation check failed: {e}"
        )

        return result


def load_model():

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}"
        )

    return joblib.load(MODEL_PATH)


def predict_phishing(model, features):

    feature_values = [
        features[name]
        for name in model.feature_names_in_
    ]

    probabilities = model.predict_proba(
        [feature_values]
    )[0]

    class_probabilities = dict(
        zip(model.classes_, probabilities)
    )

    phishing_probability = class_probabilities.get(
        0,
        0.0
    )

    legitimate_probability = class_probabilities.get(
        1,
        0.0
    )

    prediction = (
        "PHISHING"
        if phishing_probability >= legitimate_probability
        else "LEGITIMATE"
    )

    return (
        prediction,
        phishing_probability,
        legitimate_probability
    )


def main():

    print()
    print("======================================")
    print("       HACKTVIS PhishGuard")
    print("       LIVE ML PREDICTION")
    print("======================================")

    url = input("Enter URL to scan: ").strip()

    if not url:
        print("\nERROR: URL cannot be empty.")
        return

    try:

        print()
        print("Analyzing URL and website...")
        print("Please wait...")
        print()

        # --------------------------------
        # 1. Build live website features
        # --------------------------------

        features, metadata = build_features(url)

        # --------------------------------
        # 2. Load ML model
        # --------------------------------

        model = load_model()

        # --------------------------------
        # 3. ML prediction
        # --------------------------------

        prediction, phishing_probability, legitimate_probability = (
            predict_phishing(
                model,
                features
            )
        )

        # --------------------------------
        # 4. Basic reputation
        # --------------------------------

        reputation = check_basic_reputation(
            metadata.get("final_url", url)
        )

        # --------------------------------
        # 5. Display results
        # --------------------------------

        print("======================================")
        print("       HACKTVIS PhishGuard")
        print("       SCAN RESULT")
        print("======================================")

        print(
            "Requested URL:",
            url
        )

        print(
            "Final URL:",
            metadata.get(
                "final_url",
                url
            )
        )

        print(
            "HTTP Status:",
            metadata.get(
                "status_code",
                "Unknown"
            )
        )

        print(
            "Page Title:",
            metadata.get(
                "title",
                "Unknown"
            )
        )

        print()
        print("--------------------------------------")
        print("ML PREDICTION")
        print("--------------------------------------")

        print(
            "Prediction:",
            prediction
        )

        print(
            f"Phishing Probability: "
            f"{phishing_probability * 100:.2f}%"
        )

        print(
            f"Legitimate Probability: "
            f"{legitimate_probability * 100:.2f}%"
        )

        print()
        print("--------------------------------------")
        print("BASIC REPUTATION")
        print("--------------------------------------")

        print(
            "Status:",
            reputation["status"]
        )

        print(
            "Risk Score:",
            f"{reputation['risk_score']}/100"
        )

        print()
        print("Reasons:")

        for reason in reputation["reasons"]:
            print("-", reason)

        print()
        print("--------------------------------------")
        print("FEATURE STATUS")
        print("--------------------------------------")

        print(
            f"{len(features)} ML features successfully generated."
        )

        print()
        print("======================================")

    except Exception as e:

        print()
        print("======================================")
        print("SCAN ERROR")
        print("======================================")
        print(str(e))
        print("======================================")


if __name__ == "__main__":
    main()
