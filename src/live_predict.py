
import pandas as pd
import joblib
import ipaddress

from pathlib import Path
from urllib.parse import urlparse

from feature_builder import build_features
from report import generate_report


BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_FILE = BASE_DIR / "models" / "phishing_model.pkl"


# ==========================================
# 1. BASIC REPUTATION CHECK
# ==========================================

def check_reputation(url):

    result = {
        "status": "UNKNOWN",
        "risk_score": 0,
        "reasons": []
    }

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            result["reasons"].append("Invalid hostname.")
            return result

        try:
            ipaddress.ip_address(hostname)
            result["risk_score"] += 20
            result["reasons"].append(
                "URL uses an IP address."
            )
        except ValueError:
            pass

        if parsed.scheme.lower() != "https":
            result["risk_score"] += 10
            result["reasons"].append(
                "Website does not use HTTPS."
            )

        result["status"] = (
            "LOW_RISK"
            if result["risk_score"] == 0
            else "REVIEW"
        )

    except Exception as error:
        result["reasons"].append(str(error))

    return result


# ==========================================
# 2. RISK ENGINE
# ==========================================

def calculate_risk(ml_probability, reputation, features):

    score = 0
    reasons = []

    # ML contribution: maximum 50 points
    ml_score = round(ml_probability * 50)
    score += ml_score

    if ml_probability >= 0.70:
        reasons.append(
            "ML model indicates elevated phishing probability."
        )

    elif ml_probability >= 0.40:
        reasons.append(
            "ML model indicates moderate phishing probability."
        )

    # Reputation contribution: maximum 20 points
    reputation_score = min(
        reputation["risk_score"], 20
    )

    score += reputation_score
    reasons.extend(reputation["reasons"])

    # URL indicators
    if features.get("IsDomainIP", 0):
        score += 10
        reasons.append("IP-based hostname detected.")

    if not features.get("IsHTTPS", 0):
        score += 5
        reasons.append("HTTPS is not enabled.")

    if features.get("HasObfuscation", 0):
        score += 10
        reasons.append("URL obfuscation detected.")

    score = min(score, 100)

    if score >= 70:
        level = "CRITICAL"

    elif score >= 40:
        level = "HIGH"

    elif score >= 20:
        level = "MEDIUM"

    else:
        level = "LOW"

    if not reasons:
        reasons.append(
            "No basic risk indicators detected."
        )

    return {
        "score": score,
        "level": level,
        "reasons": list(dict.fromkeys(reasons))
    }


# ==========================================
# 3. URL PREDICTION
# ==========================================

def predict_url(url):

    if not MODEL_FILE.exists():
        raise FileNotFoundError(
            f"ML model not found: {MODEL_FILE}"
        )

    # Build live website features
    features, metadata = build_features(url)

    # Load trained model
    model = joblib.load(MODEL_FILE)

    # Check feature availability
    required_features = list(model.feature_names_in_)

    missing_features = [
        name for name in required_features
        if name not in features
    ]

    if missing_features:
        raise ValueError(
            f"Missing ML features: {missing_features}"
        )

    # Create DataFrame in exact training order
    X = pd.DataFrame(
        [[features[name] for name in required_features]],
        columns=required_features
    )

    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    class_probabilities = dict(
        zip(model.classes_, probabilities)
    )

    # Dataset mapping:
    # 0 = phishing
    # 1 = legitimate

    phishing_probability = float(
        class_probabilities.get(0, 0.0)
    )

    legitimate_probability = float(
        class_probabilities.get(1, 0.0)
    )

    verdict = (
        "PHISHING"
        if prediction == 0
        else "LEGITIMATE"
    )

    # Reputation analysis
    reputation = check_reputation(
        metadata.get("final_url", url)
    )

    # Risk assessment
    risk = calculate_risk(
        phishing_probability,
        reputation,
        features
    )

    return {
        "verdict": verdict,
        "phishing_probability": phishing_probability,
        "legitimate_probability": legitimate_probability,
        "reputation": reputation,
        "risk": risk,
        "metadata": metadata,
        "features": features
    }


# ==========================================
# 4. PDF REPORT GENERATOR
# ==========================================

def create_security_report(url, result):

    scan_data = {
        "url": url,
        **result
    }

    report_path = generate_report(scan_data)

    return report_path


# ==========================================
# 5. MAIN SCANNER
# ==========================================

def main():

    print("\n" + "=" * 50)
    print("          HACKTVIS PhishGuard")
    print("          AI/ML WEBSITE SCANNER")
    print("=" * 50)

    url = input("\nEnter URL to scan: ").strip()

    if not url:
        print("Error: No URL entered.")
        return

    # Basic URL format validation
    try:
        parsed = urlparse(url)

        if (
            parsed.scheme.lower() not in ("http", "https")
            or not parsed.hostname
        ):
            print("Error: Enter a valid HTTP or HTTPS URL.")
            return

    except ValueError:
        print("Error: Invalid URL format.")
        return

    print("\nAnalyzing URL and website...")
    print("Please wait...\n")

    try:

        # Run complete scanner
        result = predict_url(url)

        # ==================================
        # SCAN RESULT
        # ==================================

        print("=" * 50)
        print("SCAN RESULT")
        print("=" * 50)

        metadata = result.get("metadata", {})

        print("Requested URL:", url)
        print("Final URL:", metadata.get("final_url", "Unknown"))
        print("HTTP Status:", metadata.get("status_code", "Unknown"))
        print("Page Title:", metadata.get("title", "Unknown"))

        # ==================================
        # MACHINE LEARNING
        # ==================================

        print("\n" + "-" * 50)
        print("MACHINE LEARNING PREDICTION")
        print("-" * 50)

        print("Prediction:", result["verdict"])

        print(
            f"Phishing Probability: "
            f"{result['phishing_probability'] * 100:.2f}%"
        )

        print(
            f"Legitimate Probability: "
            f"{result['legitimate_probability'] * 100:.2f}%"
        )

        # ==================================
        # REPUTATION
        # ==================================

        print("\n" + "-" * 50)
        print("BASIC REPUTATION")
        print("-" * 50)

        reputation = result["reputation"]

        print("Status:", reputation["status"])
        print("Indicator Score:", reputation["risk_score"])

        # ==================================
        # RISK ASSESSMENT
        # ==================================

        print("\n" + "-" * 50)
        print("FINAL RISK ASSESSMENT")
        print("-" * 50)

        risk = result["risk"]

        print("Risk Score:", f"{risk['score']}/100")
        print("Risk Level:", risk["level"])

        print("\nRisk Reasons:")

        for reason in risk["reasons"]:
            print("-", reason)

        # ==================================
        # SCAN INFORMATION
        # ==================================

        print("\n" + "-" * 50)
        print("SCAN INFORMATION")
        print("-" * 50)

        print("ML Features Generated:", len(result["features"]))
        print("ML Validation: PROVISIONAL")
        print("External Reputation Database: NOT CONNECTED")

        # ==================================
        # PDF REPORT
        # ==================================

        print("\nGenerating PDF security report...")

        report_path = create_security_report(
            url,
            result
        )

        print("\n" + "=" * 50)
        print("PDF SECURITY REPORT")
        print("=" * 50)

        print("Report generated successfully!")
        print("Report location:", report_path)

        # ==================================
        # COMPLETION
        # ==================================

        print("\n" + "=" * 50)
        print("HACKTVIS PhishGuard Scan Complete")
        print("=" * 50)

        print(
            "\nNote: Automated predictions and risk scores "
            "are experimental indicators, not confirmed verdicts."
        )

    except Exception as error:

        print("\n" + "=" * 50)
        print("SCAN FAILED")
        print("=" * 50)

        print("Error:", error)


if __name__ == "__main__":
    main()
