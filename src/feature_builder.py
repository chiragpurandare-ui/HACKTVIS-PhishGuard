from urllib.parse import urlparse
from pathlib import Path
import re

from url_analyzer import analyze_url
from website_analyzer import analyze_website


# Exact feature order used when training the Random Forest.
ML_FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "URLSimilarityIndex",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
    "LineOfCode",
    "LargestLineLength",
    "HasTitle",
    "DomainTitleMatchScore",
    "URLTitleMatchScore",
    "HasFavicon",
    "Robots",
    "IsResponsive",
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
    "HasDescription",
    "NoOfPopup",
    "NoOfiFrame",
    "HasExternalFormSubmit",
    "HasSocialNet",
    "HasSubmitButton",
    "HasHiddenFields",
    "HasPasswordField",
    "Bank",
    "Pay",
    "Crypto",
    "HasCopyrightInfo",
    "NoOfImage",
    "NoOfCSS",
    "NoOfJS",
    "NoOfSelfRef",
    "NoOfEmptyRef",
    "NoOfExternalRef",
]


def keyword_flag(url, keywords):
    """Return 1 if one of the supplied keywords occurs in the URL."""

    url_lower = url.lower()

    return int(
        any(keyword in url_lower for keyword in keywords)
    )


def calculate_title_match(domain, title):
    """
    Simple domain/title similarity.

    This is a heuristic approximation and is not identical
    to the original PhiUSIIL implementation.
    """

    if not domain or not title:
        return 0.0

    domain_words = set(
        re.findall(r"[a-zA-Z0-9]+", domain.lower())
    )

    title_words = set(
        re.findall(r"[a-zA-Z0-9]+", title.lower())
    )

    if not domain_words:
        return 0.0

    overlap = domain_words.intersection(title_words)

    return len(overlap) / len(domain_words)


def calculate_url_title_match(url, title):
    """
    Calculate similarity between URL text and webpage title.
    """

    if not url or not title:
        return 0.0

    url_words = set(
        re.findall(r"[a-zA-Z0-9]+", url.lower())
    )

    title_words = set(
        re.findall(r"[a-zA-Z0-9]+", title.lower())
    )

    if not url_words or not title_words:
        return 0.0

    overlap = url_words.intersection(title_words)

    return len(overlap) / len(url_words)


def get_tld_legitimate_probability(tld):
    """
    Get TLDLegitimateProb from the original PhiUSIIL dataset.
    """

    import pandas as pd

    project_root = Path(__file__).resolve().parent.parent

    dataset_path = (
        project_root
        / "data"
        / "raw"
        / "PhiUSIIL_Phishing_URL_Dataset.csv"
    )

    try:
        df = pd.read_csv(
            dataset_path,
            usecols=["TLD", "TLDLegitimateProb"]
        )

        tld = tld.lower().strip()

        matches = df[
            df["TLD"].astype(str).str.lower() == tld
        ]["TLDLegitimateProb"].dropna()

        if not matches.empty:
            return float(matches.iloc[0])

    except Exception as error:
        print(
            f"TLD probability lookup failed: {error}"
        )

    return 0.0


def build_features(url):
    """
    Build a feature dictionary from URL and website analysis.

    Returns:
        feature_values
        analysis_metadata
    """

    # -----------------------------
    # URL analysis
    # -----------------------------

    url_data = analyze_url(url)

    # -----------------------------
    # Website analysis
    # -----------------------------

    website_data = analyze_website(
        url_data["normalized_url"]
    )

    if not website_data["success"]:
        raise RuntimeError(
            website_data["error"]
        )

    # Website feature dictionary.
    web = website_data["features"]

    # -----------------------------
    # URL parsing
    # -----------------------------

    parsed = urlparse(
        url_data["normalized_url"]
    )

    domain = url_data["hostname"]

    title = web.get(
        "Title",
        ""
    )

    # -----------------------------
    # TLD
    # -----------------------------

    if parsed.hostname and "." in parsed.hostname:
        tld = parsed.hostname.split(".")[-1]
        tld_length = len(tld)
        tld_probability = get_tld_legitimate_probability(tld)
    else:
        tld_length = 0
        tld_probability = 0.0

    # -----------------------------
    # ML feature dictionary
    # -----------------------------

    features = {

        # -----------------------------
        # URL-level features
        # -----------------------------

        "URLLength":
            url_data["URLLength"],

        "DomainLength":
            url_data["DomainLength"],

        "IsDomainIP":
            url_data["IsDomainIP"],

        "URLSimilarityIndex":
            url_data["URLSimilarityIndex"],

        "CharContinuationRate":
            url_data["CharContinuationRate"],

        "TLDLegitimateProb":
            tld_probability,

        "URLCharProb":
            url_data["URLCharProb"],

        "TLDLength":
            tld_length,

        "NoOfSubDomain":
            url_data["NoOfSubDomain"],

        "HasObfuscation":
            url_data["HasObfuscation"],

        "NoOfObfuscatedChar":
            url_data["NoOfObfuscatedChar"],

        "ObfuscationRatio":
            url_data["ObfuscationRatio"],

        "NoOfLettersInURL":
            url_data["NoOfLettersInURL"],

        "LetterRatioInURL":
            url_data["LetterRatioInURL"],

        "NoOfDegitsInURL":
            url_data["NoOfDegitsInURL"],

        "DegitRatioInURL":
            url_data["DegitRatioInURL"],

        "NoOfEqualsInURL":
            url_data["NoOfEqualsInURL"],

        "NoOfQMarkInURL":
            url_data["NoOfQMarkInURL"],

        "NoOfAmpersandInURL":
            url_data["NoOfAmpersandInURL"],

        "NoOfOtherSpecialCharsInURL":
            url_data["NoOfOtherSpecialCharsInURL"],

        "SpacialCharRatioInURL":
            url_data["SpacialCharRatioInURL"],

        "IsHTTPS":
            url_data["IsHTTPS"],

        # -----------------------------
        # Website features
        # -----------------------------

        "LineOfCode":
            web["LineOfCode"],

        "LargestLineLength":
            web["LargestLineLength"],

        "HasTitle":
            web["HasTitle"],

        "DomainTitleMatchScore":
            calculate_title_match(
                domain,
                title
            ),

        "URLTitleMatchScore":
            calculate_url_title_match(
                url_data["normalized_url"],
                title
            ),

        "HasFavicon":
            web["HasFavicon"],

        "Robots":
            web["Robots"],

        "IsResponsive":
            web["IsResponsive"],

        # -----------------------------
        # Currently unavailable
        # -----------------------------

        "NoOfURLRedirect":
            0,

        "NoOfSelfRedirect":
            0,

        "HasDescription":
            web["HasDescription"],

        "NoOfPopup":
            0,

        # -----------------------------
        # HTML features
        # -----------------------------

        "NoOfiFrame":
            web["NoOfiFrame"],

        "HasExternalFormSubmit":
            web["HasExternalFormSubmit"],

        "HasSocialNet":
            web["HasSocialNet"],

        "HasSubmitButton":
            web["HasSubmitButton"],

        "HasHiddenFields":
            web["HasHiddenFields"],

        "HasPasswordField":
            web["HasPasswordField"],

        # -----------------------------
        # Suspicious URL keywords
        # -----------------------------

        "Bank":
            keyword_flag(
                url,
                [
                    "bank",
                    "banking"
                ]
            ),

        "Pay":
            keyword_flag(
                url,
                [
                    "pay",
                    "payment",
                    "billing"
                ]
            ),

        "Crypto":
            keyword_flag(
                url,
                [
                    "crypto",
                    "bitcoin",
                    "ethereum",
                    "wallet"
                ]
            ),

        # -----------------------------
        # Currently unavailable
        # -----------------------------

        "HasCopyrightInfo":
            0,

        # -----------------------------
        # Resource/reference features
        # -----------------------------

        "NoOfImage":
            web["NoOfImage"],

        "NoOfCSS":
            web["NoOfCSS"],

        "NoOfJS":
            web["NoOfJS"],

        "NoOfSelfRef":
            web["NoOfSelfRef"],

        "NoOfEmptyRef":
            web["NoOfEmptyRef"],

        "NoOfExternalRef":
            web["NoOfExternalRef"],
    }

    # -----------------------------
    # Verify all features
    # -----------------------------

    missing = [
        feature
        for feature in ML_FEATURES
        if feature not in features
    ]

    if missing:
        raise RuntimeError(
            f"Missing ML features: {missing}"
        )

    # -----------------------------
    # Preserve exact model order
    # -----------------------------

    ordered_features = {
        feature: features[feature]
        for feature in ML_FEATURES
    }

    # -----------------------------
    # Metadata
    # -----------------------------

    metadata = {
        "requested_url":
            url,

        "final_url":
            website_data["final_url"],

        "status_code":
            website_data["status_code"],

        "content_type":
            website_data["content_type"],

        "title":
            title,
    }

    return ordered_features, metadata


# ============================================================
# TEST MODE
# ============================================================

if __name__ == "__main__":

    url = input(
        "Enter URL to build features: "
    ).strip()

    if not url:
        print("No URL entered.")
        raise SystemExit(1)

    try:

        features, metadata = build_features(url)

    except Exception as error:

        print(
            f"\nFeature building failed: {error}"
        )

        raise SystemExit(1)

    print(
        "\n================================"
    )

    print(
        "HACKTVIS PhishGuard Feature Builder"
    )

    print(
        "================================"
    )

    print(
        f"Final URL: {metadata['final_url']}"
    )

    print(
        f"HTTP Status: {metadata['status_code']}"
    )

    print(
        f"Title: {metadata['title']}"
    )

    print(
        "\nML Features:"
    )

    for name, value in features.items():

        print(
            f"{name}: {value}"
        )

    print(
        f"\nTotal ML features: {len(features)}"
    )