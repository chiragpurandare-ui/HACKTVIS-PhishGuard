from urllib.parse import urlparse
import re
import math


def calculate_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0

    length = len(text)
    probabilities = [
        text.count(char) / length
        for char in set(text)
    ]

    return -sum(
        p * math.log2(p)
        for p in probabilities
        if p > 0
    )

def calculate_char_continuation_rate(text):
    """
    Estimate how often consecutive characters belong
    to the same character category.
    """

    if len(text) < 2:
        return 0.0

    same_category = 0

    for first, second in zip(text, text[1:]):

        if first.isalpha() and second.isalpha():
            same_category += 1

        elif first.isdigit() and second.isdigit():
            same_category += 1

        elif not first.isalnum() and not second.isalnum():
            same_category += 1

    return same_category / (len(text) - 1)


def calculate_url_char_probability(text):
    """
    Estimate character regularity using character frequency.

    Higher values indicate a more repetitive/regular URL.
    """

    if not text:
        return 0.0

    counts = {}

    for char in text.lower():
        counts[char] = counts.get(char, 0) + 1

    total = len(text)

    probability = sum(
        (count / total) ** 2
        for count in counts.values()
    )

    return probability


def calculate_url_similarity_index(url, domain):
    """
    Estimate similarity between URL and domain.

    Returns a value between 0 and 100.
    """

    if not url or not domain:
        return 0.0

    url_clean = re.sub(
        r"[^a-zA-Z0-9]",
        "",
        url.lower()
    )

    domain_clean = re.sub(
        r"[^a-zA-Z0-9]",
        "",
        domain.lower()
    )

    if not url_clean or not domain_clean:
        return 0.0

    common = 0

    for char in set(domain_clean):

        common += min(
            url_clean.count(char),
            domain_clean.count(char)
        )

    return min(
        100.0,
        (common / len(domain_clean)) * 100
    )

def analyze_url(url):
    """
    Analyze URL-level characteristics.

    This analyzer does NOT open or request the website.
    """

    original_url = url.strip()

    # Add scheme if missing
    normalized_url = original_url

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", normalized_url):
        normalized_url = "https://" + normalized_url

    parsed = urlparse(normalized_url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    full_url = normalized_url

    char_continuation_rate = (
        calculate_char_continuation_rate(
            full_url
        )
    )

    url_char_probability = (
        calculate_url_char_probability(
            full_url
        )
    )

    url_similarity_index = (
        calculate_url_similarity_index(
            full_url,
            hostname
        )
    )

    # URL characters
    url_length = len(full_url)

    letters = sum(c.isalpha() for c in full_url)
    digits = sum(c.isdigit() for c in full_url)

    special_chars = sum(
        not c.isalnum()
        for c in full_url
    )

    # Domain
    domain_length = len(hostname)

    is_domain_ip = bool(
        re.fullmatch(
            r"\d{1,3}(\.\d{1,3}){3}",
            hostname
        )
    )

    # Subdomains
    domain_parts = hostname.split(".") if hostname else []

    no_of_subdomain = max(
        len(domain_parts) - 2,
        0
    )

    # TLD
    tld = ""

    if len(domain_parts) >= 2:
        tld = domain_parts[-1]

    # URL special characters
    no_of_equals = full_url.count("=")
    no_of_qmark = full_url.count("?")
    no_of_ampersand = full_url.count("&")

    no_of_other_special = sum(
        full_url.count(char)
        for char in [
            "@",
            "%",
            "#",
            ";",
            ":",
            "$",
            ","
        ]
    )

    # Obfuscation indicators
    no_of_obfuscated = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            full_url
        )
    )

    has_obfuscation = int(
        no_of_obfuscated > 0
    )

    # HTTPS
    is_https = int(
        parsed.scheme.lower() == "https"
    )

    # Ratios
    letter_ratio = (
        letters / url_length
        if url_length else 0
    )

    digit_ratio = (
        digits / url_length
        if url_length else 0
    )

    special_ratio = (
        special_chars / url_length
        if url_length else 0
    )

    obfuscation_ratio = (
        no_of_obfuscated / url_length
        if url_length else 0
    )

    # Entropy
    entropy = calculate_entropy(full_url)

    # Suspicious keywords
    suspicious_keywords = [
        "login",
        "signin",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "bank",
        "payment",
        "wallet",
        "confirm",
        "authentication",
        "free",
        "bonus"
    ]

    url_lower = full_url.lower()

    found_keywords = [
        keyword
        for keyword in suspicious_keywords
        if keyword in url_lower
    ]

    return {
        "url": original_url,
        "normalized_url": normalized_url,

        "scheme": parsed.scheme,
        "hostname": hostname,
        "path": path,
        "query": query,
        "fragment": fragment,

        "URLLength": url_length,
         "DomainLength": domain_length,
        "IsDomainIP": int(is_domain_ip),

        "URLSimilarityIndex": url_similarity_index,
          "CharContinuationRate": char_continuation_rate,
          "URLCharProb": url_char_probability,

        "NoOfSubDomain": no_of_subdomain,

        "NoOfObfuscatedChar": no_of_obfuscated,
        "HasObfuscation": has_obfuscation,
        "ObfuscationRatio": obfuscation_ratio,

        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letter_ratio,

        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digit_ratio,

        "NoOfEqualsInURL": no_of_equals,
        "NoOfQMarkInURL": no_of_qmark,
        "NoOfAmpersandInURL": no_of_ampersand,
        "NoOfOtherSpecialCharsInURL": no_of_other_special,

        "SpacialCharRatioInURL": special_ratio,

        "IsHTTPS": is_https,

        "URL_Entropy": entropy,

        "SuspiciousKeywords": found_keywords,
        "SuspiciousKeywordCount": len(found_keywords)
    }


if __name__ == "__main__":

    test_url = input(
        "Enter URL to analyze: "
    ).strip()

    if not test_url:
        print("No URL entered.")
        raise SystemExit(1)

    result = analyze_url(test_url)

    print("\n================================")
    print("HACKTVIS PhishGuard URL Analyzer")
    print("================================")

    for key, value in result.items():
        print(f"{key}: {value}")
