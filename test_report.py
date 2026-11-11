from src.report import generate_report

test_data = {
    "url": "https://example.com",
    "verdict": "LEGITIMATE",
    "phishing_probability": 0.10,
    "legitimate_probability": 0.90,
    "metadata": {
        "final_url": "https://example.com",
        "status_code": 200,
        "title": "Example Domain"
    },
    "reputation": {
        "status": "LOW_RISK",
        "risk_score": 0
    },
    "risk": {
        "score": 5,
        "level": "LOW",
        "reasons": ["No basic risk indicators detected."]
    }
}

path = generate_report(test_data)

print("PDF generated successfully!")
print("Report location:", path)
