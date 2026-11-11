from src.database import (
    save_scan,
    get_all_scans,
    get_scan_statistics
)

test_result = {
    "verdict": "LEGITIMATE",
    "phishing_probability": 0.10,
    "legitimate_probability": 0.90,

    "risk": {
        "score": 5,
        "level": "LOW"
    },

    "reputation": {
        "status": "LOW_RISK"
    }
}

scan_id = save_scan(
    "https://example.com",
    test_result,
    "test_report.pdf"
)

print("Saved scan ID:", scan_id)

print("\nScan History:")
print(get_all_scans())

print("\nStatistics:")
print(get_scan_statistics())
