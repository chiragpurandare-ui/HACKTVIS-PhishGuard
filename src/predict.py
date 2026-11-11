import pandas as pd
import joblib
from pathlib import Path


MODEL_FILE = Path("models/phishing_model.pkl")


DROP_COLUMNS = [
    "FILENAME",
    "URL",
    "Domain",
    "TLD",
    "Title"
]


def load_model():
    """Load the trained phishing detection model."""
    return joblib.load(MODEL_FILE)


def predict_from_dataframe(df):
    """
    Predict phishing/legitimate status from
    a dataframe containing PhiUSIIL features.
    """

    model = load_model()

    X = df.drop(columns=DROP_COLUMNS + ["label"], errors="ignore")

    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    class_probabilities = dict(
        zip(model.classes_, probabilities)
    )

    phishing_probability = class_probabilities.get(0, 0.0)
    legitimate_probability = class_probabilities.get(1, 0.0)

    if prediction == 0:
        verdict = "PHISHING"
    else:
        verdict = "LEGITIMATE"

    return {
        "prediction": int(prediction),
        "verdict": verdict,
        "phishing_probability": float(phishing_probability),
        "legitimate_probability": float(legitimate_probability)
    }


if __name__ == "__main__":

    test_file = Path("data/processed/test.csv")

    test_df = pd.read_csv(test_file)

    sample = test_df.iloc[[0]]

    result = predict_from_dataframe(sample)

    print("\n==============================")
    print("HACKTVIS PhishGuard")
    print("==============================")

    print(f"Prediction: {result['verdict']}")
    print(
        f"Phishing Probability: "
        f"{result['phishing_probability'] * 100:.2f}%"
    )
    print(
        f"Legitimate Probability: "
        f"{result['legitimate_probability'] * 100:.2f}%"
    )