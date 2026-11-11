import pandas as pd
import joblib

from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)


# ==========================================
# Configuration
# ==========================================

TRAIN_FILE = Path(
    "data/processed/train.csv"
)

VALIDATION_FILE = Path(
    "data/processed/validation.csv"
)

TEST_FILE = Path(
    "data/processed/test.csv"
)

MODEL_FILE = Path(
    "models/phishing_model.pkl"
)


# ==========================================
# Columns not used by ML
# ==========================================

DROP_COLUMNS = [
    "FILENAME",
    "URL",
    "Domain",
    "TLD",
    "Title"
]


# ==========================================
# Load datasets
# ==========================================

print("Loading datasets...")

train_df = pd.read_csv(TRAIN_FILE)
val_df = pd.read_csv(VALIDATION_FILE)
test_df = pd.read_csv(TEST_FILE)

print("Training shape:", train_df.shape)
print("Validation shape:", val_df.shape)
print("Testing shape:", test_df.shape)


# ==========================================
# Separate features and labels
# ==========================================

X_train = train_df.drop(
    columns=DROP_COLUMNS + ["label"]
)

y_train = train_df["label"]


X_val = val_df.drop(
    columns=DROP_COLUMNS + ["label"]
)

y_val = val_df["label"]


X_test = test_df.drop(
    columns=DROP_COLUMNS + ["label"]
)

y_test = test_df["label"]


# ==========================================
# Verify feature count
# ==========================================

print("\nNumber of ML features:", X_train.shape[1])

print("\nFeatures:")
print(X_train.columns.tolist())


# ==========================================
# Create Random Forest
# ==========================================

print("\nCreating Random Forest model...")

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced",
    max_features="sqrt"
)


# ==========================================
# Train
# ==========================================

print("\nTraining model...")

model.fit(
    X_train,
    y_train
)

print("Training complete.")


# ==========================================
# Validation
# ==========================================

print("\n======================================")
print("VALIDATION RESULTS")
print("======================================")

val_predictions = model.predict(X_val)

val_probabilities = model.predict_proba(X_val)[:, 1]

val_accuracy = accuracy_score(
    y_val,
    val_predictions
)

val_precision = precision_score(
    y_val,
    val_predictions
)

val_recall = recall_score(
    y_val,
    val_predictions
)

val_f1 = f1_score(
    y_val,
    val_predictions
)

val_auc = roc_auc_score(
    y_val,
    val_probabilities
)

print(f"Accuracy:  {val_accuracy:.4f}")
print(f"Precision: {val_precision:.4f}")
print(f"Recall:    {val_recall:.4f}")
print(f"F1 Score:  {val_f1:.4f}")
print(f"ROC-AUC:   {val_auc:.4f}")


# ==========================================
# Final test evaluation
# ==========================================

print("\n======================================")
print("TEST RESULTS")
print("======================================")

test_predictions = model.predict(X_test)

test_probabilities = model.predict_proba(X_test)[:, 1]

test_accuracy = accuracy_score(
    y_test,
    test_predictions
)

test_precision = precision_score(
    y_test,
    test_predictions
)

test_recall = recall_score(
    y_test,
    test_predictions
)

test_f1 = f1_score(
    y_test,
    test_predictions
)

test_auc = roc_auc_score(
    y_test,
    test_probabilities
)

print(f"Accuracy:  {test_accuracy:.4f}")
print(f"Precision: {test_precision:.4f}")
print(f"Recall:    {test_recall:.4f}")
print(f"F1 Score:  {test_f1:.4f}")
print(f"ROC-AUC:   {test_auc:.4f}")


# ==========================================
# Classification report
# ==========================================

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        test_predictions,
        target_names=[
            "Phishing",
            "Legitimate"
        ]
    )
)


# ==========================================
# Confusion Matrix
# ==========================================

print("\nConfusion Matrix:")

cm = confusion_matrix(
    y_test,
    test_predictions
)

print(cm)


# ==========================================
# Feature importance
# ==========================================

feature_importance = pd.DataFrame({
    "feature": X_train.columns,
    "importance": model.feature_importances_
})

feature_importance = feature_importance.sort_values(
    by="importance",
    ascending=False
)

print("\nTop 20 Important Features:")

print(
    feature_importance.head(20).to_string(
        index=False
    )
)


# ==========================================
# Save model
# ==========================================

MODEL_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)

joblib.dump(
    model,
    MODEL_FILE
)

print("\n======================================")
print("MODEL SAVED")
print("======================================")

print(f"Model: {MODEL_FILE}")