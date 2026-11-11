import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split


# ==========================================
# Configuration
# ==========================================

INPUT_FILE = Path(
    "data/processed/phiusiil_24k.csv"
)

OUTPUT_DIR = Path(
    "data/processed"
)

RANDOM_STATE = 42


# ==========================================
# Load dataset
# ==========================================

print("Loading dataset...")

df = pd.read_csv(INPUT_FILE)

print(f"Dataset shape: {df.shape}")


# ==========================================
# Separate features and target
# ==========================================

X = df.drop(columns=["label"])
y = df["label"]


# ==========================================
# First split
# 70% training
# 30% temporary
# ==========================================

X_train, X_temp, y_train, y_temp = train_test_split(
    X,
    y,
    test_size=0.30,
    random_state=RANDOM_STATE,
    stratify=y
)


# ==========================================
# Second split
# 15% validation
# 15% testing
# ==========================================

X_val, X_test, y_val, y_test = train_test_split(
    X_temp,
    y_temp,
    test_size=0.50,
    random_state=RANDOM_STATE,
    stratify=y_temp
)


# ==========================================
# Recombine features + labels
# ==========================================

train_df = X_train.copy()
train_df["label"] = y_train

val_df = X_val.copy()
val_df["label"] = y_val

test_df = X_test.copy()
test_df["label"] = y_test


# ==========================================
# Reset indexes
# ==========================================

train_df = train_df.reset_index(drop=True)
val_df = val_df.reset_index(drop=True)
test_df = test_df.reset_index(drop=True)


# ==========================================
# Save
# ==========================================

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

train_df.to_csv(
    OUTPUT_DIR / "train.csv",
    index=False
)

val_df.to_csv(
    OUTPUT_DIR / "validation.csv",
    index=False
)

test_df.to_csv(
    OUTPUT_DIR / "test.csv",
    index=False
)


# ==========================================
# Display results
# ==========================================

print("\n======================================")
print("DATASET SPLIT COMPLETE")
print("======================================")

print(f"\nTraining:   {train_df.shape}")
print(f"Validation: {val_df.shape}")
print(f"Testing:    {test_df.shape}")

print("\nTraining labels:")
print(train_df["label"].value_counts())

print("\nValidation labels:")
print(val_df["label"].value_counts())

print("\nTesting labels:")
print(test_df["label"].value_counts())

print("\nFiles created:")
print("data/processed/train.csv")
print("data/processed/validation.csv")
print("data/processed/test.csv")