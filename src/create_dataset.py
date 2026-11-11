import pandas as pd
from pathlib import Path

# ==============================
# Configuration
# ==============================

INPUT_FILE = Path(
    "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"
)

OUTPUT_FILE = Path(
    "data/processed/phiusiil_24k.csv"
)

SAMPLES_PER_CLASS = 12000
RANDOM_STATE = 42


# ==============================
# Load dataset
# ==============================

print("Loading original dataset...")

df = pd.read_csv(INPUT_FILE, low_memory=False)

print(f"Original shape: {df.shape}")


# ==============================
# Remove duplicate URLs
# ==============================

print("\nRemoving duplicate URLs...")

before = len(df)

df = df.drop_duplicates(
    subset=["URL"],
    keep="first"
)

after = len(df)

print(f"Removed duplicates: {before - after}")
print(f"Shape after duplicates: {df.shape}")


# ==============================
# Check labels
# ==============================

print("\nOriginal label distribution:")
print(df["label"].value_counts())


# ==============================
# Separate classes
# ==============================

class_0 = df[df["label"] == 0]
class_1 = df[df["label"] == 1]

print("\nClass 0:", len(class_0))
print("Class 1:", len(class_1))


# ==============================
# Balanced sampling
# ==============================

if len(class_0) < SAMPLES_PER_CLASS:
    raise ValueError("Not enough class 0 samples.")

if len(class_1) < SAMPLES_PER_CLASS:
    raise ValueError("Not enough class 1 samples.")


sample_0 = class_0.sample(
    n=SAMPLES_PER_CLASS,
    random_state=RANDOM_STATE
)

sample_1 = class_1.sample(
    n=SAMPLES_PER_CLASS,
    random_state=RANDOM_STATE
)


# ==============================
# Combine samples
# ==============================

balanced_df = pd.concat(
    [sample_0, sample_1],
    axis=0
)


# ==============================
# Shuffle dataset
# ==============================

balanced_df = balanced_df.sample(
    frac=1,
    random_state=RANDOM_STATE
).reset_index(drop=True)


# ==============================
# Save dataset
# ==============================

OUTPUT_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)

balanced_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ==============================
# Final information
# ==============================

print("\n================================")
print("DATASET CREATION COMPLETE")
print("================================")

print(f"Final shape: {balanced_df.shape}")

print("\nFinal label distribution:")
print(balanced_df["label"].value_counts())

print(f"\nSaved to:")
print(OUTPUT_FILE)