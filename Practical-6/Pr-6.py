# ============================================================
# PRACTICAL 6
# DATASET BALANCING FOR ML / DEEP LEARNING
# ============================================================

import os
import pandas as pd
import matplotlib.pyplot as plt


# ============================================================
# 1. PATH CONFIGURATION
# ============================================================

INPUT_FILE = (
    r"D:\PDS PRACTICAL\Practical-5\output"
    r"\feature_engineered_logs.csv"
)

OUTPUT_FOLDER = (
    r"D:\PDS PRACTICAL\Practical-6\output"
)

os.makedirs(
    OUTPUT_FOLDER,
    exist_ok=True
)


# ============================================================
# 2. LOAD FEATURE-ENGINEERED DATASET
# ============================================================

print("=" * 70)
print("PRACTICAL 6: DATASET BALANCING")
print("=" * 70)

print("\n[1] Loading feature-engineered dataset...")

df = pd.read_csv(
    INPUT_FILE,
    low_memory=False
)

print("Dataset loaded successfully.")
print("Total records:", len(df))


# ============================================================
# 3. CHECK LABEL COLUMN
# ============================================================

if "label" not in df.columns:

    raise ValueError(
        "ERROR: label column not found."
    )


print("\nOriginal class distribution:")

print(
    df["label"].value_counts()
)


# ============================================================
# 4. CREATE BINARY ATTACK CATEGORY
# ============================================================

print("\n" + "=" * 70)
print("CREATING BENIGN / ATTACK GROUPS")
print("=" * 70)

df["attack_group"] = (
    df["label"]
    .astype(str)
    .str.lower()
    .apply(
        lambda x:
        "benign"
        if x == "benign"
        else "attack"
    )
)


print("\nBinary distribution before balancing:")

print(
    df["attack_group"].value_counts()
)


# ============================================================
# 5. SEPARATE BENIGN AND ATTACK DATA
# ============================================================

benign_data = df[
    df["attack_group"] == "benign"
].copy()


attack_data = df[
    df["attack_group"] == "attack"
].copy()


print("\nBenign records:")
print(len(benign_data))


print("\nAttack records:")
print(len(attack_data))


# ============================================================
# 6. CHECK ATTACK CATEGORIES
# ============================================================

print("\n" + "=" * 70)
print("ATTACK CATEGORY DISTRIBUTION")
print("=" * 70)

attack_categories = (
    attack_data["label"]
    .value_counts()
)

print(
    attack_categories
)


# ============================================================
# 7. BALANCE USING UNDERSAMPLING
# ============================================================

print("\n" + "=" * 70)
print("BALANCING DATASET")
print("=" * 70)

# Use all attack records.
# Number of benign records is reduced to the total
# number of attack records.

target_size = len(attack_data)

print(
    "\nTarget size per class:",
    target_size
)


if len(benign_data) >= target_size:

    benign_sample = benign_data.sample(
        n=target_size,
        random_state=42
    )

else:

    print(
        "Benign class is smaller than attack class."
    )

    benign_sample = benign_data.sample(
        n=target_size,
        replace=True,
        random_state=42
    )


# ============================================================
# 8. COMBINE BALANCED DATA
# ============================================================

balanced_df = pd.concat(
    [
        benign_sample,
        attack_data
    ],
    ignore_index=True
)


# ============================================================
# 9. SHUFFLE DATA
# ============================================================

balanced_df = (
    balanced_df
    .sample(
        frac=1,
        random_state=42
    )
    .reset_index(drop=True)
)


# ============================================================
# 10. FINAL CLASS DISTRIBUTION
# ============================================================

print("\n" + "=" * 70)
print("FINAL BALANCED DISTRIBUTION")
print("=" * 70)

final_distribution = (
    balanced_df["attack_group"]
    .value_counts()
)

print(
    final_distribution
)


# ============================================================
# 11. ATTACK CATEGORY CHECK
# ============================================================

print("\nAttack categories preserved:")

print(
    balanced_df[
        balanced_df["attack_group"] == "attack"
    ]["label"].value_counts()
)


# ============================================================
# 12. SAVE BALANCED DATASET
# ============================================================

OUTPUT_FILE = os.path.join(
    OUTPUT_FOLDER,
    "balanced_dataset.csv"
)


balanced_df.to_csv(
    OUTPUT_FILE,
    index=False
)


print("\nBalanced dataset saved:")
print(
    OUTPUT_FILE
)


# ============================================================
# 13. SAVE DISTRIBUTION
# ============================================================

distribution_table = (
    balanced_df["attack_group"]
    .value_counts()
    .reset_index()
)


distribution_table.columns = [
    "Class",
    "Count"
]


distribution_table["Percentage"] = (
    distribution_table["Count"]
    / len(balanced_df)
    * 100
)


distribution_table.to_csv(
    os.path.join(
        OUTPUT_FOLDER,
        "balanced_class_distribution.csv"
    ),
    index=False
)


# ============================================================
# 14. PLOT CLASS DISTRIBUTION
# ============================================================

plt.figure(
    figsize=(8, 5)
)


plt.bar(
    distribution_table["Class"],
    distribution_table["Count"]
)


plt.title(
    "Balanced Dataset Class Distribution"
)


plt.xlabel(
    "Class"
)


plt.ylabel(
    "Number of Records"
)


plt.tight_layout()


plt.savefig(
    os.path.join(
        OUTPUT_FOLDER,
        "balanced_class_distribution.png"
    ),
    dpi=300
)


plt.close()


# ============================================================
# 15. SAVE REPORT
# ============================================================

report_file = os.path.join(
    OUTPUT_FOLDER,
    "practical_6_report.txt"
)


with open(
    report_file,
    "w",
    encoding="utf-8"
) as file:

    file.write(
        "PRACTICAL 6 - DATASET BALANCING\n"
    )

    file.write(
        "=" * 60 + "\n\n"
    )

    file.write(
        "Objective:\n"
    )

    file.write(
        "To handle an imbalanced dataset for fair "
        "ML and Deep Learning training.\n\n"
    )

    file.write(
        "Original Distribution:\n"
    )

    for label, count in df["label"].value_counts().items():

        file.write(
            f"{label}: {count}\n"
        )


    file.write(
        "\nBalancing Technique:\n"
    )

    file.write(
        "Random undersampling of the benign class "
        "while retaining all attack records.\n\n"
    )


    file.write(
        "Final Binary Distribution:\n"
    )

    for label, count in final_distribution.items():

        percentage = (
            count
            / len(balanced_df)
            * 100
        )

        file.write(
            f"{label}: "
            f"{count} "
            f"({percentage:.2f}%)\n"
        )


    file.write(
        "\nAttack Categories Preserved:\n"
    )

    for label, count in (
        balanced_df[
            balanced_df["attack_group"] == "attack"
        ]["label"].value_counts().items()
    ):

        file.write(
            f"{label}: {count}\n"
        )


    file.write(
        "\nConclusion:\n"
    )

    file.write(
        "The dataset was balanced by retaining all attack "
        "records and randomly undersampling benign records "
        "to the same total count. The resulting dataset "
        "contains the feature-engineered columns required "
        "for machine-learning training.\n"
    )


# ============================================================
# 16. FINAL MESSAGE
# ============================================================

print("\n" + "=" * 70)
print("PRACTICAL 6 COMPLETED SUCCESSFULLY")
print("=" * 70)

print(
    "\nFinal dataset size:",
    len(balanced_df)
)

print(
    "\nOutput files:"
)

print(
    "1. balanced_dataset.csv"
)

print(
    "2. balanced_class_distribution.csv"
)

print(
    "3. balanced_class_distribution.png"
)

print(
    "4. practical_6_report.txt"
)

print(
    "\nOutput folder:"
)

print(
    OUTPUT_FOLDER
)