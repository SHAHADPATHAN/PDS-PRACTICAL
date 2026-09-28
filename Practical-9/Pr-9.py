# ============================================================
# PRACTICAL 9
# SIMPLE CLASSIFIER TO DETECT ATTACKS
# ============================================================

import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report
)


# ============================================================
# 1. PATH CONFIGURATION
# ============================================================

# IMPORTANT:
# Practical 9 now uses the BALANCED dataset created
# in Practical 6.

INPUT_FILE = (
    r"D:\PDS PRACTICAL\Practical-6\output"
    r"\balanced_dataset.csv"
)

OUTPUT_FOLDER = (
    r"D:\PDS PRACTICAL\Practical-9\output"
)

os.makedirs(
    OUTPUT_FOLDER,
    exist_ok=True
)


# ============================================================
# 2. LOAD BALANCED DATASET
# ============================================================

print("=" * 70)
print("PRACTICAL 9: SIMPLE ATTACK CLASSIFIER")
print("=" * 70)

print("\n[1] Loading balanced dataset...")

df = pd.read_csv(
    INPUT_FILE,
    low_memory=False
)

print(
    "Dataset loaded successfully."
)

print(
    "Total records:",
    len(df)
)


# ============================================================
# 3. CHECK LABEL COLUMN
# ============================================================

if "label" not in df.columns:

    raise ValueError(
        "ERROR: 'label' column not found in the balanced dataset."
    )

print("\nOriginal labels:")

print(
    df["label"].value_counts()
)


# ============================================================
# 4. CREATE BINARY ATTACK TARGET
# ============================================================

print("\n" + "=" * 70)
print("CREATING BINARY ATTACK LABEL")
print("=" * 70)

# Benign = 0
# All attack categories = 1

df["attack"] = (
    df["label"]
    .astype(str)
    .str.lower()
    .ne("benign")
    .astype(int)
)

print("\nBinary target distribution:")

print(
    df["attack"].value_counts()
)

print("\nMeaning:")

print("0 = Benign")
print("1 = Attack")


# ============================================================
# 5. CHECK CLASS BALANCE
# ============================================================

print("\n" + "=" * 70)
print("CHECKING CLASS BALANCE")
print("=" * 70)

class_counts = df["attack"].value_counts()

class_percentages = (
    df["attack"]
    .value_counts(normalize=True)
    * 100
)

for class_value in sorted(class_counts.index):

    class_name = (
        "Benign"
        if class_value == 0
        else "Attack"
    )

    print(
        f"{class_name}: "
        f"{class_counts[class_value]} "
        f"({class_percentages[class_value]:.2f}%)"
    )


# ============================================================
# 6. SELECT FEATURES FROM PRACTICAL 5
# ============================================================

print("\n" + "=" * 70)
print("SELECTING FEATURES FROM PRACTICAL 5")
print("=" * 70)

# Numerical features created in Practical 5

numeric_features = [
    "requests_per_ip",
    "time_between_requests",
    "user_agent_length",
    "unique_user_agents_per_ip"
]


# Categorical / binary features

categorical_features = [
    "client_type",
    "is_bot"
]


# Find available numerical features

available_numeric = [
    column
    for column in numeric_features
    if column in df.columns
]


# Find available categorical features

available_categorical = [
    column
    for column in categorical_features
    if column in df.columns
]


print("\nNumeric features found:")

for column in available_numeric:

    print(
        " -",
        column
    )


print("\nCategorical features found:")

for column in available_categorical:

    print(
        " -",
        column
    )


if len(available_numeric) == 0:

    raise ValueError(
        "ERROR: No Practical 5 numerical features were found."
    )


# ============================================================
# 7. HANDLE MISSING VALUES
# ============================================================

print("\n" + "=" * 70)
print("HANDLING MISSING VALUES")
print("=" * 70)


# Numerical columns

for column in available_numeric:

    df[column] = pd.to_numeric(
        df[column],
        errors="coerce"
    )

    df[column] = (
        df[column]
        .fillna(0)
    )


# Categorical columns

for column in available_categorical:

    df[column] = (
        df[column]
        .fillna("unknown")
        .astype(str)
    )


print(
    "Missing values handled successfully."
)


# ============================================================
# 8. ENCODE CATEGORICAL FEATURES
# ============================================================

print("\n" + "=" * 70)
print("ENCODING CATEGORICAL FEATURES")
print("=" * 70)


if len(available_categorical) > 0:

    X_categorical = pd.get_dummies(
        df[available_categorical],
        columns=available_categorical,
        dtype=int
    )

else:

    X_categorical = pd.DataFrame(
        index=df.index
    )


print(
    "Categorical encoding completed."
)

print(
    "Encoded categorical columns:",
    len(X_categorical.columns)
)


# ============================================================
# 9. CREATE FINAL FEATURE MATRIX
# ============================================================

print("\n" + "=" * 70)
print("CREATING FINAL FEATURE MATRIX")
print("=" * 70)


X_numeric = df[
    available_numeric
].copy()


X = pd.concat(
    [
        X_numeric,
        X_categorical
    ],
    axis=1
)


y = df[
    "attack"
]


print(
    "Final feature matrix shape:",
    X.shape
)

print(
    "Target shape:",
    y.shape
)


# ============================================================
# 10. REMOVE INFINITE VALUES
# ============================================================

print("\n[2] Checking infinite values...")

X = X.replace(
    [float("inf"), float("-inf")],
    0
)

X = X.fillna(0)

print(
    "Infinite and missing feature values handled."
)


# ============================================================
# 11. TRAIN / TEST SPLIT
# ============================================================

print("\n" + "=" * 70)
print("TRAIN / TEST SPLIT")
print("=" * 70)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print(
    "Training records:",
    len(X_train)
)

print(
    "Testing records:",
    len(X_test)
)


print(
    "\nTraining class distribution:"
)

print(
    y_train.value_counts()
)


print(
    "\nTesting class distribution:"
)

print(
    y_test.value_counts()
)


# ============================================================
# 12. TRAIN RANDOM FOREST CLASSIFIER
# ============================================================

print("\n" + "=" * 70)
print("TRAINING RANDOM FOREST CLASSIFIER")
print("=" * 70)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)


print(
    "Training model..."
)


model.fit(
    X_train,
    y_train
)


print(
    "Model training completed successfully."
)


# ============================================================
# 13. MAKE PREDICTIONS
# ============================================================

print("\n" + "=" * 70)
print("MAKING PREDICTIONS")
print("=" * 70)


y_pred = model.predict(
    X_test
)


print(
    "Predictions completed."
)


# ============================================================
# 14. CALCULATE ACCURACY
# ============================================================

print("\n" + "=" * 70)
print("MODEL ACCURACY")
print("=" * 70)


accuracy = accuracy_score(
    y_test,
    y_pred
)


print(
    f"Accuracy: {accuracy * 100:.2f}%"
)


# ============================================================
# 15. CONFUSION MATRIX
# ============================================================

print("\n" + "=" * 70)
print("CONFUSION MATRIX")
print("=" * 70)


cm = confusion_matrix(
    y_test,
    y_pred
)


print(
    cm
)


# Save confusion matrix as CSV

cm_df = pd.DataFrame(
    cm,
    index=[
        "Actual Benign",
        "Actual Attack"
    ],
    columns=[
        "Predicted Benign",
        "Predicted Attack"
    ]
)


cm_df.to_csv(
    os.path.join(
        OUTPUT_FOLDER,
        "confusion_matrix.csv"
    )
)


# ============================================================
# 16. CONFUSION MATRIX HEATMAP
# ============================================================

plt.figure(
    figsize=(7, 5)
)


sns.heatmap(
    cm,
    annot=True,
    fmt="d",
    cmap="Blues",
    xticklabels=[
        "Benign",
        "Attack"
    ],
    yticklabels=[
        "Benign",
        "Attack"
    ]
)


plt.title(
    "Confusion Matrix - Random Forest"
)


plt.xlabel(
    "Predicted Label"
)


plt.ylabel(
    "Actual Label"
)


plt.tight_layout()


plt.savefig(
    os.path.join(
        OUTPUT_FOLDER,
        "confusion_matrix.png"
    ),
    dpi=300
)


plt.close()


print(
    "Confusion matrix graph saved."
)


# ============================================================
# 17. CLASSIFICATION REPORT
# ============================================================

print("\n" + "=" * 70)
print("CLASSIFICATION REPORT")
print("=" * 70)


report = classification_report(
    y_test,
    y_pred,
    target_names=[
        "Benign",
        "Attack"
    ],
    zero_division=0
)


print(
    report
)


# Save classification report

with open(
    os.path.join(
        OUTPUT_FOLDER,
        "classification_report.txt"
    ),
    "w",
    encoding="utf-8"
) as file:

    file.write(
        report
    )


# ============================================================
# 18. FEATURE IMPORTANCE
# ============================================================

print("\n" + "=" * 70)
print("FEATURE IMPORTANCE")
print("=" * 70)


feature_importance = pd.DataFrame({

    "Feature": X.columns,

    "Importance":
        model.feature_importances_

})


feature_importance = (
    feature_importance
    .sort_values(
        "Importance",
        ascending=False
    )
)


print(
    feature_importance.head(10)
)


# Save feature importance

feature_importance.to_csv(
    os.path.join(
        OUTPUT_FOLDER,
        "feature_importance.csv"
    ),
    index=False
)


# ============================================================
# 19. FEATURE IMPORTANCE GRAPH
# ============================================================

top_features = (
    feature_importance
    .head(10)
    .sort_values(
        "Importance"
    )
)


plt.figure(
    figsize=(10, 6)
)


plt.barh(
    top_features["Feature"],
    top_features["Importance"]
)


plt.title(
    "Top 10 Feature Importance - Random Forest"
)


plt.xlabel(
    "Importance"
)


plt.ylabel(
    "Feature"
)


plt.tight_layout()


plt.savefig(
    os.path.join(
        OUTPUT_FOLDER,
        "feature_importance.png"
    ),
    dpi=300
)


plt.close()


print(
    "Feature importance graph saved."
)


# ============================================================
# 20. SAVE MODEL RESULTS
# ============================================================

results = pd.DataFrame({

    "Metric": [
        "Accuracy",
        "Training Records",
        "Testing Records",
        "Number of Features"
    ],

    "Value": [
        accuracy,
        len(X_train),
        len(X_test),
        X.shape[1]
    ]

})


results.to_csv(
    os.path.join(
        OUTPUT_FOLDER,
        "model_results.csv"
    ),
    index=False
)


# ============================================================
# 21. SAVE TEST PREDICTIONS
# ============================================================

prediction_results = pd.DataFrame({

    "Actual": y_test.values,

    "Predicted": y_pred

})


prediction_results.to_csv(
    os.path.join(
        OUTPUT_FOLDER,
        "test_predictions.csv"
    ),
    index=False
)


# ============================================================
# 22. CREATE PRACTICAL REPORT
# ============================================================

report_file = os.path.join(
    OUTPUT_FOLDER,
    "practical_9_report.txt"
)


with open(
    report_file,
    "w",
    encoding="utf-8"
) as file:

    file.write(
        "PRACTICAL 9 - SIMPLE CLASSIFIER TO DETECT ATTACKS\n"
    )

    file.write(
        "=" * 70 + "\n\n"
    )


    file.write(
        "Objective:\n"
    )

    file.write(
        "To build a simple machine-learning classifier "
        "to detect attacks using features generated "
        "in Practical 5 and the balanced dataset "
        "prepared in Practical 6.\n\n"
    )


    file.write(
        "Input Dataset:\n"
    )

    file.write(
        "balanced_dataset.csv from Practical 6\n\n"
    )


    file.write(
        "Algorithm:\n"
    )

    file.write(
        "Random Forest Classifier\n\n"
    )


    file.write(
        "Target Classes:\n"
    )

    file.write(
        "0 = Benign\n"
    )

    file.write(
        "1 = Attack\n\n"
    )


    file.write(
        "Train/Test Split:\n"
    )

    file.write(
        "80% Training and 20% Testing\n\n"
    )


    file.write(
        f"Total Records: {len(df)}\n"
    )

    file.write(
        f"Training Records: {len(X_train)}\n"
    )

    file.write(
        f"Testing Records: {len(X_test)}\n"
    )

    file.write(
        f"Number of Features: {X.shape[1]}\n\n"
    )


    file.write(
        "Class Distribution:\n"
    )

    for class_value in sorted(
        class_counts.index
    ):

        class_name = (
            "Benign"
            if class_value == 0
            else "Attack"
        )

        count = class_counts[
            class_value
        ]

        percentage = (
            count / len(df)
        ) * 100

        file.write(
            f"{class_name}: "
            f"{count} "
            f"({percentage:.2f}%)\n"
        )


    file.write(
        "\nModel Accuracy:\n"
    )

    file.write(
        f"{accuracy * 100:.2f}%\n\n"
    )


    file.write(
        "Confusion Matrix:\n"
    )

    file.write(
        str(cm)
    )


    file.write(
        "\n\nClassification Report:\n"
    )

    file.write(
        report
    )


    file.write(
        "\n\nConclusion:\n"
    )

    file.write(
        "A Random Forest classifier was trained using "
        "features generated during Practical 5. The "
        "balanced dataset prepared in Practical 6 was "
        "used for training and testing. The model was "
        "evaluated using accuracy, confusion matrix, "
        "precision, recall, and F1-score.\n"
    )


# ============================================================
# 23. FINAL OUTPUT
# ============================================================

print("\n" + "=" * 70)
print("PRACTICAL 9 COMPLETED SUCCESSFULLY")
print("=" * 70)


print("\nAlgorithm:")
print(
    "Random Forest Classifier"
)


print(
    f"\nAccuracy: {accuracy * 100:.2f}%"
)


print(
    "\nOutput files:"
)


print(
    "1. confusion_matrix.csv"
)

print(
    "2. confusion_matrix.png"
)

print(
    "3. classification_report.txt"
)

print(
    "4. feature_importance.csv"
)

print(
    "5. feature_importance.png"
)

print(
    "6. model_results.csv"
)

print(
    "7. test_predictions.csv"
)

print(
    "8. practical_9_report.txt"
)


print(
    "\nOutput folder:"
)

print(
    OUTPUT_FOLDER
)

print(
    "\nPractical 9 finished successfully."
)