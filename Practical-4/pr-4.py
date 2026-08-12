"""
============================================================
PRACTICAL 4
To Label the Requests as Benign or Attack

============================================================
"""

import os
import pandas as pd


# CONFIGURATION

PROJECT_FOLDER = r"D:\PDS PRACTICAL"

INPUT_FILE = os.path.join(
    PROJECT_FOLDER,
    "Practical-3",
    "output",
    "cj_preprocessed.csv"
)

OUTPUT_FOLDER = os.path.join(
    PROJECT_FOLDER,
    "Practical-4",
    "output"
)

os.makedirs(
    OUTPUT_FOLDER,
    exist_ok=True
)


# HEADING FUNCTION

def heading(title):
    print("\n" + "=" * 80)
    print(title.center(80))
    print("=" * 80)


# STEP 1 : CHECK INPUT FILE

heading("STEP 1 : CHECKING INPUT DATASET")

print("Input file:")
print(INPUT_FILE)

if not os.path.exists(INPUT_FILE):

    print("\nERROR: Input dataset not found!")

    raise SystemExit

print("\nInput dataset found successfully!")


# STEP 2 : LOAD DATASET

heading("STEP 2 : LOADING PREPROCESSED DATASET")

df = pd.read_csv(
    INPUT_FILE,
    low_memory=False
)

print("\nDataset loaded successfully!")

print(f"\nRows    : {len(df):,}")
print(f"Columns : {len(df.columns)}")

print("\nColumns:")
print(df.columns.tolist())


# STEP 3 : ORIGINAL DATA SAMPLE

heading("STEP 3 : ORIGINAL DATA SAMPLE")

print(
    df.head(10).to_string(index=False)
)


# STEP 4 : PREPARE DATA FOR ATTACK DETECTION

heading("STEP 4 : PREPARING DATA FOR ATTACK DETECTION")

text_columns = [
    "category_type",
    "sub_key",
    "Browser-OS",
    "language",
    "meta-data"
]

available_columns = [
    column
    for column in text_columns
    if column in df.columns
]

print("\nText columns used for detection:")
print(available_columns)

print(
    "\nPreparing individual columns..."
)

# Convert only the required columns to lowercase strings.
# We do NOT combine all columns into one huge DataFrame.

for column in available_columns:

    df[column] = (
        df[column]
        .fillna("")
        .astype(str)
        .str.lower()
        .str.strip()
    )

print(
    "\nData preparation completed successfully!"
)

# STEP 5 : SQL INJECTION DETECTION

heading("STEP 5 : DETECTING SQL INJECTION")

sqli_pattern = (
    r"\bor\b\s*1\s*=\s*1"
    r"|\band\b\s*1\s*=\s*1"
    r"|union\s+select"
    r"|select\s+.*\s+from"
    r"|insert\s+into"
    r"|delete\s+from"
    r"|drop\s+table"
    r"|'[^']*'\s*or\s*'[^']*'\s*="
)

sqli_detected = pd.Series(
    False,
    index=df.index
)

for column in available_columns:

    sqli_detected |= df[column].str.contains(
        sqli_pattern,
        regex=True,
        na=False
    )

print(
    "\nPossible SQL Injection records:"
)

print(
    f"{sqli_detected.sum():,}"
)


# STEP 6 : PATH TRAVERSAL DETECTION

heading("STEP 6 : DETECTING PATH TRAVERSAL")

path_pattern = (
    r"\.\./"
    r"|\.\.\\"
    r"|%2e%2e"
    r"|%252e%252e"
    r"|/etc/passwd"
    r"|/etc/shadow"
)

path_detected = pd.Series(
    False,
    index=df.index
)

for column in available_columns:

    path_detected |= df[column].str.contains(
        path_pattern,
        regex=True,
        na=False
    )

print(
    "\nPossible Path Traversal records:"
)

print(
    f"{path_detected.sum():,}"
)


# STEP 7 : LOGIN ACTIVITY DETECTION

heading("STEP 7 : DETECTING LOGIN ACTIVITY")

login_pattern = (
    r"/login"
    r"|/signin"
    r"|/sign-in"
    r"|login"
    r"|signin"
    r"|password"
    r"|passwd"
    r"|authentication"
    r"|authenticate"
)

login_detected = pd.Series(
    False,
    index=df.index
)

for column in available_columns:

    login_detected |= df[column].str.contains(
        login_pattern,
        regex=True,
        na=False
    )

print(
    "\nAuthentication-related records:"
)

print(
    f"{login_detected.sum():,}"
)


# STEP 8 : BRUTE FORCE DETECTION

heading("STEP 8 : DETECTING POSSIBLE BRUTE FORCE")

brute_force_detected = pd.Series(
    False,
    index=df.index
)

if "Client-IP-address" in df.columns:

    # Count authentication-related activity per IP

    login_ip_counts = (
        df.loc[
            login_detected,
            "Client-IP-address"
        ]
        .value_counts()
    )

    # Five or more authentication-related
    # records from the same IP

    brute_force_ips = login_ip_counts[
        login_ip_counts >= 5
    ].index

    brute_force_detected = (
        login_detected
        &
        df["Client-IP-address"].isin(
            brute_force_ips
        )
    )

print(
    "\nPossible brute-force records:"
)

print(
    f"{brute_force_detected.sum():,}"
)


# STEP 9 : CREATE LABEL

heading("STEP 9 : CREATING LABEL COLUMN")

# Initially classify every record as benign.

df["label"] = "benign"


# Apply attack labels.

df.loc[
    brute_force_detected,
    "label"
] = "brute_force"


df.loc[
    path_detected,
    "label"
] = "path_traversal"


df.loc[
    sqli_detected,
    "label"
] = "sqli"


print(
    "\nLabel column created successfully!"
)


# STEP 10 : LABEL DISTRIBUTION

heading("STEP 10 : LABEL DISTRIBUTION")

label_counts = (
    df["label"]
    .value_counts()
)

print("\nNumber of records per label:")

print(
    label_counts
)


print("\nPercentage distribution:")

label_percentage = (
    df["label"]
    .value_counts(normalize=True)
    .mul(100)
    .round(2)
)

print(
    label_percentage
)


# STEP 11 : SHOW LABELED DATA

heading("STEP 11 : LABELED DATA SAMPLE")

display_columns = [
    "timestamp",
    "Client-IP-address",
    "Browser-OS",
    "language",
    "meta-data",
    "label"
]

display_columns = [
    column
    for column in display_columns
    if column in df.columns
]

print(
    df[
        display_columns
    ]
    .head(20)
    .to_string(index=False)
)


# STEP 12 : DETECTED ATTACK RECORDS

heading("STEP 12 : DETECTED ATTACK RECORDS")

attack_records = df[
    df["label"] != "benign"
]

print(
    f"\nTotal potential attack records: "
    f"{len(attack_records):,}"
)

if len(attack_records) > 0:

    print(
        "\nSample detected attack records:"
    )

    print(
        attack_records[
            display_columns
        ]
        .head(20)
        .to_string(index=False)
    )

else:

    print(
        "\nNo records matched the defined "
        "attack patterns."
    )


# STEP 13 : IP ANALYSIS

heading("STEP 13 : IP ANALYSIS")

if "Client-IP-address" in df.columns:

    for label in [
        "sqli",
        "path_traversal",
        "brute_force"
    ]:

        print(
            f"\nTop IP addresses for {label}:"
        )

        label_data = df[
            df["label"] == label
        ]

        if len(label_data) > 0:

            print(
                label_data[
                    "Client-IP-address"
                ]
                .value_counts()
                .head(10)
            )

        else:

            print(
                "No records found."
            )



# STEP 14 : SAVE LABELED DATASET

heading("STEP 14 : SAVING LABELED DATASET")

OUTPUT_FILE = os.path.join(
    OUTPUT_FOLDER,
    "labeled_logs.csv"
)

df.to_csv(
    OUTPUT_FILE,
    index=False
)

print(
    "\nLabeled dataset saved successfully!"
)

print(
    f"File: {OUTPUT_FILE}"
)


# STEP 15 : SAVE LABEL SUMMARY

heading("STEP 15 : SAVING LABEL SUMMARY")

SUMMARY_FILE = os.path.join(
    OUTPUT_FOLDER,
    "label_summary.csv"
)

summary = (
    df["label"]
    .value_counts()
    .rename_axis("label")
    .reset_index(name="count")
)

summary["percentage"] = (
    summary["count"]
    / len(df)
    * 100
).round(2)

summary.to_csv(
    SUMMARY_FILE,
    index=False
)

print(
    "\nLabel summary:"
)

print(
    summary.to_string(index=False)
)

print(
    f"\nSaved to: {SUMMARY_FILE}"
)


# STEP 16 : GENERATE REPORT

heading("STEP 16 : GENERATING REPORT")

REPORT_FILE = os.path.join(
    OUTPUT_FOLDER,
    "practical_4_report.txt"
)

with open(
    REPORT_FILE,
    "w",
    encoding="utf-8"
) as report:

    report.write(
        "=" * 70 + "\n"
    )

    report.write(
        "PRACTICAL 4 : BASIC LOG CLASSIFICATION\n"
    )

    report.write(
        "=" * 70 + "\n\n"
    )

    report.write(
        "Objective:\n"
    )

    report.write(
        "Create labeled categories for log analysis "
        "using known attack patterns.\n\n"
    )

    report.write(
        f"Total Records: {len(df):,}\n\n"
    )

    report.write(
        "Label Distribution:\n"
    )

    report.write(
        summary.to_string(index=False)
    )

    report.write(
        "\n\nAttack Detection Rules:\n"
    )

    report.write(
        "SQL Injection: OR 1=1, UNION SELECT, "
        "SELECT FROM, INSERT INTO, DELETE FROM, "
        "DROP TABLE.\n"
    )

    report.write(
        "Path Traversal: ../, ..\\, %2e%2e, "
        "/etc/passwd.\n"
    )

    report.write(
        "Brute Force: Five or more authentication-"
        "related records from the same IP.\n"
    )

    report.write(
        "\nDataset Limitation:\n"
    )

    report.write(
        "The supplied cj.log dataset does not contain "
        "explicit URL, HTTP method, or status-code "
        "fields. Therefore, classification is based "
        "only on patterns available in the dataset.\n"
    )

print(
    f"\nReport saved to: {REPORT_FILE}"
)


# FINAL SUMMARY


heading("PRACTICAL 4 COMPLETED")

print(
    "\nClassification completed successfully!"
)

print(
    f"\nTotal Records : {len(df):,}"
)

print(
    f"Total Columns : {len(df.columns)}"
)

print(
    "\nLabel Distribution:"
)

print(
    summary.to_string(index=False)
)

print(
    "\nGenerated Files:"
)

print(
    "1. labeled_logs.csv"
)

print(
    "2. label_summary.csv"
)

print(
    "3. practical_4_report.txt"
)

print(
    "\nPractical 4 completed successfully!"
)