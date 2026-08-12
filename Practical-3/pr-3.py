# ============================================================
# PRACTICAL 3
# To Clean the Data and Preprocess the Dataset
# ============================================================

import os
import pandas as pd



# STEP 1 : LOAD THE STRUCTURED DATASET


INPUT_FILE = r"D:\PDS PRACTICAL\Practical-2\output\cj_cleaned.csv"

OUTPUT_FOLDER = "output"

os.makedirs(OUTPUT_FOLDER, exist_ok=True)

df = pd.read_csv(
    INPUT_FILE,
    low_memory=False
)

print("=" * 80)
print("PRACTICAL 3 : DATA CLEANING AND PREPROCESSING".center(80))
print("=" * 80)

print("\nDataset Loaded Successfully!")

print("\nShape of Dataset:")
print(df.shape)

print("\nFirst 5 Records:")
print(df.head())



# STEP 2 : CONVERT TIMESTAMP TO DATETIME


print("\n" + "=" * 80)
print("1st STEP : CONVERT TIMESTAMP TO DATETIME".center(80))
print("=" * 80)

print("\nBefore Conversion:")
print(df["timestamp"].head())

df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    errors="coerce"
)

print("\nAfter Conversion:")
print(df["timestamp"].head())

print("\nTimestamp Data Type:")
print(df["timestamp"].dtype)



# STEP 2 : HANDLE MISSING VALUES


print("\n" + "=" * 80)
print("2nd STEP : HANDLE MISSING VALUES".center(80))
print("=" * 80)

print("\nMissing Values Before Cleaning:")

print(df.isnull().sum())


# Replace missing values in string columns
# with "Unknown"

string_columns = [
    "category_type",
    "sub_key",
    "Browser-OS",
    "language",
    "meta-data"
]

for col in string_columns:

    if col in df.columns:

        df[col] = df[col].fillna("Unknown")


print("\nMissing Values After Cleaning:")

print(df.isnull().sum())



# STEP 3 : NORMALIZE URL PATHS

print("\n" + "=" * 80)
print(
    "3rd STEP : NORMALIZE URL PATHS "
    "(e.g. /index.html vs /index)".center(80)
)
print("=" * 80)




print("\nChecking .html values in Browser-OS:")

html_rows = df[
    df["Browser-OS"].astype(str).str.contains(
        r"\.html",
        na=False,
        regex=True
    )
]

print(html_rows)



# Remove .html extension


df["Browser-OS"] = df["Browser-OS"].astype(str).str.replace(
    r"\.html$",
    "",
    regex=True
)

print("\nAfter removing .html extension:")

print(df)



# Check unique values


print("\nUnique Browser-OS Values:")

print(
    df["Browser-OS"].unique()[:]
)



# Check remaining extensions


print("\nRemaining Extensions:")

extension_counts = (
    df["Browser-OS"]
    .astype(str)
    .str.extract(
        r"\.([a-zA-Z0-9]+)$"
    )[0]
    .value_counts()
)

print(extension_counts)



# STEP 4 : LOWERCASE AND REMOVE EXTRA SPACES


print("\n" + "=" * 80)
print(
    "4th STEP : LOWERCASE AND STRIP SPACES "
    "FROM STRING COLUMNS".center(80)
)
print("=" * 80)


string_columns = [
    "category_type",
    "sub_key",
    "Browser-OS",
    "language",
    "meta-data"
]


for col in string_columns:

    if col in df.columns:

        df[col] = (
            df[col]
            .astype(str)
            .str.lower()
            .str.strip()
        )


print("\nAfter Lowercase and Strip:")

print(df)



# STEP 5 : REMOVE EXTRA SPACES FROM COLUMN NAMES

print("\n" + "=" * 80)
print("5th STEP : CLEAN COLUMN NAMES".center(80))
print("=" * 80)


df.columns = (
    df.columns
    .str.strip()
)


print("\nCleaned Column Names:")

print(df.columns.tolist())



# STEP 6 : CHECK DATA TYPES


print("\n" + "=" * 80)
print("6th STEP : CHECK DATA TYPES".center(80))
print("=" * 80)

print(df.dtypes)



# STEP 7 : CHECK DUPLICATE RECORDS

print("\n" + "=" * 80)
print("7th STEP : CHECK DUPLICATE RECORDS".center(80))
print("=" * 80)


duplicate_count = df.duplicated().sum()

print(
    f"\nNumber of Duplicate Records: "
    f"{duplicate_count:,}"
)


if duplicate_count > 0:

    df = df.drop_duplicates()

    print(
        f"Removed {duplicate_count:,} duplicate records."
    )

else:

    print("No duplicate records found.")



# STEP 8 : FINAL MISSING VALUE CHECK


print("\n" + "=" * 80)
print("8th STEP : FINAL MISSING VALUE CHECK".center(80))
print("=" * 80)

print(df.isnull().sum())



# STEP 9 : FINAL DATASET

print("\n" + "=" * 80)
print("9th STEP : FINAL CLEANED DATASET".center(80))
print("=" * 80)

print("\nFinal Shape:")

print(df.shape)

print("\nFinal Dataset:")

print(df)



# STEP 10 : SAVE PREPROCESSED DATASET

print("\n" + "=" * 80)
print("10th STEP : SAVE CLEANED DATASET".center(80))
print("=" * 80)


OUTPUT_FILE = os.path.join(
    OUTPUT_FOLDER,
    "cj_preprocessed.csv"
)


df.to_csv(
    OUTPUT_FILE,
    index=False
)


print(
    "\nCleaned dataset saved successfully!"
)

print(
    f"File: {OUTPUT_FILE}"
)



# STEP 11 : SAVE CLEANING REPORT

REPORT_FILE = os.path.join(
    OUTPUT_FOLDER,
    "practical_3_report.txt"
)


with open(
    REPORT_FILE,
    "w",
    encoding="utf-8"
) as report:

    report.write(
        "PRACTICAL 3 : DATA CLEANING AND PREPROCESSING\n"
    )

    report.write("=" * 70 + "\n\n")

    report.write(
        f"Original Input File : {INPUT_FILE}\n"
    )

    report.write(
        f"Final Number of Rows : {len(df):,}\n"
    )

    report.write(
        f"Final Number of Columns : {len(df.columns)}\n\n"
    )

    report.write(
        "Cleaning Operations Performed:\n\n"
    )

    report.write(
        "1. Timestamp converted to datetime format.\n"
    )

    report.write(
        "2. Missing values handled.\n"
    )

    report.write(
        "3. .html extension checked and normalized.\n"
    )

    report.write(
        "4. String values converted to lowercase.\n"
    )

    report.write(
        "5. Extra spaces removed.\n"
    )

    report.write(
        "6. Column names cleaned.\n"
    )

    report.write(
        "7. Duplicate records checked and removed.\n"
    )

    report.write(
        "8. Final missing values checked.\n"
    )


print(
    f"\nReport saved: {REPORT_FILE}"
)



# FINAL SUMMARY


print("\n" + "=" * 80)
print("PRACTICAL 3 COMPLETED".center(80))
print("=" * 80)

print(
    f"""
Input Dataset:
    cj_cleaned.csv

Final Dataset:
    cj_preprocessed.csv

Rows:
    {len(df):,}

Columns:
    {len(df.columns)}

Cleaning performed:
    ✓ Timestamp converted to datetime
    ✓ Missing values handled
    ✓ URL/.html normalization checked
    ✓ Strings converted to lowercase
    ✓ Extra spaces removed
    ✓ Duplicate records checked
    ✓ Final dataset saved

Output:
    {OUTPUT_FILE}

Report:
    {REPORT_FILE}
"""
)

