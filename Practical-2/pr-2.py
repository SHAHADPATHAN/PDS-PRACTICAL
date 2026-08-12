"""
=============================================================
PRACTICAL 2
To Convert the Unstructured Log Data into a Structured Dataset
=============================================================
"""

import os
import json
import logging

import pandas as pd

# CONFIGURATION


LOG_FILE = r"D:\PDS PRACTICAL\Logs\logs\cj.log"

OUTPUT_FOLDER = "output"

os.makedirs(OUTPUT_FOLDER, exist_ok=True)



# LOGGING

logging.basicConfig(
    filename="output/practical_2.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logging.info("Practical 2 Started")


# HEADING FUNCTION

def heading(title):
    """Display a formatted heading."""

    print("\n" + "=" * 80)
    print(title.center(80))
    print("=" * 80)



# STEP 1: CHECK FILE


heading("STEP 1 : CHECKING LOG FILE")

if not os.path.exists(LOG_FILE):

    print("\nLog File Not Found!")

    print("\nExpected location:")
    print(LOG_FILE)

    logging.error("Log file not found.")

    raise SystemExit


print("Log File Found Successfully!")

print(f"Location : {LOG_FILE}")



# STEP 2: PARSE RAW LOG


heading("STEP 2 : PARSING RAW LOG DATA")

records = []

valid_records = 0

invalid_records = 0


print("Reading and parsing cj.log...")
print("Please wait. The file is large.")


with open(
    LOG_FILE,
    "r",
    encoding="utf-8",
    errors="replace"
) as file:

    for line in file:

        line = line.strip()

        if not line:
            continue

        try:

            # Convert JSON string into Python list
            row = json.loads(line)

            # Make sure every row has 8 positions
            while len(row) < 8:
                row.append(None)

            # Keep only the first 8 fields
            row = row[:8]

            records.append({

                "category_type": row[0],

                "sub_key": row[1],

                "timestamp": row[2],

                "Client-IP-address": row[3],

                "port": row[4],

                "Browser-OS": row[5],

                "language": row[6],

                "meta-data": row[7]

            })

            valid_records += 1

        except (json.JSONDecodeError, TypeError):

            invalid_records += 1


print("\nParsing Completed!")

print(f"Valid Records   : {valid_records:,}")

print(f"Invalid Records : {invalid_records:,}")



# STEP 3: CREATE PANDAS DATAFRAME


heading("STEP 3 : CREATING PANDAS DATAFRAME")

df = pd.DataFrame(records)


print("\nStructured DataFrame Created Successfully!")

print("\nFirst 10 Records:")

print(
    df.head(10).to_string(index=False)
)



# STEP 4: DISPLAY DATAFRAME INFORMATION


heading("STEP 4 : DATAFRAME INFORMATION")

print("\nShape:")

print(df.shape)


print("\nColumns:")

print(df.columns.tolist())


print("\nData Types:")

print(df.dtypes)


print("\nMissing Values:")

print(df.isnull().sum())



# STEP 5: CONVERT DATA TYPES


heading("STEP 5 : DATA TYPE CONVERSION")


# Convert timestamp into datetime

df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    errors="coerce"
)


# Convert port into numeric

df["port"] = pd.to_numeric(
    df["port"],
    errors="coerce"
)


print("\nData types after conversion:")

print(df.dtypes)



# STEP 6: DISPLAY STRUCTURED DATA


heading("STEP 6 : STRUCTURED DATA")

print(
    df.sample(
        min(10, len(df)),
        random_state=42
    ).to_string(index=False)
)



# STEP 7: BASIC ANALYSIS


heading("STEP 7 : BASIC ANALYSIS")


print("\nNumber of Records:")

print(f"{len(df):,}")


print("\nNumber of Columns:")

print(len(df.columns))


print("\nUnique IP Addresses:")

print(
    df["Client-IP-address"].nunique()
)


print("\nTop 10 IP Addresses:")

print(
    df["Client-IP-address"]
    .value_counts()
    .head(10)
)


print("\nTop 10 Browser/User Agents:")

print(
    df["Browser-OS"]
    .value_counts(dropna=False)
    .head(10)
)


print("\nTop 10 Languages:")

print(
    df["language"]
    .value_counts(dropna=False)
    .head(10)
)



# STEP 8: SAVE STRUCTURED DATASET


heading("STEP 8 : SAVING STRUCTURED DATASET")

OUTPUT_FILE = os.path.join(
    OUTPUT_FOLDER,
    "cj_cleaned.csv"
)


df.to_csv(
    OUTPUT_FILE,
    index=False
)


print("\nStructured dataset saved successfully!")

print(
    f"File : {OUTPUT_FILE}"
)



# STEP 9: SAVE SAMPLE DATASET


heading("STEP 9 : SAVING SAMPLE DATASET")

SAMPLE_FILE = os.path.join(
    OUTPUT_FOLDER,
    "structured_sample.csv"
)


df.sample(
    min(100, len(df)),
    random_state=42
).to_csv(
    SAMPLE_FILE,
    index=False
)


print(
    f"Sample dataset saved to: {SAMPLE_FILE}"
)



# STEP 10: FIELD DESCRIPTION


heading("STEP 10 : STRUCTURED FIELD DESCRIPTION")


field_description = pd.DataFrame({

    "Field": [

        "category_type",

        "sub_key",

        "timestamp",

        "Client-IP-address",

        "port",

        "Browser-OS",

        "language",

        "meta-data"

    ],

    "Description": [

        "Category or type of event",

        "Additional event key or subtype",

        "Date and time of the event",

        "IP address of the client",

        "Network port used by the client",

        "Browser, operating system or user-agent information",

        "Language information",

        "Additional metadata associated with the event"

    ]

})


print(
    field_description.to_string(index=False)
)



# STEP 11: SAVE FIELD DESCRIPTION


FIELD_FILE = os.path.join(
    OUTPUT_FOLDER,
    "field_description.csv"
)


field_description.to_csv(
    FIELD_FILE,
    index=False
)


print(
    f"\nField description saved to: {FIELD_FILE}"
)


# STEP 12: GENERATE REPORT

heading("STEP 12 : GENERATING REPORT")


REPORT_FILE = os.path.join(
    OUTPUT_FOLDER,
    "practical_2_report.txt"
)


with open(
    REPORT_FILE,
    "w",
    encoding="utf-8"
) as report:

    report.write("=" * 70 + "\n")

    report.write(
        "PRACTICAL 2 : STRUCTURED LOG DATASET\n"
    )

    report.write("=" * 70 + "\n\n")

    report.write("OBJECTIVE\n")

    report.write(
        "To convert unstructured raw log data into "
        "a structured tabular dataset using Python "
        "and Pandas.\n\n"
    )

    report.write("SOURCE DATASET\n")

    report.write(
        "cj.log\n\n"
    )

    report.write("TOTAL VALID RECORDS\n")

    report.write(
        f"{valid_records:,}\n\n"
    )

    report.write("INVALID RECORDS\n")

    report.write(
        f"{invalid_records:,}\n\n"
    )

    report.write("STRUCTURED COLUMNS\n")

    for column in df.columns:

        report.write(
            f"- {column}\n"
        )

    report.write("\nUNIQUE IP ADDRESSES\n")

    report.write(
        f"{df['Client-IP-address'].nunique():,}\n"
    )

    report.write(
        "\nTOP 10 IP ADDRESSES\n"
    )

    report.write(
        str(
            df["Client-IP-address"]
            .value_counts()
            .head(10)
        )
    )

    report.write(
        "\n\nTOP 10 USER AGENTS\n"
    )

    report.write(
        str(
            df["Browser-OS"]
            .value_counts(dropna=False)
            .head(10)
        )
    )


print(
    f"\nReport saved to: {REPORT_FILE}"
)


# FINAL SUMMARY

heading("PRACTICAL 2 COMPLETED")

print("""
Raw cj.log has successfully been converted into
a structured Pandas DataFrame.

Extracted Fields:

1. category_type
2. sub_key
3. timestamp
4. Client-IP-address
5. port
6. Browser-OS
7. language
8. meta-data
""")


print(
    f"Total Structured Records : {len(df):,}"
)

print(
    f"Total Columns            : {len(df.columns)}"
)

print(
    f"Unique IP Addresses      : "
    f"{df['Client-IP-address'].nunique():,}"
)


print("\nGenerated Files:")

print("- cj_cleaned.csv")

print("- structured_sample.csv")

print("- field_description.csv")

print("- practical_2_report.txt")

print("- practical_2.log")


logging.info("Practical 2 Completed Successfully")

