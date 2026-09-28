"""
============================================================
PRACTICAL 5
Feature Engineering for Anomaly Detection
============================================================

Objective:
    Create meaningful features for anomaly detection
    and suspicious activity analysis.

Features:
    1. Number of requests per IP
    2. Time between requests
    3. Status code frequency
    4. User-agent parsing
    5. URL entropy
    6. Additional IP-level features

Input:
    Practical-4/output/labeled_logs.csv

Output:
    Practical-5/output/feature_engineered_logs.csv
    Practical-5/output/ip_features.csv
    Practical-5/output/practical_5_report.txt
============================================================
"""

import os
import math
import re

import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_FOLDER = r"D:\PDS PRACTICAL"

INPUT_FILE = os.path.join(
    PROJECT_FOLDER,
    "Practical-4",
    "output",
    "labeled_logs.csv"
)

OUTPUT_FOLDER = os.path.join(
    PROJECT_FOLDER,
    "Practical-5",
    "output"
)

os.makedirs(
    OUTPUT_FOLDER,
    exist_ok=True
)


# ============================================================
# HEADING FUNCTION
# ============================================================

def heading(title):
    """Display a formatted heading."""

    print("\n" + "=" * 80)
    print(title.center(80))
    print("=" * 80)


# ============================================================
# STEP 1 : CHECK INPUT FILE
# ============================================================

heading("STEP 1 : CHECKING INPUT DATASET")

print("Input file:")
print(INPUT_FILE)

if not os.path.exists(INPUT_FILE):

    print("\nERROR: Input dataset not found!")

    print(
        "\nPlease complete Practical 4 first."
    )

    raise SystemExit

print("\nInput dataset found successfully!")


# ============================================================
# STEP 2 : LOAD DATASET
# ============================================================

heading("STEP 2 : LOADING LABELED DATASET")

df = pd.read_csv(
    INPUT_FILE,
    low_memory=False
)

print("\nDataset loaded successfully!")

print(
    f"\nRows    : {len(df):,}"
)

print(
    f"Columns : {len(df.columns)}"
)

print("\nColumns:")

print(
    df.columns.tolist()
)


# ============================================================
# STEP 3 : CONVERT TIMESTAMP
# ============================================================

heading("STEP 3 : CONVERTING TIMESTAMP")

if "timestamp" in df.columns:

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    print(
        "Timestamp converted successfully."
    )

else:

    print(
        "Timestamp column not found."
    )


# ============================================================
# STEP 4 : NUMBER OF REQUESTS PER IP
# ============================================================

heading("STEP 4 : NUMBER OF REQUESTS PER IP")

if "Client-IP-address" in df.columns:

    ip_request_count = (
        df["Client-IP-address"]
        .value_counts()
    )

    df["requests_per_ip"] = (
        df["Client-IP-address"]
        .map(ip_request_count)
    )

    print(
        "\nRequests per IP feature created."
    )

    print(
        "\nTop 10 IP addresses:"
    )

    print(
        ip_request_count.head(10)
    )

else:

    print(
        "Client-IP-address column not found."
    )


# ============================================================
# STEP 5 : TIME BETWEEN REQUESTS
# ============================================================

heading("STEP 5 : TIME BETWEEN REQUESTS")

if (
    "Client-IP-address" in df.columns
    and "timestamp" in df.columns
):

    print(
        "Calculating time difference between "
        "consecutive events from the same IP..."
    )

    # Sort by IP and timestamp

    df = df.sort_values(
        [
            "Client-IP-address",
            "timestamp"
        ]
    )

    # Calculate difference between consecutive
    # requests from the same IP.

    df["time_between_requests"] = (
        df.groupby(
            "Client-IP-address"
        )["timestamp"]
        .diff()
        .dt.total_seconds()
    )

    # First request from an IP has no previous
    # request, so fill it with 0.

    df["time_between_requests"] = (
        df["time_between_requests"]
        .fillna(0)
    )

    print(
        "\nTime-between-requests feature created."
    )

    print(
        df[
            [
                "Client-IP-address",
                "timestamp",
                "time_between_requests"
            ]
        ].head(20)
    )

else:

    print(
        "Required columns are not available."
    )


# ============================================================
# STEP 6 : STATUS CODE FREQUENCY
# ============================================================

heading("STEP 6 : STATUS CODE FREQUENCY")


# Your cj.log dataset does not contain an explicit
# HTTP status-code column.

status_column = None

possible_status_columns = [
    "status",
    "status_code",
    "Status",
    "Status_Code",
    "HTTP_Status"
]

for column in possible_status_columns:

    if column in df.columns:

        status_column = column
        break


if status_column is not None:

    print(
        f"Status column found: {status_column}"
    )

    status_counts = (
        df[status_column]
        .value_counts()
    )

    df["status_frequency"] = (
        df[status_column]
        .map(status_counts)
    )

    print(
        "\nStatus frequency:"
    )

    print(
        status_counts
    )

else:

    print(
        "No HTTP status-code column exists "
        "in the supplied cj.log dataset."
    )

    print(
        "Status-code feature skipped."
    )


# ============================================================
# STEP 7 : USER-AGENT PARSING
# ============================================================

heading("STEP 7 : USER-AGENT PARSING")


# Your dataset stores browser/client information
# in Browser-OS.

if "Browser-OS" in df.columns:

    user_agent = (
        df["Browser-OS"]
        .fillna("")
        .astype(str)
        .str.lower()
    )


    # --------------------------------------------------------
    # Browser / Client Type
    # --------------------------------------------------------

    def identify_client(value):

        if "chrome" in value:

            return "chrome"

        if "firefox" in value:

            return "firefox"

        if "safari" in value:

            return "safari"

        if "edge" in value:

            return "edge"

        if "opera" in value:

            return "opera"

        if "mozilla" in value:

            return "mozilla"

        if "go-http-client" in value:

            return "go-http-client"

        if "gobuster" in value:

            return "gobuster"

        if "dirbuster" in value:

            return "dirbuster"

        if "python" in value:

            return "python"

        if "curl" in value:

            return "curl"

        if "wget" in value:

            return "wget"

        return "other"


    df["client_type"] = user_agent.apply(
        identify_client
    )


    # --------------------------------------------------------
    # Bot / Automated Client Detection
    # --------------------------------------------------------

    bot_pattern = (
        r"bot"
        r"|crawler"
        r"|spider"
        r"|gobuster"
        r"|dirbuster"
        r"|curl"
        r"|wget"
        r"|python"
        r"|go-http-client"
    )


    df["is_bot"] = (
        user_agent
        .str.contains(
            bot_pattern,
            regex=True,
            na=False
        )
    )


    print(
        "\nClient type distribution:"
    )

    print(
        df["client_type"]
        .value_counts()
    )


    print(
        "\nBot / automated-client distribution:"
    )

    print(
        df["is_bot"]
        .value_counts()
    )


else:

    print(
        "Browser-OS column not found."
    )


# ============================================================
# STEP 8 : URL ENTROPY
# ============================================================

heading("STEP 8 : URL ENTROPY")


# Check whether the dataset has a URL field.

possible_url_columns = [
    "url",
    "URL",
    "resource",
    "resource_requested",
    "requested_url",
    "request_url",
    "path",
    "url_path"
]

url_column = None

for column in possible_url_columns:

    if column in df.columns:

        url_column = column
        break


# ------------------------------------------------------------
# Entropy function
# ------------------------------------------------------------

def calculate_entropy(value):
    """
    Calculate Shannon entropy of a string.
    """

    if pd.isna(value):

        return 0.0

    value = str(value)

    if len(value) == 0:

        return 0.0

    frequency = {}

    for character in value:

        frequency[character] = (
            frequency.get(character, 0) + 1
        )

    entropy = 0.0

    length = len(value)

    for count in frequency.values():

        probability = count / length

        entropy -= (
            probability
            * math.log2(probability)
        )

    return entropy


if url_column is not None:

    print(
        f"URL column found: {url_column}"
    )

    df["url_entropy"] = (
        df[url_column]
        .fillna("")
        .apply(calculate_entropy)
    )

    print(
        "\nURL entropy calculated."
    )

    print(
        df["url_entropy"].describe()
    )

else:

    print(
        "No URL/resource column exists "
        "in the supplied cj.log dataset."
    )

    print(
        "URL entropy cannot be calculated "
        "from the current dataset."
    )


# ============================================================
# STEP 9 : USER-AGENT LENGTH
# ============================================================

heading("STEP 9 : USER-AGENT LENGTH")

if "Browser-OS" in df.columns:

    df["user_agent_length"] = (
        df["Browser-OS"]
        .fillna("")
        .astype(str)
        .str.len()
    )

    print(
        "User-agent length feature created."
    )

    print(
        df["user_agent_length"].describe()
    )


# ============================================================
# STEP 10 : UNIQUE USER-AGENT COUNT PER IP
# ============================================================

heading("STEP 10 : UNIQUE USER-AGENTS PER IP")


if (
    "Client-IP-address" in df.columns
    and "Browser-OS" in df.columns
):

    unique_agents_per_ip = (
        df.groupby(
            "Client-IP-address"
        )["Browser-OS"]
        .nunique()
    )

    df["unique_user_agents_per_ip"] = (
        df["Client-IP-address"]
        .map(unique_agents_per_ip)
    )

    print(
        "Unique user-agent count per IP created."
    )

    print(
        unique_agents_per_ip.head(10)
    )


# ============================================================
# STEP 11 : IP-LEVEL FEATURES
# ============================================================

heading("STEP 11 : CREATING IP-LEVEL FEATURES")


if "Client-IP-address" in df.columns:

    ip_features = (
        df.groupby(
            "Client-IP-address"
        )
        .agg(
            total_requests=(
                "Client-IP-address",
                "size"
            )
        )
        .reset_index()
    )


    if "time_between_requests" in df.columns:

        time_features = (
            df.groupby(
                "Client-IP-address"
            )["time_between_requests"]
            .agg(
                average_time_between_requests="mean",
                minimum_time_between_requests="min",
                maximum_time_between_requests="max"
            )
            .reset_index()
        )

        ip_features = ip_features.merge(
            time_features,
            on="Client-IP-address",
            how="left"
        )


    if "is_bot" in df.columns:

        bot_features = (
            df.groupby(
                "Client-IP-address"
            )["is_bot"]
            .sum()
            .reset_index(
                name="bot_requests"
            )
        )

        ip_features = ip_features.merge(
            bot_features,
            on="Client-IP-address",
            how="left"
        )


    if "Browser-OS" in df.columns:

        agent_features = (
            df.groupby(
                "Client-IP-address"
            )["Browser-OS"]
            .nunique()
            .reset_index(
                name="unique_user_agents"
            )
        )

        ip_features = ip_features.merge(
            agent_features,
            on="Client-IP-address",
            how="left"
        )


    print(
        "\nIP-level features:"
    )

    print(
        ip_features.head(10)
    )

else:

    ip_features = pd.DataFrame()

    print(
        "IP address column not available."
    )


# ============================================================
# STEP 12 : SAVE FEATURE-ENGINEERED DATASET
# ============================================================

heading("STEP 12 : SAVING FEATURE-ENGINEERED DATASET")


OUTPUT_FILE = os.path.join(
    OUTPUT_FOLDER,
    "feature_engineered_logs.csv"
)

df.to_csv(
    OUTPUT_FILE,
    index=False
)

print(
    "\nFeature-engineered dataset saved!"
)

print(
    OUTPUT_FILE
)


# ============================================================
# STEP 13 : SAVE IP FEATURES
# ============================================================

heading("STEP 13 : SAVING IP FEATURES")


IP_FEATURE_FILE = os.path.join(
    OUTPUT_FOLDER,
    "ip_features.csv"
)


if not ip_features.empty:

    ip_features.to_csv(
        IP_FEATURE_FILE,
        index=False
    )

    print(
        f"IP features saved to:\n"
        f"{IP_FEATURE_FILE}"
    )

else:

    print(
        "No IP feature file created."
    )


# ============================================================
# STEP 14 : GENERATE REPORT
# ============================================================

heading("STEP 14 : GENERATING REPORT")


REPORT_FILE = os.path.join(
    OUTPUT_FOLDER,
    "practical_5_report.txt"
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
        "PRACTICAL 5 : FEATURE ENGINEERING\n"
    )

    report.write(
        "=" * 70 + "\n\n"
    )

    report.write(
        "Objective:\n"
    )

    report.write(
        "Create meaningful features for anomaly "
        "detection and suspicious activity analysis.\n\n"
    )

    report.write(
        f"Total Records: {len(df):,}\n\n"
    )

    report.write(
        "Features Created:\n\n"
    )

    if "requests_per_ip" in df.columns:

        report.write(
            "1. Requests per IP\n"
        )

    if "time_between_requests" in df.columns:

        report.write(
            "2. Time between requests\n"
        )

    if "status_frequency" in df.columns:

        report.write(
            "3. Status code frequency\n"
        )

    else:

        report.write(
            "3. Status code frequency - "
            "not available because the dataset "
            "does not contain status codes.\n"
        )

    if "client_type" in df.columns:

        report.write(
            "4. User-agent/client type\n"
        )

    if "is_bot" in df.columns:

        report.write(
            "5. Bot/automated client indicator\n"
        )

    if "url_entropy" in df.columns:

        report.write(
            "6. URL entropy\n"
        )

    else:

        report.write(
            "6. URL entropy - "
            "not available because the dataset "
            "does not contain URL fields.\n"
        )

    if "user_agent_length" in df.columns:

        report.write(
            "7. User-agent length\n"
        )

    if "unique_user_agents_per_ip" in df.columns:

        report.write(
            "8. Unique user-agents per IP\n"
        )

    report.write(
        "\nDataset Limitation:\n"
    )

    report.write(
        "The supplied cj.log dataset does not contain "
        "explicit HTTP status-code or URL fields. "
        "Therefore, those features are generated only "
        "when the corresponding columns are available.\n"
    )


print(
    f"\nReport saved to:\n"
    f"{REPORT_FILE}"
)


# ============================================================
# FINAL SUMMARY
# ============================================================

heading("PRACTICAL 5 COMPLETED")

print(
    "\nFeature engineering completed successfully!"
)

print(
    f"\nTotal Records : {len(df):,}"
)

print(
    f"Total Columns : {len(df.columns)}"
)

print(
    "\nGenerated files:"
)

print(
    "- feature_engineered_logs.csv"
)

print(
    "- ip_features.csv"
)

print(
    "- practical_5_report.txt"
)

print(
    "\nPractical 5 completed successfully!"
)