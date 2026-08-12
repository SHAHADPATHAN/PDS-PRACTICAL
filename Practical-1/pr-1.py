"""
===========================================================
PRACTICAL 1
Load and Explore the Unstructured Access Log Data
===========================================================
"""

import os
import json
import random
import logging
from datetime import datetime

import pandas as pd
import matplotlib.pyplot as plt

from tqdm import tqdm
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)


LOG_FILE = r"D:\PDS PRACTICAL\Logs\logs\cj.log"  

OUTPUT_FOLDER = "output"

os.makedirs(OUTPUT_FOLDER, exist_ok=True)

logging.basicConfig(
    filename="output/project.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logging.info("Project Started")

# Heading Function


def heading(title):
    print("\n" + "=" * 80)
    print(Fore.CYAN + title.center(80))
    print("=" * 80)



# Step 1 : Load Log File


heading("STEP 1 : LOADING LOG FILE")

try:

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        log_lines = file.readlines()

    print(Fore.GREEN + f"\nSuccessfully Loaded : {LOG_FILE}")
    print(Fore.YELLOW + f"Total Log Entries : {len(log_lines):,}")

    logging.info("Log file loaded successfully.")

except FileNotFoundError:

    print(Fore.RED + "\nLog File Not Found!")

    logging.error("Log file not found.")

    exit()

# Step 2 : Load Using Pandas


heading("STEP 2 : LOADING USING PANDAS")

df_raw = pd.DataFrame(log_lines, columns=["Raw_Log"])

print(df_raw.head())

# Step 3 : Basic Information


heading("STEP 3 : BASIC INFORMATION")

print(Fore.YELLOW + f"\nTotal Log Entries : {len(log_lines):,}")

print("\nFirst 10 Entries")
print("-" * 60)

for line in log_lines[:10]:
    print(line.strip())

print("\nLast 10 Entries")
print("-" * 60)

for line in log_lines[-10:]:
    print(line.strip())

print("\nRandom 10 Entries")
print("-" * 60)

sample_logs = random.sample(log_lines, 10)

for line in sample_logs:
    print(line.strip())


# Step 4 : Explain Log Format


heading("STEP 4 : LOG FORMAT")

print("""
Your log file is NOT a standard Apache access log.

It contains the following fields:

Index   Field
-------------------------------------
0       Event Type
1       Event Sub Type
2       Timestamp
3       IP Address
4       Port
5       User Agent
6       Language
7       Forwarded IP

Example:

[null,null,"2023-01-08 08:07:15",
"104.28.209.153",
"61901",
"Mozilla/5.0...",
"en",
"104.28.209.153"]

Useful Fields:

IP Address
Timestamp
Port
User Agent
Language
Forwarded IP
Event Type
Event Sub Type
""")

logging.info("Displayed Log Format")


# Step 5 : Parse JSON Log


heading("STEP 5 : PARSING LOG")

records = []

for line in tqdm(log_lines):

    line = line.strip()

    if line == "":
        continue

    try:

        row = json.loads(line)

        while len(row) < 8:
            row.append(None)

        records.append({

            "Event_Type": row[0],

            "Sub_Type": row[1],

            "Timestamp": row[2],

            "IP_Address": row[3],

            "Port": row[4],

            "User_Agent": row[5],

            "Language": row[6],

            "Forwarded_IP": row[7]

        })

    except Exception:

        continue

df = pd.DataFrame(records)

print(Fore.GREEN + "\nParsing Completed Successfully!\n")

print(df.head())

logging.info("Parsing Completed")


# Step 6 : Data Exploration


heading("STEP 6 : DATA EXPLORATION")

print("\nDataFrame Head")
print(df.head())

print("\nDataFrame Information")
print("-" * 70)
df.info()

print("\nData Description")
print("-" * 70)
print(df.describe(include="all"))

print("\nShape")
print(df.shape)

print("\nColumns")
print(df.columns.tolist())

print("\nData Types")
print(df.dtypes)

print("\nMissing Values")
print(df.isnull().sum())


# Step 7 : Unique Analysis


heading("STEP 7 : UNIQUE ANALYSIS")

print("\nUnique Event Types")
print(df["Event_Type"].value_counts(dropna=False))

print("\nUnique Sub Types")
print(df["Sub_Type"].value_counts(dropna=False))

print("\nNumber of Unique IP Addresses")
print(df["IP_Address"].nunique())

print("\nTop 10 IP Addresses")
print(df["IP_Address"].value_counts().head(10))

print("\nTop 10 Languages")
print(df["Language"].value_counts(dropna=False).head(10))

print("\nTop 10 User Agents")
print(df["User_Agent"].value_counts(dropna=False).head(10))


# Step 8 : Random Inspection

heading("STEP 8 : RANDOM INSPECTION")

random_rows = df.sample(min(10, len(df)))

print(random_rows)

print("\nObservations")
print("-" * 70)

print("1. Multiple visitors accessed the server.")
print("2. Different browsers generated requests.")
print("3. Some entries have missing language values.")
print("4. Some requests are generated automatically.")
print("5. Multiple IP addresses appear repeatedly.")


# Step 9 : Useful Fields


heading("STEP 9 : USEFUL FIELDS")

fields = pd.DataFrame({

    "Field": [

        "Event_Type",
        "Sub_Type",
        "Timestamp",
        "IP_Address",
        "Port",
        "User_Agent",
        "Language",
        "Forwarded_IP"

    ],

    "Purpose": [

        "Type of request",
        "Subtype information",
        "Traffic timeline",
        "Visitor Identification",
        "Connection Port",
        "Browser Analysis",
        "User Language",
        "Original Client IP"

    ]

})

print(fields)


# Step 10 : Convert Timestamp


heading("STEP 10 : DATE CONVERSION")

df["Timestamp"] = pd.to_datetime(
    df["Timestamp"],
    errors="coerce"
)

print(df["Timestamp"].head())


# Step 11 : Save CSV Files


heading("STEP 11 : SAVING OUTPUT")

sample_logs_df = pd.DataFrame(sample_logs)

sample_logs_df.to_csv(
    "output/sample_logs.csv",
    index=False,
    header=["Sample_Log"]
)

df.to_csv(
    "output/extracted_fields.csv",
    index=False
)

print("sample_logs.csv Saved")
print("extracted_fields.csv Saved")

logging.info("CSV Files Saved")


# Step 12 : Generate Report


heading("STEP 12 : REPORT GENERATION")

with open(
        "output/report.txt",
        "w",
        encoding="utf-8"
) as report:

    report.write("=" * 60 + "\n")
    report.write("ACCESS LOG ANALYSIS REPORT\n")
    report.write("=" * 60 + "\n\n")

    report.write(f"Total Records : {len(df)}\n")

    report.write(f"Unique IP Addresses : {df['IP_Address'].nunique()}\n")

    report.write(f"Unique Languages : {df['Language'].nunique()}\n")

    report.write(f"Unique Event Types : {df['Event_Type'].nunique()}\n")

    report.write("\nTop 10 IP Addresses\n")
    report.write(str(df["IP_Address"].value_counts().head(10)))

    report.write("\n\nTop Languages\n")
    report.write(str(df["Language"].value_counts().head(10)))

print("\nReport Saved Successfully")

logging.info("Report Generated")


# Step 13 : Visualization


heading("STEP 13 : VISUALIZATION")

plt.figure(figsize=(10,5))

df["Event_Type"].fillna("NULL").value_counts().plot(
    kind="bar"
)

plt.title("Event Type Frequency")
plt.xlabel("Event Type")
plt.ylabel("Count")
plt.grid(True)

plt.savefig("output/event_type.png")

plt.show()

# ---------------------------------------------------------

plt.figure(figsize=(10,5))

df["IP_Address"].value_counts().head(10).plot(
    kind="bar"
)

plt.title("Top 10 IP Addresses")
plt.xlabel("IP Address")
plt.ylabel("Requests")
plt.grid(True)

plt.savefig("output/top_ip.png")

plt.show()

# ---------------------------------------------------------

plt.figure(figsize=(10,5))

df["Language"].fillna("Unknown").value_counts().head(10).plot(
    kind="bar"
)

plt.title("Top Languages")
plt.xlabel("Language")
plt.ylabel("Count")
plt.grid(True)

plt.savefig("output/language.png")

plt.show()

# ---------------------------------------------------------

plt.figure(figsize=(8,8))

df["Language"].fillna("Unknown").value_counts().head(8).plot(
    kind="pie",
    autopct="%1.1f%%"
)

plt.ylabel("")

plt.title("Language Distribution")

plt.savefig("output/language_pie.png")

plt.show()

# ---------------------------------------------------------

plt.figure(figsize=(10,5))

df["Port"] = pd.to_numeric(df["Port"], errors="coerce")

df["Port"].plot(kind="hist", bins=40)

plt.title("Port Distribution")

plt.xlabel("Port")

plt.grid(True)

plt.savefig("output/port_distribution.png")

plt.show()

# ---------------------------------------------------------

requests_per_day = (
    df.groupby(df["Timestamp"].dt.date)
      .size()
)

plt.figure(figsize=(12,5))

requests_per_day.plot()

plt.title("Requests Over Time")

plt.xlabel("Date")

plt.ylabel("Requests")

plt.grid(True)

plt.savefig("output/requests_over_time.png")

plt.show()

logging.info("Graphs Generated")


# Final Summary


heading("PROJECT COMPLETED")

print(Fore.GREEN + "Log File Successfully Analyzed")

print(Fore.GREEN + f"Total Records : {len(df):,}")

print(Fore.GREEN + f"Unique IPs : {df['IP_Address'].nunique():,}")

print(Fore.GREEN + f"Unique Languages : {df['Language'].nunique():,}")

print(Fore.GREEN + f"Unique Event Types : {df['Event_Type'].nunique():,}")

print("\nGenerated Files")

print("- sample_logs.csv")
print("- extracted_fields.csv")
print("- report.txt")
print("- event_type.png")
print("- top_ip.png")
print("- language.png")
print("- language_pie.png")
print("- port_distribution.png")
print("- requests_over_time.png")

logging.info("Project Completed")

