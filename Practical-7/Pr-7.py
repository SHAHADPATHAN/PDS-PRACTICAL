# ============================================================
# PRACTICAL 7
# Data Wrangling for Aggregated Analysis
# ============================================================

import os
import pandas as pd
import matplotlib.pyplot as plt


# ============================================================
# 1. PATH CONFIGURATION
# ============================================================

INPUT_FILE = r"D:\PDS PRACTICAL\Practical-6\output\balanced_dataset.csv"

OUTPUT_FOLDER = r"D:\PDS PRACTICAL\Practical-7\output"

os.makedirs(OUTPUT_FOLDER, exist_ok=True)


# ============================================================
# 2. LOAD BALANCED DATASET
# ============================================================

print("=" * 70)
print("PRACTICAL 7: DATA WRANGLING & AGGREGATED ANALYSIS")
print("=" * 70)

print("\n[1] Loading balanced dataset...")

df = pd.read_csv(
    INPUT_FILE,
    low_memory=False
)

print("Dataset loaded successfully.")
print("Total records:", len(df))


# ============================================================
# 3. CHECK REQUIRED COLUMNS
# ============================================================

print("\nAvailable columns:")

for column in df.columns:
    print(" -", column)


required_columns = [
    "Client-IP-address",
    "timestamp",
    "label"
]

missing_columns = [
    column for column in required_columns
    if column not in df.columns
]

if missing_columns:
    raise ValueError(
        "Required columns are missing: "
        + ", ".join(missing_columns)
    )


# ============================================================
# 4. CONVERT TIMESTAMP
# ============================================================

print("\n[2] Converting timestamp...")

df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    errors="coerce"
)

invalid_timestamps = df["timestamp"].isna().sum()

print("Invalid timestamps:", invalid_timestamps)


# Remove records where timestamp is unavailable
df = df.dropna(subset=["timestamp"])

print("Records after timestamp cleaning:", len(df))


# ============================================================
# 5. GROUP BY IP - ATTACK FREQUENCY
# ============================================================

print("\n" + "=" * 70)
print("IP-WISE ATTACK FREQUENCY")
print("=" * 70)

# Count total requests for each IP
ip_frequency = (
    df.groupby("Client-IP-address")
    .size()
    .reset_index(name="total_requests")
)

# Count attack records for each IP
attack_df = df[
    df["label"].str.lower() != "benign"
]

ip_attack_frequency = (
    attack_df.groupby("Client-IP-address")
    .size()
    .reset_index(name="attack_count")
)

# Merge total and attack counts
ip_analysis = pd.merge(
    ip_frequency,
    ip_attack_frequency,
    on="Client-IP-address",
    how="left"
)

ip_analysis["attack_count"] = (
    ip_analysis["attack_count"]
    .fillna(0)
    .astype(int)
)

# Calculate attack percentage
ip_analysis["attack_percentage"] = (
    ip_analysis["attack_count"]
    / ip_analysis["total_requests"]
) * 100

# Sort by attack count
ip_analysis = ip_analysis.sort_values(
    "attack_count",
    ascending=False
)

print("\nTop IPs by attack frequency:")

print(
    ip_analysis.head(10).to_string(index=False)
)


# Save IP analysis
ip_analysis.to_csv(
    os.path.join(
        OUTPUT_FOLDER,
        "ip_attack_frequency.csv"
    ),
    index=False
)

print("\nIP attack analysis saved.")


# ============================================================
# 6. TOP ATTACKING IPS GRAPH
# ============================================================

top_ips = ip_analysis.head(10)

plt.figure(figsize=(10, 6))

plt.bar(
    top_ips["Client-IP-address"].astype(str),
    top_ips["attack_count"]
)

plt.title("Top IP Addresses by Attack Frequency")
plt.xlabel("IP Address")
plt.ylabel("Attack Count")
plt.xticks(rotation=45)
plt.tight_layout()

plt.savefig(
    os.path.join(
        OUTPUT_FOLDER,
        "top_attack_ips.png"
    )
)

plt.close()


# ============================================================
# 7. HOURLY TRAFFIC ANALYSIS
# ============================================================

print("\n" + "=" * 70)
print("HOURLY TRAFFIC ANALYSIS")
print("=" * 70)

hourly_traffic = (
    df.set_index("timestamp")
    .resample("1h")
    .size()
    .reset_index(name="request_count")
)

print("\nFirst 10 hourly records:")

print(
    hourly_traffic.head(10).to_string(index=False)
)


# Save hourly traffic
hourly_traffic.to_csv(
    os.path.join(
        OUTPUT_FOLDER,
        "hourly_traffic.csv"
    ),
    index=False
)


# ============================================================
# 8. DAILY TRAFFIC ANALYSIS
# ============================================================

print("\n" + "=" * 70)
print("DAILY TRAFFIC ANALYSIS")
print("=" * 70)

daily_traffic = (
    df.set_index("timestamp")
    .resample("1D")
    .size()
    .reset_index(name="request_count")
)

print("\nDaily traffic:")

print(
    daily_traffic.head(10).to_string(index=False)
)


# Save daily traffic
daily_traffic.to_csv(
    os.path.join(
        OUTPUT_FOLDER,
        "daily_traffic.csv"
    ),
    index=False
)


# ============================================================
# 9. HOURLY ATTACK TRAFFIC
# ============================================================

attack_hourly = (
    attack_df
    .set_index("timestamp")
    .resample("1h")
    .size()
    .reset_index(name="attack_count")
)

attack_hourly.to_csv(
    os.path.join(
        OUTPUT_FOLDER,
        "hourly_attack_traffic.csv"
    ),
    index=False
)


# ============================================================
# 10. DAILY ATTACK TRAFFIC
# ============================================================

attack_daily = (
    attack_df
    .set_index("timestamp")
    .resample("1D")
    .size()
    .reset_index(name="attack_count")
)

attack_daily.to_csv(
    os.path.join(
        OUTPUT_FOLDER,
        "daily_attack_traffic.csv"
    ),
    index=False
)


# ============================================================
# 11. HOURLY TRAFFIC GRAPH
# ============================================================

plt.figure(figsize=(12, 6))

plt.plot(
    hourly_traffic["timestamp"],
    hourly_traffic["request_count"]
)

plt.title("Hourly Network Traffic")
plt.xlabel("Time")
plt.ylabel("Number of Requests")
plt.xticks(rotation=45)
plt.tight_layout()

plt.savefig(
    os.path.join(
        OUTPUT_FOLDER,
        "hourly_traffic.png"
    )
)

plt.close()


# ============================================================
# 12. PIVOT TABLE
# ============================================================

print("\n" + "=" * 70)
print("PIVOT TABLE: REQUEST TYPE BY LABEL")
print("=" * 70)

# The original dataset does not contain a standard
# HTTP request-type column such as GET/POST.
# Therefore category_type is used when available.

if "category_type" in df.columns:

    pivot_table = pd.pivot_table(
        df,
        index="category_type",
        columns="label",
        values="Client-IP-address",
        aggfunc="count",
        fill_value=0
    )

    print("\nPivot Table:")
    print(pivot_table)

    pivot_table.to_csv(
        os.path.join(
            OUTPUT_FOLDER,
            "request_type_label_pivot.csv"
        )
    )

else:

    print(
        "category_type column is not available. "
        "Pivot table skipped."
    )


# ============================================================
# 13. PIVOT TABLE USING SUB KEY
# ============================================================

if "sub_key" in df.columns:

    subkey_pivot = pd.pivot_table(
        df,
        index="sub_key",
        columns="label",
        values="Client-IP-address",
        aggfunc="count",
        fill_value=0
    )

    subkey_pivot.to_csv(
        os.path.join(
            OUTPUT_FOLDER,
            "subkey_label_pivot.csv"
        )
    )

    print("\nSub-key vs Label pivot table saved.")


# ============================================================
# 14. IDENTIFY BOTS
# ============================================================

print("\n" + "=" * 70)
print("BOT FILTERING")
print("=" * 70)

if "is_bot" in df.columns:

    bot_count = df["is_bot"].sum()

    print("Bot records:", bot_count)

    # Remove bot records
    df_without_bots = df[
        df["is_bot"] != True
    ].copy()

else:

    print(
        "is_bot column not found."
    )

    print(
        "Detecting bots using Browser-OS/User-Agent..."
    )

    if "Browser-OS" in df.columns:

        bot_pattern = (
            r"bot|crawler|spider|"
            r"scraper|gobuster|dirbuster|"
            r"curl|wget|python-requests"
        )

        bot_mask = (
            df["Browser-OS"]
            .fillna("")
            .astype(str)
            .str.lower()
            .str.contains(
                bot_pattern,
                regex=True,
                na=False
            )
        )

        df["is_bot"] = bot_mask

        print(
            "Detected bot records:",
            bot_mask.sum()
        )

        df_without_bots = df[
            ~bot_mask
        ].copy()

    else:

        print(
            "Browser-OS column not available."
        )

        df_without_bots = df.copy()


print(
    "Records after bot filtering:",
    len(df_without_bots)
)


# Save bot-filtered data
df_without_bots.to_csv(
    os.path.join(
        OUTPUT_FOLDER,
        "data_without_bots.csv"
    ),
    index=False
)


# ============================================================
# 15. FILTER INTERNAL IPs
# ============================================================

print("\n" + "=" * 70)
print("INTERNAL IP FILTERING")
print("=" * 70)


def is_internal_ip(ip):
    """
    Check common private/internal IPv4 ranges.
    """

    if pd.isna(ip):
        return False

    ip = str(ip).strip()

    parts = ip.split(".")

    if len(parts) != 4:
        return False

    try:
        a, b, c, d = map(int, parts)
    except ValueError:
        return False

    # 10.0.0.0/8
    if a == 10:
        return True

    # 172.16.0.0/12
    if a == 172 and 16 <= b <= 31:
        return True

    # 192.168.0.0/16
    if a == 192 and b == 168:
        return True

    # localhost
    if a == 127:
        return True

    return False


internal_mask = (
    df_without_bots["Client-IP-address"]
    .apply(is_internal_ip)
)

internal_count = internal_mask.sum()

print("Internal IP records:", internal_count)

# Remove internal IPs
external_data = df_without_bots[
    ~internal_mask
].copy()

print(
    "Records after removing internal IPs:",
    len(external_data)
)


# Save final filtered dataset
external_data.to_csv(
    os.path.join(
        OUTPUT_FOLDER,
        "filtered_external_traffic.csv"
    ),
    index=False
)


# ============================================================
# 16. FINAL ATTACK DISTRIBUTION
# ============================================================

print("\n" + "=" * 70)
print("FINAL FILTERED DATASET")
print("=" * 70)

final_label_distribution = (
    external_data["label"]
    .value_counts()
)

print(
    final_label_distribution
)


final_label_distribution.to_csv(
    os.path.join(
        OUTPUT_FOLDER,
        "final_label_distribution.csv"
    ),
    header=["count"]
)


# ============================================================
# 17. CREATE PRACTICAL REPORT
# ============================================================

report_file = os.path.join(
    OUTPUT_FOLDER,
    "practical_7_report.txt"
)

with open(
    report_file,
    "w",
    encoding="utf-8"
) as f:

    f.write(
        "PRACTICAL 7 - DATA WRANGLING\n"
    )

    f.write("=" * 60 + "\n\n")

    f.write("Objective:\n")

    f.write(
        "To aggregate, reshape and filter the balanced "
        "dataset for deeper analysis.\n\n"
    )

    f.write(
        "1. IP-wise Attack Frequency\n"
    )

    f.write(
        "The dataset was grouped by Client-IP-address "
        "to calculate total requests and attack frequency.\n\n"
    )

    f.write(
        "2. Time-Series Analysis\n"
    )

    f.write(
        "Traffic was resampled into hourly and daily "
        "time intervals.\n\n"
    )

    f.write(
        "3. Pivot Table\n"
    )

    f.write(
        "A pivot table was created between category_type "
        "and label when category_type was available.\n\n"
    )

    f.write(
        "4. Bot Filtering\n"
    )

    f.write(
        "Bot traffic was identified using the is_bot field "
        "or User-Agent patterns.\n\n"
    )

    f.write(
        "5. Internal IP Filtering\n"
    )

    f.write(
        "Private IPv4 ranges such as 10.x.x.x, "
        "172.16.x.x-172.31.x.x and 192.168.x.x "
        "were filtered out.\n\n"
    )

    f.write(
        "Conclusion:\n"
    )

    f.write(
        "The balanced dataset was successfully transformed "
        "into aggregated and filtered datasets suitable "
        "for deeper traffic and attack analysis.\n"
    )


# ============================================================
# 18. FINAL OUTPUT
# ============================================================

print("\n" + "=" * 70)
print("PRACTICAL 7 COMPLETED SUCCESSFULLY")
print("=" * 70)

print("\nOutput files:")

output_files = [
    "ip_attack_frequency.csv",
    "hourly_traffic.csv",
    "daily_traffic.csv",
    "hourly_attack_traffic.csv",
    "daily_attack_traffic.csv",
    "request_type_label_pivot.csv",
    "subkey_label_pivot.csv",
    "data_without_bots.csv",
    "filtered_external_traffic.csv",
    "final_label_distribution.csv",
    "top_attack_ips.png",
    "hourly_traffic.png",
    "practical_7_report.txt"
]

for file in output_files:
    print(" -", file)

print("\nOutput folder:")
print(OUTPUT_FOLDER)