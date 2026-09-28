# ============================================================
# PRACTICAL 8
# DATA VISUALIZATION AND EXPLORATORY DATA ANALYSIS (EDA)
# ============================================================

import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px


# ============================================================
# 1. PATH CONFIGURATION
# ============================================================

INPUT_FILE = r"D:\PDS PRACTICAL\Practical-6\output\balanced_dataset.csv"

OUTPUT_FOLDER = r"D:\PDS PRACTICAL\Practical-8\output"

os.makedirs(OUTPUT_FOLDER, exist_ok=True)


# ============================================================
# 2. LOAD DATASET
# ============================================================

print("=" * 70)
print("PRACTICAL 8: DATA VISUALIZATION AND EDA")
print("=" * 70)

print("\n[1] Loading balanced dataset...")

df = pd.read_csv(
    INPUT_FILE,
    low_memory=False
)

print("Dataset loaded successfully.")
print("Total records:", len(df))

print("\nDataset columns:")
print(list(df.columns))


# ============================================================
# 3. CONVERT TIMESTAMP
# ============================================================

print("\n[2] Converting timestamp...")

if "timestamp" in df.columns:

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    df = df.dropna(
        subset=["timestamp"]
    )

    print(
        "Valid timestamp records:",
        len(df)
    )

else:

    raise ValueError(
        "timestamp column not found."
    )


# ============================================================
# 4. BASIC EDA
# ============================================================

print("\n" + "=" * 70)
print("BASIC EXPLORATORY DATA ANALYSIS")
print("=" * 70)

print("\nDataset Shape:")
print(df.shape)

print("\nData Types:")
print(df.dtypes)

print("\nMissing Values:")
print(
    df.isnull().sum()
)

print("\nLabel Distribution:")

if "label" in df.columns:

    print(
        df["label"].value_counts()
    )


# ============================================================
# 5. REQUESTS PER HOUR
# ============================================================

print("\n" + "=" * 70)
print("1. REQUESTS PER HOUR")
print("=" * 70)

hourly_requests = (
    df.set_index("timestamp")
    .resample("1h")
    .size()
    .reset_index(name="request_count")
)

print(
    hourly_requests.head(10)
)


# Save data
hourly_requests.to_csv(
    os.path.join(
        OUTPUT_FOLDER,
        "requests_per_hour.csv"
    ),
    index=False
)


# Plot
plt.figure(figsize=(12, 6))

plt.plot(
    hourly_requests["timestamp"],
    hourly_requests["request_count"]
)

plt.title(
    "Requests per Hour"
)

plt.xlabel("Time")
plt.ylabel("Number of Requests")

plt.xticks(rotation=45)

plt.tight_layout()

plt.savefig(
    os.path.join(
        OUTPUT_FOLDER,
        "requests_per_hour.png"
    ),
    dpi=300
)

plt.close()

print(
    "Requests-per-hour graph saved."
)


# ============================================================
# 6. TOP 10 ATTACKING IPs
# ============================================================

print("\n" + "=" * 70)
print("2. TOP 10 ATTACKING IPs")
print("=" * 70)

if (
    "Client-IP-address" in df.columns
    and "label" in df.columns
):

    attack_df = df[
        df["label"]
        .astype(str)
        .str.lower()
        != "benign"
    ]

    top_attack_ips = (
        attack_df[
            "Client-IP-address"
        ]
        .value_counts()
        .head(10)
        .reset_index()
    )

    top_attack_ips.columns = [
        "IP Address",
        "Attack Count"
    ]

    print(
        top_attack_ips
    )

    top_attack_ips.to_csv(
        os.path.join(
            OUTPUT_FOLDER,
            "top_10_attacking_ips.csv"
        ),
        index=False
    )


    # Plot
    plt.figure(figsize=(10, 6))

    sns.barplot(
        data=top_attack_ips,
        x="Attack Count",
        y="IP Address"
    )

    plt.title(
        "Top 10 Attacking IP Addresses"
    )

    plt.xlabel(
        "Number of Attack Records"
    )

    plt.ylabel(
        "IP Address"
    )

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            OUTPUT_FOLDER,
            "top_10_attacking_ips.png"
        ),
        dpi=300
    )

    plt.close()

    print(
        "Top attacking IP graph saved."
    )

else:

    print(
        "Required columns for IP analysis "
        "are not available."
    )


# ============================================================
# 7. ATTACK CATEGORIES OVER TIME
# ============================================================

print("\n" + "=" * 70)
print("3. ATTACK CATEGORIES OVER TIME")
print("=" * 70)

if "label" in df.columns:

    # Remove benign records
    attacks = df[
        df["label"]
        .astype(str)
        .str.lower()
        != "benign"
    ].copy()

    # Group by hour and attack category
    attack_time = (
        attacks
        .set_index("timestamp")
        .groupby(
            "label"
        )
        .resample("1h")
        .size()
        .reset_index(
            name="attack_count"
        )
    )

    print(
        attack_time.head(10)
    )

    attack_time.to_csv(
        os.path.join(
            OUTPUT_FOLDER,
            "attack_categories_over_time.csv"
        ),
        index=False
    )


    # Plot using seaborn
    plt.figure(figsize=(14, 7))

    sns.lineplot(
        data=attack_time,
        x="timestamp",
        y="attack_count",
        hue="label"
    )

    plt.title(
        "Attack Categories Over Time"
    )

    plt.xlabel(
        "Time"
    )

    plt.ylabel(
        "Attack Count"
    )

    plt.xticks(rotation=45)

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            OUTPUT_FOLDER,
            "attack_categories_over_time.png"
        ),
        dpi=300
    )

    plt.close()

    print(
        "Attack categories over time graph saved."
    )

else:

    print(
        "label column not available."
    )


# ============================================================
# 8. STATUS CODE DISTRIBUTION
# ============================================================

print("\n" + "=" * 70)
print("4. STATUS CODE DISTRIBUTION")
print("=" * 70)

# The supplied cj.log dataset does not contain
# an explicit HTTP status-code column.

status_columns = [
    "status",
    "status_code",
    "Status",
    "Status-Code"
]

status_column = None

for column in status_columns:

    if column in df.columns:

        status_column = column
        break


if status_column is not None:

    status_distribution = (
        df[status_column]
        .value_counts()
        .reset_index()
    )

    status_distribution.columns = [
        "Status Code",
        "Count"
    ]

    print(
        status_distribution
    )

    status_distribution.to_csv(
        os.path.join(
            OUTPUT_FOLDER,
            "status_code_distribution.csv"
        ),
        index=False
    )


    plt.figure(figsize=(10, 6))

    sns.barplot(
        data=status_distribution,
        x="Status Code",
        y="Count"
    )

    plt.title(
        "HTTP Status Code Distribution"
    )

    plt.xlabel(
        "Status Code"
    )

    plt.ylabel(
        "Count"
    )

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            OUTPUT_FOLDER,
            "status_code_distribution.png"
        ),
        dpi=300
    )

    plt.close()

else:

    print(
        "Status code column is not available "
        "in the supplied cj.log dataset."
    )

    print(
        "Status-code visualization skipped "
        "instead of creating artificial values."
    )


# ============================================================
# 9. HEATMAP: IP VS REQUEST CATEGORY
# ============================================================

print("\n" + "=" * 70)
print("5. HEATMAP: IP VS REQUEST TYPE")
print("=" * 70)

# The dataset does not have a standard HTTP request-type
# field such as GET/POST.
#
# Therefore category_type is used when available.

if (
    "Client-IP-address" in df.columns
    and "category_type" in df.columns
    and "label" in df.columns
):

    # Select attack traffic
    attack_data = df[
        df["label"]
        .astype(str)
        .str.lower()
        != "benign"
    ].copy()


    # Find top 20 attacking IPs
    top_ips = (
        attack_data[
            "Client-IP-address"
        ]
        .value_counts()
        .head(20)
        .index
    )


    # Keep only top IPs
    heatmap_data = attack_data[
        attack_data[
            "Client-IP-address"
        ].isin(top_ips)
    ]


    # Create pivot table
    heatmap_table = pd.pivot_table(
        heatmap_data,
        index="Client-IP-address",
        columns="category_type",
        values="label",
        aggfunc="count",
        fill_value=0
    )


    print(
        "\nHeatmap table:"
    )

    print(
        heatmap_table
    )


    # Save heatmap data
    heatmap_table.to_csv(
        os.path.join(
            OUTPUT_FOLDER,
            "ip_request_type_heatmap.csv"
        )
    )


    # Plot heatmap
    plt.figure(
        figsize=(14, 9)
    )

    sns.heatmap(
        heatmap_table,
        annot=False,
        cmap="YlOrRd",
        linewidths=0.3
    )

    plt.title(
        "Heatmap of Attacking IPs vs Request Categories"
    )

    plt.xlabel(
        "Request Category"
    )

    plt.ylabel(
        "IP Address"
    )

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            OUTPUT_FOLDER,
            "ip_request_type_heatmap.png"
        ),
        dpi=300
    )

    plt.close()

    print(
        "IP vs request-category heatmap saved."
    )

else:

    print(
        "Required columns for heatmap are not available."
    )


# ============================================================
# 10. LABEL DISTRIBUTION
# ============================================================

print("\n" + "=" * 70)
print("6. LABEL DISTRIBUTION")
print("=" * 70)

if "label" in df.columns:

    label_counts = (
        df["label"]
        .value_counts()
    )

    print(
        label_counts
    )


    plt.figure(
        figsize=(8, 5)
    )

    sns.barplot(
        x=label_counts.index,
        y=label_counts.values
    )

    plt.title(
        "Traffic Label Distribution"
    )

    plt.xlabel(
        "Label"
    )

    plt.ylabel(
        "Number of Records"
    )

    plt.xticks(
        rotation=30
    )

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            OUTPUT_FOLDER,
            "label_distribution.png"
        ),
        dpi=300
    )

    plt.close()


# ============================================================
# 11. USER-AGENT / BOT ANALYSIS
# ============================================================

print("\n" + "=" * 70)
print("7. USER-AGENT / BOT ANALYSIS")
print("=" * 70)

if "is_bot" in df.columns:

    bot_distribution = (
        df["is_bot"]
        .value_counts()
        .reset_index()
    )

    bot_distribution.columns = [
        "Is Bot",
        "Count"
    ]

    print(
        bot_distribution
    )

    bot_distribution.to_csv(
        os.path.join(
            OUTPUT_FOLDER,
            "bot_distribution.csv"
        ),
        index=False
    )


    plt.figure(
        figsize=(7, 5)
    )

    sns.barplot(
        data=bot_distribution,
        x="Is Bot",
        y="Count"
    )

    plt.title(
        "Bot vs Non-Bot Traffic"
    )

    plt.xlabel(
        "Bot"
    )

    plt.ylabel(
        "Number of Records"
    )

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            OUTPUT_FOLDER,
            "bot_distribution.png"
        ),
        dpi=300
    )

    plt.close()

else:

    print(
        "is_bot column is not available."
    )


# ============================================================
# 12. PLOTLY INTERACTIVE VISUALIZATION
# ============================================================

print("\n" + "=" * 70)
print("8. PLOTLY INTERACTIVE VISUALIZATION")
print("=" * 70)

# Create interactive hourly traffic chart

if len(hourly_requests) > 0:

    fig = px.line(
        hourly_requests,
        x="timestamp",
        y="request_count",
        title="Interactive Hourly Network Traffic"
    )

    fig.update_layout(
        xaxis_title="Time",
        yaxis_title="Number of Requests"
    )

    fig.write_html(
        os.path.join(
            OUTPUT_FOLDER,
            "interactive_hourly_traffic.html"
        )
    )

    print(
        "Interactive Plotly graph saved."
    )


# ============================================================
# 13. CREATE EDA REPORT
# ============================================================

print("\n" + "=" * 70)
print("CREATING EDA REPORT")
print("=" * 70)

report_file = os.path.join(
    OUTPUT_FOLDER,
    "practical_8_report.txt"
)

with open(
    report_file,
    "w",
    encoding="utf-8"
) as f:

    f.write(
        "PRACTICAL 8 - DATA VISUALIZATION AND EDA\n"
    )

    f.write("=" * 65 + "\n\n")

    f.write("Objective:\n")

    f.write(
        "To use visualization techniques to understand "
        "the balanced network log dataset.\n\n"
    )

    f.write(
        "Visualizations performed:\n"
    )

    f.write(
        "1. Requests per hour\n"
    )

    f.write(
        "2. Top 10 attacking IP addresses\n"
    )

    f.write(
        "3. Attack categories over time\n"
    )

    f.write(
        "4. Status-code distribution when available\n"
    )

    f.write(
        "5. IP vs request-category heatmap\n"
    )

    f.write(
        "6. Label distribution\n"
    )

    f.write(
        "7. Bot vs non-bot traffic\n"
    )

    f.write(
        "8. Interactive Plotly visualization\n\n"
    )

    f.write(
        "Dataset Limitation:\n"
    )

    f.write(
        "The supplied cj.log dataset does not contain "
        "an explicit HTTP status-code field or standard "
        "HTTP request method field such as GET or POST. "
        "Therefore those visualizations are skipped or "
        "replaced with analysis using available fields.\n\n"
    )

    f.write(
        "Conclusion:\n"
    )

    f.write(
        "Data visualization and EDA helped identify "
        "traffic patterns, attack frequency, temporal "
        "trends, and relationships between IP addresses "
        "and request categories.\n"
    )


# ============================================================
# 14. FINAL MESSAGE
# ============================================================

print("\n" + "=" * 70)
print("PRACTICAL 8 COMPLETED SUCCESSFULLY")
print("=" * 70)

print("\nOutput folder:")
print(OUTPUT_FOLDER)

print("\nGenerated visualizations include:")

print("1. Requests per hour")
print("2. Top 10 attacking IPs")
print("3. Attack categories over time")
print("4. Status code distribution - if available")
print("5. IP vs request category heatmap")
print("6. Label distribution")
print("7. Bot distribution")
print("8. Interactive Plotly visualization")

print("\nEDA report:")
print(
    os.path.join(
        OUTPUT_FOLDER,
        "practical_8_report.txt"
    )
)