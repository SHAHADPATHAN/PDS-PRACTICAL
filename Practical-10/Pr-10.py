# ============================================================
# PRACTICAL 10
# REUSABLE DATA PIPELINE FOR LOG FILE
# ============================================================

import os
import json
import re
import time

import numpy as np
import pandas as pd


# ============================================================
# 1. CONFIGURATION
# ============================================================

INPUT_FILE = r"D:\PDS PRACTICAL\Logs\logs\cj.log"

OUTPUT_FOLDER = r"D:\PDS PRACTICAL\Practical-10\output"

os.makedirs(
    OUTPUT_FOLDER,
    exist_ok=True
)


# ============================================================
# 2. PIPELINE CLASS
# ============================================================

class LogDataPipeline:

    def __init__(self, input_file, output_folder):

        self.input_file = input_file
        self.output_folder = output_folder

        self.df = None

        self.total_lines = 0
        self.parsed_records = 0
        self.invalid_records = 0


    # ========================================================
    # STEP 1: LOAD RAW LOGS
    # ========================================================

    def load_logs(self):

        print("\n" + "=" * 70)
        print("STEP 1: LOADING RAW LOG FILE")
        print("=" * 70)

        if not os.path.exists(self.input_file):

            raise FileNotFoundError(
                f"Log file not found:\n{self.input_file}"
            )

        records = []

        print(
            "Reading:",
            self.input_file
        )

        with open(
            self.input_file,
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                self.total_lines += 1

                line = line.strip()

                if not line:
                    continue

                records.append(line)


        print(
            "Total raw lines:",
            self.total_lines
        )

        print(
            "Non-empty records:",
            len(records)
        )

        return records


    # ========================================================
    # STEP 2: PARSE AND STRUCTURE
    # ========================================================

    def parse_logs(self, records):

        print("\n" + "=" * 70)
        print("STEP 2: PARSING AND STRUCTURING")
        print("=" * 70)

        structured_records = []

        for line in records:

            try:

                data = json.loads(line)

                if not isinstance(data, list):

                    self.invalid_records += 1
                    continue


                # Expected cj.log structure:
                #
                # 0 = Event Type
                # 1 = Sub Type
                # 2 = Timestamp
                # 3 = IP Address
                # 4 = Port
                # 5 = Browser / User-Agent
                # 6 = Language
                # 7 = Forwarded IP / Metadata


                structured_records.append({

                    "category_type":
                        data[0]
                        if len(data) > 0
                        else None,

                    "sub_key":
                        data[1]
                        if len(data) > 1
                        else None,

                    "timestamp":
                        data[2]
                        if len(data) > 2
                        else None,

                    "Client-IP-address":
                        data[3]
                        if len(data) > 3
                        else None,

                    "port":
                        data[4]
                        if len(data) > 4
                        else None,

                    "Browser-OS":
                        data[5]
                        if len(data) > 5
                        else None,

                    "language":
                        data[6]
                        if len(data) > 6
                        else None,

                    "meta-data":
                        data[7]
                        if len(data) > 7
                        else None

                })


            except (
                json.JSONDecodeError,
                TypeError,
                IndexError
            ):

                self.invalid_records += 1


        self.parsed_records = len(
            structured_records
        )


        self.df = pd.DataFrame(
            structured_records
        )


        print(
            "Successfully parsed:",
            self.parsed_records
        )

        print(
            "Invalid records:",
            self.invalid_records
        )

        print(
            "\nStructured columns:"
        )

        print(
            list(self.df.columns)
        )


        return self.df


    # ========================================================
    # STEP 3: LABELING
    # ========================================================

    def label_data(self):

        print("\n" + "=" * 70)
        print("STEP 3: LABELING")
        print("=" * 70)


        # Combine available text fields for pattern detection

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
            if column in self.df.columns
        ]


        # Create lower-case searchable columns

        for column in available_columns:

            self.df[
                column + "_search"
            ] = (
                self.df[column]
                .fillna("")
                .astype(str)
                .str.lower()
            )


        # Initialize all records as benign

        self.df["label"] = "benign"


        # ----------------------------------------------------
        # SQL INJECTION
        # ----------------------------------------------------

        sqli_pattern = (
            r"'(\s*)or(\s*)"
            r"1(\s*)=(\s*)1"
            r"|union(\s+)select"
            r"|drop(\s+)table"
            r"|insert(\s+)into"
            r"|--"
        )


        sqli_mask = np.zeros(
            len(self.df),
            dtype=bool
        )


        for column in available_columns:

            sqli_mask |= (
                self.df[
                    column + "_search"
                ]
                .str.contains(
                    sqli_pattern,
                    regex=True,
                    na=False
                )
            )


        self.df.loc[
            sqli_mask,
            "label"
        ] = "sqli"


        # ----------------------------------------------------
        # PATH TRAVERSAL
        # ----------------------------------------------------

        traversal_pattern = (
            r"\.\./"
            r"|\.\.\\"
            r"%2e%2e"
        )


        traversal_mask = np.zeros(
            len(self.df),
            dtype=bool
        )


        for column in available_columns:

            traversal_mask |= (
                self.df[
                    column + "_search"
                ]
                .str.contains(
                    traversal_pattern,
                    regex=True,
                    na=False
                )
            )


        self.df.loc[
            traversal_mask,
            "label"
        ] = "path_traversal"


        # ----------------------------------------------------
        # BRUTE FORCE
        # ----------------------------------------------------

        login_pattern = (
            r"login"
            r"|signin"
            r"|sign-in"
            r"|password"
            r"|authentication"
            r"|auth"
        )


        login_mask = np.zeros(
            len(self.df),
            dtype=bool
        )


        for column in available_columns:

            login_mask |= (
                self.df[
                    column + "_search"
                ]
                .str.contains(
                    login_pattern,
                    regex=True,
                    na=False
                )
            )


        if "Client-IP-address" in self.df.columns:

            login_ips = (
                self.df.loc[
                    login_mask,
                    "Client-IP-address"
                ]
                .value_counts()
            )


            brute_force_ips = login_ips[
                login_ips >= 5
            ].index


            brute_force_mask = (
                self.df[
                    "Client-IP-address"
                ].isin(
                    brute_force_ips
                )
                & login_mask
            )


            self.df.loc[
                brute_force_mask,
                "label"
            ] = "brute_force"


        # ----------------------------------------------------
        # REMOVE TEMPORARY SEARCH COLUMNS
        # ----------------------------------------------------

        search_columns = [
            column + "_search"
            for column in available_columns
        ]


        self.df.drop(
            columns=search_columns,
            inplace=True
        )


        print(
            "\nLabel distribution:"
        )

        print(
            self.df[
                "label"
            ].value_counts()
        )


    # ========================================================
    # STEP 4: PREPROCESSING
    # ========================================================

    def preprocess(self):

        print("\n" + "=" * 70)
        print("STEP 4: PREPROCESSING")
        print("=" * 70)


        # ----------------------------------------------------
        # TIMESTAMP
        # ----------------------------------------------------

        self.df["timestamp"] = pd.to_datetime(
            self.df["timestamp"],
            errors="coerce"
        )


        # ----------------------------------------------------
        # TEXT NORMALIZATION
        # ----------------------------------------------------

        text_columns = [
            "category_type",
            "sub_key",
            "Browser-OS",
            "language",
            "meta-data"
        ]


        for column in text_columns:

            if column in self.df.columns:

                self.df[column] = (
                    self.df[column]
                    .fillna("unknown")
                    .astype(str)
                    .str.strip()
                    .str.lower()
                )


        # ----------------------------------------------------
        # IP ADDRESS
        # ----------------------------------------------------

        if "Client-IP-address" in self.df.columns:

            self.df[
                "Client-IP-address"
            ] = (
                self.df[
                    "Client-IP-address"
                ]
                .fillna("unknown")
                .astype(str)
                .str.strip()
            )


        # ----------------------------------------------------
        # PORT
        # ----------------------------------------------------

        if "port" in self.df.columns:

            self.df["port"] = pd.to_numeric(
                self.df["port"],
                errors="coerce"
            )

            self.df["port"] = (
                self.df["port"]
                .fillna(0)
            )


        print(
            "Preprocessing completed."
        )


        print(
            "Missing values after preprocessing:"
        )

        print(
            self.df.isna().sum()
        )


    # ========================================================
    # STEP 5: FEATURE ENGINEERING
    # ========================================================

    def feature_engineering(self):

        print("\n" + "=" * 70)
        print("STEP 5: FEATURE ENGINEERING")
        print("=" * 70)


        # ----------------------------------------------------
        # REQUESTS PER IP
        # ----------------------------------------------------

        if "Client-IP-address" in self.df.columns:

            self.df[
                "requests_per_ip"
            ] = (
                self.df[
                    "Client-IP-address"
                ]
                .map(
                    self.df[
                        "Client-IP-address"
                    ].value_counts()
                )
            )

        else:

            self.df[
                "requests_per_ip"
            ] = 0


        # ----------------------------------------------------
        # TIME BETWEEN REQUESTS
        # ----------------------------------------------------

        if (
            "Client-IP-address" in self.df.columns
            and "timestamp" in self.df.columns
        ):

            print(
                "Calculating time between requests..."
            )


            self.df = self.df.sort_values(
                [
                    "Client-IP-address",
                    "timestamp"
                ]
            )


            self.df[
                "time_between_requests"
            ] = (
                self.df
                .groupby(
                    "Client-IP-address"
                )["timestamp"]
                .diff()
                .dt.total_seconds()
            )


            self.df[
                "time_between_requests"
            ] = (
                self.df[
                    "time_between_requests"
                ]
                .fillna(0)
            )

        else:

            self.df[
                "time_between_requests"
            ] = 0


        # ----------------------------------------------------
        # USER AGENT LENGTH
        # ----------------------------------------------------

        if "Browser-OS" in self.df.columns:

            self.df[
                "user_agent_length"
            ] = (
                self.df[
                    "Browser-OS"
                ]
                .fillna("")
                .astype(str)
                .str.len()
            )

        else:

            self.df[
                "user_agent_length"
            ] = 0


        # ----------------------------------------------------
        # UNIQUE USER AGENTS PER IP
        # ----------------------------------------------------

        if (
            "Client-IP-address" in self.df.columns
            and "Browser-OS" in self.df.columns
        ):

            unique_agents = (
                self.df
                .groupby(
                    "Client-IP-address"
                )["Browser-OS"]
                .transform(
                    "nunique"
                )
            )


            self.df[
                "unique_user_agents_per_ip"
            ] = unique_agents

        else:

            self.df[
                "unique_user_agents_per_ip"
            ] = 0


        # ----------------------------------------------------
        # BOT DETECTION
        # ----------------------------------------------------

        if "Browser-OS" in self.df.columns:

            bot_pattern = (
                r"bot|crawler|spider|"
                r"scraper|gobuster|"
                r"dirbuster|curl|wget|"
                r"python-requests"
            )


            self.df[
                "is_bot"
            ] = (
                self.df[
                    "Browser-OS"
                ]
                .fillna("")
                .astype(str)
                .str.lower()
                .str.contains(
                    bot_pattern,
                    regex=True,
                    na=False
                )
            )

        else:

            self.df[
                "is_bot"
            ] = False


        # ----------------------------------------------------
        # CLIENT TYPE
        # ----------------------------------------------------

        if "Browser-OS" in self.df.columns:

            user_agent = (
                self.df[
                    "Browser-OS"
                ]
                .fillna("")
                .astype(str)
                .str.lower()
            )


            self.df[
                "client_type"
            ] = np.select(

                [
                    user_agent.str.contains(
                        "gobuster",
                        na=False
                    ),

                    user_agent.str.contains(
                        "dirbuster",
                        na=False
                    ),

                    user_agent.str.contains(
                        "curl|wget|python-requests",
                        regex=True,
                        na=False
                    ),

                    user_agent.str.contains(
                        "chrome",
                        na=False
                    ),

                    user_agent.str.contains(
                        "firefox",
                        na=False
                    ),

                    user_agent.str.contains(
                        "mozilla",
                        na=False
                    )
                ],

                [
                    "gobuster",
                    "dirbuster",
                    "command_line_tool",
                    "chrome",
                    "firefox",
                    "mozilla"
                ],

                default="other"
            )

        else:

            self.df[
                "client_type"
            ] = "unknown"


        print(
            "\nFeature engineering completed."
        )


        print(
            "\nGenerated features:"
        )


        feature_columns = [
            "requests_per_ip",
            "time_between_requests",
            "user_agent_length",
            "unique_user_agents_per_ip",
            "is_bot",
            "client_type"
        ]


        for column in feature_columns:

            print(
                " -",
                column
            )


    # ========================================================
    # STEP 6: SAVE OUTPUTS
    # ========================================================

    def save_outputs(self):

        print("\n" + "=" * 70)
        print("STEP 6: SAVING OUTPUTS")
        print("=" * 70)


        # ----------------------------------------------------
        # CSV OUTPUT
        # ----------------------------------------------------

        csv_file = os.path.join(
            self.output_folder,
            "processed_logs.csv"
        )


        self.df.to_csv(
            csv_file,
            index=False
        )


        print(
            "\nCSV saved:"
        )

        print(
            csv_file
        )


        # ----------------------------------------------------
        # PARQUET OUTPUT
        # ----------------------------------------------------

        parquet_file = os.path.join(
            self.output_folder,
            "processed_logs.parquet"
        )


        try:

            self.df.to_parquet(
                parquet_file,
                index=False
            )


            print(
                "\nParquet saved:"
            )

            print(
                parquet_file
            )


        except ImportError:

            print(
                "\nPyArrow is not installed."
            )

            print(
                "Install it using:"
            )

            print(
                "pip install pyarrow"
            )


        # ----------------------------------------------------
        # PIPELINE SUMMARY
        # ----------------------------------------------------

        summary_file = os.path.join(
            self.output_folder,
            "pipeline_summary.txt"
        )


        with open(
            summary_file,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                "PRACTICAL 10 - REUSABLE DATA PIPELINE\n"
            )

            file.write(
                "=" * 60 + "\n\n"
            )


            file.write(
                f"Input file: {self.input_file}\n"
            )


            file.write(
                f"Total raw lines: {self.total_lines}\n"
            )


            file.write(
                f"Successfully parsed: {self.parsed_records}\n"
            )


            file.write(
                f"Invalid records: {self.invalid_records}\n"
            )


            file.write(
                f"Final records: {len(self.df)}\n"
            )


            file.write(
                f"Final columns: {len(self.df.columns)}\n"
            )


            file.write(
                "\nPipeline stages:\n"
            )


            file.write(
                "1. Loading logs\n"
            )

            file.write(
                "2. Parsing and structuring\n"
            )

            file.write(
                "3. Labeling\n"
            )

            file.write(
                "4. Preprocessing\n"
            )

            file.write(
                "5. Feature engineering\n"
            )

            file.write(
                "6. Saving CSV and Parquet outputs\n"
            )


            file.write(
                "\nFinal label distribution:\n"
            )


            file.write(
                str(
                    self.df[
                        "label"
                    ].value_counts()
                )
            )


        print(
            "\nPipeline summary saved:"
        )

        print(
            summary_file
        )


    # ========================================================
    # COMPLETE PIPELINE
    # ========================================================

    def run(self):

        start_time = time.time()


        print("\n")
        print("=" * 70)
        print("STARTING REUSABLE LOG DATA PIPELINE")
        print("=" * 70)


        # Step 1
        records = self.load_logs()


        # Step 2
        self.parse_logs(
            records
        )


        # Step 3
        self.label_data()


        # Step 4
        self.preprocess()


        # Step 5
        self.feature_engineering()


        # Step 6
        self.save_outputs()


        elapsed_time = (
            time.time()
            - start_time
        )


        print("\n" + "=" * 70)
        print("PIPELINE COMPLETED SUCCESSFULLY")
        print("=" * 70)


        print(
            f"\nProcessing time: "
            f"{elapsed_time:.2f} seconds"
        )


        print(
            "\nFinal dataset shape:"
        )

        print(
            self.df.shape
        )


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":

    pipeline = LogDataPipeline(
        input_file=INPUT_FILE,
        output_folder=OUTPUT_FOLDER
    )


    pipeline.run()