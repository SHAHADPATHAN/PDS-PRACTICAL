import os
import pandas as pd
from typing import Optional, List
from app.config import BALANCED_DATASET_FILE, PROCESSED_LOGS_FILE
from app.models.schemas import LogRecord, LogsQueryResponse

class DataService:
    def __init__(self):
        self._df = None
        self._load_dataset()

    def _load_dataset(self):
        # We load the 2,604 balanced dataset as primary high-speed searchable index
        # which contains exact representations of all attack categories and benign traffic
        if os.path.exists(BALANCED_DATASET_FILE):
            try:
                self._df = pd.read_csv(BALANCED_DATASET_FILE, low_memory=False)
                # Fill NAs
                self._df["timestamp"] = self._df["timestamp"].fillna("2023-01-08 08:00:00")
                self._df["Client-IP-address"] = self._df["Client-IP-address"].fillna("0.0.0.0")
                self._df["port"] = self._df["port"].fillna(80).astype(str)
                self._df["label"] = self._df["label"].fillna("benign")
                self._df["is_bot"] = self._df["is_bot"].fillna(False).astype(bool)
                self._df["client_type"] = self._df["client_type"].fillna("other")
            except Exception as e:
                print(f"Error loading dataset: {e}")
                self._df = pd.DataFrame()
        else:
            self._df = pd.DataFrame()

    def query_logs(
        self,
        page: int = 1,
        page_size: int = 25,
        search: Optional[str] = None,
        ip: Optional[str] = None,
        label: Optional[str] = None,
        is_bot: Optional[bool] = None,
        client_type: Optional[str] = None
    ) -> LogsQueryResponse:
        if self._df is None or self._df.empty:
            self._load_dataset()

        filtered_df = self._df.copy()

        if ip:
            filtered_df = filtered_df[filtered_df["Client-IP-address"].astype(str).str.contains(ip, case=False, na=False)]

        if label and label.lower() != "all":
            if label.lower() == "attack":
                filtered_df = filtered_df[filtered_df["label"].astype(str).str.lower() != "benign"]
            else:
                filtered_df = filtered_df[filtered_df["label"].astype(str).str.lower() == label.lower()]

        if is_bot is not None:
            filtered_df = filtered_df[filtered_df["is_bot"] == is_bot]

        if client_type and client_type.lower() != "all":
            filtered_df = filtered_df[filtered_df["client_type"].astype(str).str.lower() == client_type.lower()]

        if search:
            search_str = search.lower()
            mask = (
                filtered_df["Client-IP-address"].astype(str).str.lower().str.contains(search_str, na=False) |
                filtered_df["Browser-OS"].astype(str).str.lower().str.contains(search_str, na=False) |
                filtered_df["label"].astype(str).str.lower().str.contains(search_str, na=False) |
                filtered_df["category_type"].astype(str).str.lower().str.contains(search_str, na=False) |
                filtered_df["sub_key"].astype(str).str.lower().str.contains(search_str, na=False)
            )
            filtered_df = filtered_df[mask]

        total_matches = len(filtered_df)
        total_pages = max(1, (total_matches + page_size - 1) // page_size)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size

        page_df = filtered_df.iloc[start_idx:end_idx]

        records: List[LogRecord] = []
        for idx, row in page_df.iterrows():
            records.append(LogRecord(
                id=int(idx) + 1,
                timestamp=str(row.get("timestamp", "")),
                client_ip=str(row.get("Client-IP-address", "")),
                port=str(row.get("port", "")),
                category_type=str(row.get("category_type", "")) if pd.notna(row.get("category_type")) else None,
                sub_key=str(row.get("sub_key", "")) if pd.notna(row.get("sub_key")) else None,
                browser_os=str(row.get("Browser-OS", "")) if pd.notna(row.get("Browser-OS")) else None,
                language=str(row.get("language", "")) if pd.notna(row.get("language")) else None,
                label=str(row.get("label", "benign")),
                is_bot=bool(row.get("is_bot", False)),
                requests_per_ip=int(row.get("requests_per_ip", 0)) if pd.notna(row.get("requests_per_ip")) else 0,
                time_between_requests=float(row.get("time_between_requests", 0.0)) if pd.notna(row.get("time_between_requests")) else 0.0,
                client_type=str(row.get("client_type", "unknown"))
            ))

        return LogsQueryResponse(
            total_matches=total_matches,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            records=records
        )

data_service = DataService()
