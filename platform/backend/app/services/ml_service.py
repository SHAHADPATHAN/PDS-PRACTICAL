import os
import json
import joblib
import pandas as pd
from datetime import datetime, timezone
from typing import Dict, Any, List
from app.config import MODEL_FILE, METADATA_FILE
from app.models.schemas import (
    PredictRequest,
    PredictResponse,
    FeatureEvidence,
    ModelMetricsResponse
)

class MLService:
    def __init__(self):
        self.model = None
        self.metadata = {}
        self._load_model()

    def _load_model(self):
        if os.path.exists(MODEL_FILE):
            try:
                self.model = joblib.load(MODEL_FILE)
            except Exception as e:
                print(f"Failed to load model.joblib: {e}")
                self.model = None

        if os.path.exists(METADATA_FILE):
            try:
                with open(METADATA_FILE, "r") as f:
                    self.metadata = json.load(f)
            except Exception as e:
                print(f"Failed to load metadata: {e}")
                self.metadata = {}

    def get_metrics(self) -> ModelMetricsResponse:
        report = self.metadata.get("classification_report", {})
        attack_metrics = report.get("Attack", {})

        return ModelMetricsResponse(
            model_name=self.metadata.get("model_name", "RandomForestClassifier"),
            model_version=self.metadata.get("model_version", "1.0.0"),
            dataset_source=self.metadata.get("dataset_source", "Practical-6/output/balanced_dataset.csv"),
            training_date=self.metadata.get("training_date", "2026-09-28"),
            total_samples=self.metadata.get("total_samples", 2604),
            train_samples=self.metadata.get("train_samples", 2083),
            test_samples=self.metadata.get("test_samples", 521),
            accuracy=round(float(self.metadata.get("accuracy", 0.9789)), 4),
            precision_attack=round(float(attack_metrics.get("precision", 0.97)), 4),
            recall_attack=round(float(attack_metrics.get("recall", 0.99)), 4),
            f1_attack=round(float(attack_metrics.get("f1-score", 0.98)), 4),
            confusion_matrix=self.metadata.get("confusion_matrix", [[253, 8], [3, 257]]),
            feature_importances=self.metadata.get("feature_importances", {})
        )

    def predict(self, req: PredictRequest) -> PredictResponse:
        if self.model is None or not self.metadata:
            self._load_model()

        feature_names = self.metadata.get("feature_names", [])
        
        # Build 1-row DataFrame with all required columns
        row_dict = {col: 0 for col in feature_names}
        
        # Numeric values
        row_dict["requests_per_ip"] = float(req.requests_per_ip)
        row_dict["time_between_requests"] = float(req.time_between_requests)
        row_dict["user_agent_length"] = int(req.user_agent_length)
        row_dict["unique_user_agents_per_ip"] = int(req.unique_user_agents_per_ip)

        # Categorical values
        client_col = f"client_type_{req.client_type.lower()}"
        if client_col in row_dict:
            row_dict[client_col] = 1
        else:
            other_col = "client_type_other"
            if other_col in row_dict:
                row_dict[other_col] = 1

        bot_col = f"is_bot_{bool(req.is_bot)}"
        if bot_col in row_dict:
            row_dict[bot_col] = 1

        X_input = pd.DataFrame([row_dict])[feature_names]

        # Model Inference
        pred_class = int(self.model.predict(X_input)[0])
        probabilities = self.model.predict_proba(X_input)[0]

        prob_benign = float(probabilities[0])
        prob_attack = float(probabilities[1]) if len(probabilities) > 1 else (1.0 - prob_benign)

        prediction_label = "Attack" if pred_class == 1 else "Benign"
        confidence = prob_attack if pred_class == 1 else prob_benign
        risk_score = int(prob_attack * 100)

        # Explainable Evidence Extraction
        importances = self.metadata.get("feature_importances", {})
        evidence: List[FeatureEvidence] = []

        # Check bot indicator
        if req.is_bot:
            evidence.append(FeatureEvidence(
                feature="is_bot",
                value=True,
                importance=importances.get("is_bot_True", 0.15),
                contribution="Indicates Attack",
                reason="User-Agent signature matches known automated scanner/scraper tool"
            ))

        # Check request frequency
        if req.requests_per_ip > 50:
            evidence.append(FeatureEvidence(
                feature="requests_per_ip",
                value=req.requests_per_ip,
                importance=importances.get("requests_per_ip", 0.14),
                contribution="Indicates Attack",
                reason=f"High request volume ({req.requests_per_ip} requests) characteristic of automated probing"
            ))
        elif req.requests_per_ip <= 10:
            evidence.append(FeatureEvidence(
                feature="requests_per_ip",
                value=req.requests_per_ip,
                importance=importances.get("requests_per_ip", 0.14),
                contribution="Indicates Benign",
                reason=f"Low request volume ({req.requests_per_ip} requests) consistent with regular human browsing"
            ))

        # Check client tool type
        if req.client_type.lower() in ("gobuster", "dirbuster", "command_line_tool"):
            evidence.append(FeatureEvidence(
                feature="client_type",
                value=req.client_type,
                importance=importances.get(f"client_type_{req.client_type.lower()}", 0.12),
                contribution="Indicates Attack",
                reason=f"Client type '{req.client_type}' is a penetration testing or brute-force fuzzing utility"
            ))
        else:
            evidence.append(FeatureEvidence(
                feature="client_type",
                value=req.client_type,
                importance=importances.get(f"client_type_{req.client_type.lower()}", 0.08),
                contribution="Indicates Benign",
                reason=f"Client type '{req.client_type}' represents a standard consumer web browser"
            ))

        # Check time interval
        if req.time_between_requests < 0.2:
            evidence.append(FeatureEvidence(
                feature="time_between_requests",
                value=req.time_between_requests,
                importance=importances.get("time_between_requests", 0.05),
                contribution="Indicates Attack",
                reason=f"Sub-second inter-arrival rate ({req.time_between_requests:.2f}s) indicates automated scripted traffic"
            ))

        return PredictResponse(
            prediction=prediction_label,
            predicted_class=pred_class,
            confidence=round(confidence, 4),
            probabilities={"Benign": round(prob_benign, 4), "Attack": round(prob_attack, 4)},
            risk_score=risk_score,
            evidence=evidence,
            timestamp=datetime.now(timezone.utc).isoformat()
        )

ml_service = MLService()
