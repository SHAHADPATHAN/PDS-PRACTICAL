import os
import sys
import unittest
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from starlette.testclient import TestClient
from app.main import app
from app.config import (
    RAW_LOG_FILE,
    BALANCED_DATASET_FILE,
    MODEL_FILE,
    METADATA_FILE,
    PROCESSED_LOGS_FILE
)

class TestPlatform(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_raw_log_and_artifacts(self):
        """Verify presence of core datasets and model artifacts"""
        self.assertTrue(os.path.exists(RAW_LOG_FILE), "Raw cj.log must exist")
        self.assertTrue(os.path.exists(BALANCED_DATASET_FILE), "Balanced dataset must exist")
        self.assertTrue(os.path.exists(MODEL_FILE), "Saved ML model.joblib must exist")
        self.assertTrue(os.path.exists(METADATA_FILE), "Model metadata must exist")

    def test_02_health_endpoint(self):
        """Test /api/health endpoint"""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "healthy")
        self.assertTrue(data["raw_log_found"])
        self.assertTrue(data["model_loaded"])

    def test_03_analytics_kpis(self):
        """Test /api/analytics/kpis endpoint"""
        res = self.client.get("/api/analytics/kpis")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total_logs"], 2060520)
        self.assertEqual(data["unique_ips"], 16680)
        self.assertGreater(data["attack_count"], 0)
        self.assertGreater(data["benign_count"], 0)

    def test_04_logs_query_pagination_and_filters(self):
        """Test /api/logs/records with pagination and filtering"""
        # Test basic query
        res = self.client.get("/api/logs/records?page=1&page_size=10")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data["records"]), 10)
        self.assertEqual(data["total_matches"], 2604)

        # Test filter by label=sqli
        res_sqli = self.client.get("/api/logs/records?label=sqli&page=1&page_size=10")
        self.assertEqual(res_sqli.status_code, 200)
        data_sqli = res_sqli.json()
        for r in data_sqli["records"]:
            self.assertEqual(r["label"].lower(), "sqli")

        # Test filter by is_bot=true
        res_bot = self.client.get("/api/logs/records?is_bot=true&page=1&page_size=10")
        self.assertEqual(res_bot.status_code, 200)
        data_bot = res_bot.json()
        for r in data_bot["records"]:
            self.assertTrue(r["is_bot"])

    def test_05_model_metrics_and_prediction(self):
        """Test /api/model/metrics and /api/model/predict"""
        # Metrics
        res_m = self.client.get("/api/model/metrics")
        self.assertEqual(res_m.status_code, 200)
        metrics = res_m.json()
        self.assertGreaterEqual(metrics["accuracy"], 0.95)
        self.assertGreaterEqual(metrics["f1_attack"], 0.95)

        # Inference: Attack profile (Gobuster scanner, high frequency, sub-second intervals)
        payload_attack = {
            "requests_per_ip": 150,
            "time_between_requests": 0.02,
            "user_agent_length": 15,
            "unique_user_agents_per_ip": 1,
            "client_type": "gobuster",
            "is_bot": True
        }
        res_p1 = self.client.post("/api/model/predict", json=payload_attack)
        self.assertEqual(res_p1.status_code, 200)
        pred1 = res_p1.json()
        self.assertIn("prediction", pred1)
        self.assertIn("confidence", pred1)
        self.assertIn("evidence", pred1)

        # Inference: Benign profile (Chrome browser, 1 request, human delay)
        payload_benign = {
            "requests_per_ip": 2,
            "time_between_requests": 45.0,
            "user_agent_length": 115,
            "unique_user_agents_per_ip": 1,
            "client_type": "chrome",
            "is_bot": False
        }
        res_p2 = self.client.post("/api/model/predict", json=payload_benign)
        self.assertEqual(res_p2.status_code, 200)
        pred2 = res_p2.json()
        self.assertEqual(pred2["prediction"], "Benign")

    def test_06_ai_analyst_grounded_response(self):
        """Test /api/ai/analyze query groundedness"""
        res = self.client.post("/api/ai/analyze", json={"query": "How many attacks were detected?"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("grounded_stats", data)
        self.assertIn("2,545", data["answer"])  # Real attack count must be mentioned
        self.assertIn("threat_assessment", data)

    def test_07_pipeline_orchestrator(self):
        """Test /api/pipeline/status and trigger"""
        res = self.client.get("/api/pipeline/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data["stages"]), 9)

    def test_08_data_quality_and_exports(self):
        """Test /api/system/quality and file exports"""
        res_q = self.client.get("/api/system/quality")
        self.assertEqual(res_q.status_code, 200)
        self.assertEqual(res_q.json()["valid_records"], 2060520)

        # File export
        res_exp = self.client.get("/api/system/export/balanced")
        self.assertEqual(res_exp.status_code, 200)
        self.assertGreater(len(res_exp.content), 1000)

if __name__ == "__main__":
    unittest.main()
