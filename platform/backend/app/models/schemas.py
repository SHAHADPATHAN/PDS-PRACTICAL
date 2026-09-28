from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class HealthResponse(BaseModel):
    status: str
    version: str
    raw_log_found: bool
    model_loaded: bool
    total_records: int
    environment: str

class PipelineStageStatus(BaseModel):
    name: str
    status: str  # "completed", "running", "waiting", "failed"
    duration_seconds: float = 0.0
    records_processed: Optional[int] = None
    output_artifact: Optional[str] = None
    details: Optional[str] = None

class PipelineStatusResponse(BaseModel):
    state: str  # "idle", "running", "completed", "failed"
    current_stage: str
    progress_percentage: int
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    elapsed_seconds: float = 0.0
    stages: List[PipelineStageStatus]
    logs: List[str]

class PipelineRunRequest(BaseModel):
    mode: str = "fast"  # "fast" (validates & analyzes processed dataset) or "full" (re-runs 2M rows)
    include_training: bool = True

class LogRecord(BaseModel):
    id: int
    timestamp: Optional[str] = None
    client_ip: Optional[str] = None
    port: Optional[str] = None
    category_type: Optional[str] = None
    sub_key: Optional[str] = None
    browser_os: Optional[str] = None
    language: Optional[str] = None
    label: str = "benign"
    is_bot: bool = False
    requests_per_ip: Optional[int] = None
    time_between_requests: Optional[float] = None
    client_type: Optional[str] = None

class LogsQueryResponse(BaseModel):
    total_matches: int
    page: int
    page_size: int
    total_pages: int
    records: List[LogRecord]

class KPICards(BaseModel):
    total_logs: int
    unique_ips: int
    attack_count: int
    benign_count: int
    attack_percentage: float
    bot_percentage: float
    suspicious_ips_count: int
    last_pipeline_run: str

class TrafficPoint(BaseModel):
    timestamp: str
    request_count: int
    attack_count: int = 0

class AttackCategoryStat(BaseModel):
    category: str
    count: int
    percentage: float
    severity: str

class IPAnalysisRecord(BaseModel):
    ip_address: str
    total_requests: int
    attack_count: int
    attack_percentage: float
    risk_level: str
    attack_types: List[str] = []
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    user_agents: List[str] = []

class AnalyticsOverviewResponse(BaseModel):
    kpis: KPICards
    traffic_timeline: List[TrafficPoint]
    attack_distribution: List[AttackCategoryStat]
    top_suspicious_ips: List[IPAnalysisRecord]
    client_types: Dict[str, int]

class PredictRequest(BaseModel):
    requests_per_ip: float = Field(..., description="Number of requests sent from this IP")
    time_between_requests: float = Field(..., description="Seconds since previous request from this IP")
    user_agent_length: int = Field(..., description="Length of browser/user-agent string")
    unique_user_agents_per_ip: int = Field(..., description="Count of distinct user agents used by this IP")
    client_type: str = Field(default="chrome", description="Client identifier: chrome, firefox, mozilla, gobuster, dirbuster, etc.")
    is_bot: bool = Field(default=False, description="Whether request user agent matches automated scanners")

class FeatureEvidence(BaseModel):
    feature: str
    value: Any
    importance: float
    contribution: str  # "Indicates Attack" or "Indicates Benign"
    reason: str

class PredictResponse(BaseModel):
    prediction: str  # "Attack" or "Benign"
    predicted_class: int  # 1 or 0
    confidence: float
    probabilities: Dict[str, float]
    risk_score: int  # 0 to 100
    evidence: List[FeatureEvidence]
    timestamp: str

class ModelMetricsResponse(BaseModel):
    model_name: str
    model_version: str
    dataset_source: str
    training_date: str
    total_samples: int
    train_samples: int
    test_samples: int
    accuracy: float
    precision_attack: float
    recall_attack: float
    f1_attack: float
    confusion_matrix: List[List[int]]
    feature_importances: Dict[str, float]

class AIAnalysisRequest(BaseModel):
    query: str
    context_type: str = "general"  # "general", "incident", "ip", "prediction"
    target_ip: Optional[str] = None
    target_prediction: Optional[PredictResponse] = None

class AIAnalysisResponse(BaseModel):
    query: str
    answer: str
    grounded_stats: Dict[str, Any]
    threat_assessment: str
    recommended_investigation: List[str]
    mitigation_steps: List[str]
    confidence_level: str
    timestamp: str

class AIMitigationRequest(BaseModel):
    incident_type: str
    ip_address: Optional[str] = None
    requests_per_ip: Optional[float] = None
    client_type: Optional[str] = None

class AIMitigationResponse(BaseModel):
    incident_type: str
    ip_address: Optional[str]
    severity: str
    firewall_rule: str
    waf_rule: str
    immediate_actions: List[str]
    long_term_recommendations: List[str]

class DataQualityResponse(BaseModel):
    total_records: int
    valid_records: int
    invalid_records: int
    valid_rate: float
    missing_values: Dict[str, int]
    timestamp_range: Dict[str, str]
    unique_ips: int
    unique_user_agents: int
    duplicate_records: int

class SystemHealthResponse(BaseModel):
    backend_status: str
    pipeline_state: str
    model_status: str
    artifacts_status: Dict[str, bool]
    disk_usage_mb: float
    uptime_seconds: float
