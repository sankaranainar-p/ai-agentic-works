from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    SEV1 = "SEV-1"
    SEV2 = "SEV-2"
    SEV3 = "SEV-3"
    SEV4 = "SEV-4"


class Category(str, Enum):
    INFRASTRUCTURE = "infrastructure"
    APPLICATION = "application"
    DATABASE = "database"
    NETWORK = "network"
    SECURITY = "security"
    DATA_PIPELINE = "data_pipeline"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    AVAILABILITY = "availability"
    DDOS_ATTACK = "ddos_attack"
    AVAILABILITY_DROP = "availability_drop"
    HTTP_500_SPIKE = "http_500_spike"


class IncidentInput(BaseModel):
    alert_text: str = Field(..., description="Full alert text (title + description combined or raw alert body)")
    source: Optional[str] = Field(None, description="Alert source system (e.g. Datadog, PagerDuty, Splunk)")
    timestamp: Optional[str] = Field(None, description="ISO-8601 timestamp of the alert")


class ClassificationOutput(BaseModel):
    category: Category
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    recommended_action: str = Field(..., description="Primary recommended action")
    runbook: list[str] = Field(..., description="Step-by-step runbook actions")
    route_to: str = Field(..., description="Team to route this incident to")
    auto_remediation: bool = Field(..., description="Whether auto-remediation is available")
    escalation_required: bool = Field(..., description="Whether escalation is required")
    severity_override: bool = Field(False, description="True when post-processing rules upgraded the severity")
    reasoning: Optional[str] = None


class EnsembleOutput(BaseModel):
    llm_result: Optional[ClassificationOutput] = Field(None, description="LLM classifier result; None when LLM is unavailable")
    ml_result: ClassificationOutput
    final_decision: ClassificationOutput
    agreement: bool = Field(..., description="Whether LLM and ML models agreed on category")
    llm_status: str = Field("ok", description="'ok' when LLM ran successfully, 'unavailable' when it failed")
    incident_id: Optional[str] = None


class IncidentRecord(BaseModel):
    id: str
    title: str
    description: str
    category: str
    severity: str
    source: Optional[str] = None
