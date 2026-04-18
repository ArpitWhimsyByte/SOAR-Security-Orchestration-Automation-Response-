from __future__ import annotations

import random
from datetime import datetime
from typing import Dict, List, Literal

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, field_validator


# =========================
# Data models
# =========================
AlertType = Literal["ip", "url"]


class AlertInput(BaseModel):
    """
    Incoming alert payload.
    type: "ip" or "url"
    value: raw IP or URL string
    """

    type: AlertType
    value: str

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be empty")
        return value


class AlertOutput(BaseModel):
    """
    Explainable response returned to client.
    """

    risk: Literal["HIGH", "MEDIUM", "LOW"]
    action: Literal["block", "monitor", "ignore"]
    reason: List[str]
    blocked_ips: List[str]


class LogEntry(BaseModel):
    """
    Simple in-memory log structure.
    """

    timestamp: str
    alert_type: AlertType
    value: str
    enrichment: Dict[str, int | bool | str]
    frequency: int
    risk_score: int
    risk_label: str
    action: str
    reason: List[str]


# =========================
# In-memory stores
# =========================
# Tracks how often each indicator appears.
alert_frequency: Dict[str, int] = {}

# Tracks blocked IPs in memory.
blocked_ips: List[str] = []

# Stores all actions/log events in memory.
action_logs: List[LogEntry] = []


# =========================
# Enrichment layer
# =========================
def enrich_alert(alert_type: AlertType, value: str) -> Dict[str, int | bool | str]:
    """
    Simulate enrichment for indicators.
    - IP: generate simulated threat score (0-100)
    - URL: generate simulated malicious check + mapped score
    """
    if alert_type == "ip":
        threat_score = random.randint(10, 100)
        return {
            "source": "simulated_ip_threat_feed",
            "threat_score": threat_score,
        }

    # For URL, simulate malicious verdict and map it to a score.
    try:
        # Basic URL normalization/validation.
        parsed_url = HttpUrl(value)
        normalized_url = str(parsed_url)
    except Exception:
        normalized_url = value

    is_malicious = random.choice([True, False, False])  # 33% chance malicious
    threat_score = random.randint(70, 100) if is_malicious else random.randint(5, 40)
    return {
        "source": "simulated_url_scanner",
        "url": normalized_url,
        "is_malicious": is_malicious,
        "threat_score": threat_score,
    }


# =========================
# Decision engine
# =========================
def decide_action(
    alert_type: AlertType, value: str, enrichment: Dict[str, int | bool | str]
) -> Dict[str, int | str | List[str]]:
    """
    Calculate risk score from:
    - threat_score from enrichment
    - frequency count (number of times indicator seen)

    Decision logic:
    - risk_score > 80 => block
    - 50 <= risk_score <= 80 => monitor
    - else => ignore
    """
    frequency = alert_frequency.get(value, 0) + 1
    alert_frequency[value] = frequency

    threat_score = int(enrichment.get("threat_score", 0))
    # Frequency impact is capped to avoid runaway scoring.
    frequency_boost = min(frequency * 8, 30)
    risk_score = min(threat_score + frequency_boost, 100)

    # Build 2-3 short, human-readable explanations.
    reasons: List[str] = []

    if threat_score >= 75:
        reasons.append("High threat score from enrichment.")
    elif threat_score >= 40:
        reasons.append("Moderate threat score from enrichment.")
    else:
        reasons.append("Low threat score from enrichment.")

    if frequency >= 3:
        reasons.append("Multiple attempts detected for this indicator.")
    elif frequency == 2:
        reasons.append("Repeated activity detected for this indicator.")
    else:
        reasons.append("First occurrence of this indicator.")

    if risk_score > 80:
        action = "block"
        risk_label = "HIGH"
        reasons.append("Overall risk is high, so it was blocked.")
    elif risk_score >= 50:
        action = "monitor"
        risk_label = "MEDIUM"
        reasons.append("Risk is medium, so it will be monitored.")
    else:
        action = "ignore"
        risk_label = "LOW"
        reasons.append("Risk is low, so it was ignored.")

    # Keep explanations simple and capped at 3 reasons.
    reasons = reasons[:3]

    return {
        "frequency": frequency,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "action": action,
        "reasons": reasons,
    }


# =========================
# Action engine
# =========================
def execute_action(
    alert_type: AlertType,
    value: str,
    decision: Dict[str, int | str | List[str]],
    enrichment: Dict[str, int | bool | str],
) -> None:
    """
    Perform action side effects:
    - Maintain in-memory blocked IP list
    - Log all actions
    """
    action = str(decision["action"])
    if action == "block" and alert_type == "ip" and value not in blocked_ips:
        blocked_ips.append(value)

    entry = LogEntry(
        timestamp=datetime.utcnow().isoformat() + "Z",
        alert_type=alert_type,
        value=value,
        enrichment=enrichment,
        frequency=int(decision["frequency"]),
        risk_score=int(decision["risk_score"]),
        risk_label=str(decision["risk_label"]),
        action=action,
        reason=list(decision["reasons"]),  # type: ignore[arg-type]
    )
    action_logs.append(entry)


# =========================
# FastAPI app
# =========================
app = FastAPI(title="Minimal SOAR Backend", version="1.0.0")

# Allow local frontend apps (Vite/static) to call the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/alert", response_model=AlertOutput)
def ingest_alert(payload: AlertInput) -> AlertOutput:
    """
    Main ingestion endpoint:
    1) enrich
    2) decide
    3) execute action + log
    4) return explainable response
    """
    enrichment = enrich_alert(payload.type, payload.value)
    decision = decide_action(payload.type, payload.value, enrichment)
    execute_action(payload.type, payload.value, decision, enrichment)

    return AlertOutput(
        risk=str(decision["risk_label"]),  # HIGH / MEDIUM / LOW
        action=str(decision["action"]),  # block / monitor / ignore
        reason=list(decision["reasons"]),  # explainability
        blocked_ips=blocked_ips,
    )


@app.get("/blocked-ips", response_model=List[str])
def get_blocked_ips() -> List[str]:
    """
    Optional helper endpoint to inspect current blocked IPs.
    """
    return blocked_ips


@app.get("/logs", response_model=List[LogEntry])
def get_logs() -> List[LogEntry]:
    """
    Optional helper endpoint to inspect in-memory action logs.
    """
    return action_logs
