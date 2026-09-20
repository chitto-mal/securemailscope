from __future__ import annotations

SEVERITY_WEIGHT = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 0,
}


def calculate_score(findings, anomaly_signals=None):
    anomaly_signals = anomaly_signals or []
    deterministic_penalty = sum(SEVERITY_WEIGHT.get(f.get("severity"), 0) for f in findings)

    # ML is deliberately bounded so it cannot overwhelm explainable rules.
    anomaly_penalty = 0
    for signal in anomaly_signals:
        if signal.get("anomaly") and signal.get("confidence", 0) >= 0.80:
            anomaly_penalty += 5

    score = max(0, 100 - deterministic_penalty - min(anomaly_penalty, 15))
    level = (
        "CRITICAL" if score < 40
        else "HIGH" if score < 60
        else "MEDIUM" if score < 80
        else "LOW"
    )
    return {
        "score": score,
        "risk_level": level,
        "deterministic_penalty": deterministic_penalty,
        "anomaly_penalty": min(anomaly_penalty, 15),
    }
