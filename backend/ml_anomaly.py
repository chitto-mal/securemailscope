from __future__ import annotations


def detect_session_anomalies(sessions):
    """
    Optional local anomaly signal.

    Isolation Forest needs enough comparable observations to be meaningful.
    With fewer than 4 sessions, return an explicit 'insufficient_data' result
    instead of manufacturing an anomaly.
    """
    if len(sessions) < 4:
        return [{
            "session": s["id"],
            "anomaly": False,
            "confidence": 0.0,
            "status": "insufficient_data",
        } for s in sessions]

    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return [{
            "session": s["id"],
            "anomaly": False,
            "confidence": 0.0,
            "status": "dependency_unavailable",
        } for s in sessions]

    features = []
    for s in sessions:
        features.append([
            float(s.get("packets", 0)),
            float(s.get("bytes", 0)),
            float(s.get("tls_record_count", 0)),
            float(s.get("tls_handshake_count", 0)),
            1.0 if s.get("starttls") else 0.0,
            1.0 if s.get("tls_seen") else 0.0,
        ])

    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
    )
    labels = model.fit_predict(features)
    scores = model.decision_function(features)

    output = []
    for session, label, raw_score in zip(sessions, labels, scores):
        confidence = max(0.0, min(1.0, 0.5 - float(raw_score)))
        output.append({
            "session": session["id"],
            "anomaly": bool(label == -1),
            "confidence": round(confidence, 3),
            "status": "analyzed",
        })
    return output
