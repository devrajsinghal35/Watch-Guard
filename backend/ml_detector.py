import os
import time
from datetime import datetime
import sqlite3
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
import logging

logger = logging.getLogger("sentry.ml")

MODEL_PATH = os.path.join(os.path.dirname(__file__), "sentry_model.pkl")

def extract_login_features(event, history):
    # Extracts simple numeric features from a single login event and its IP history.
    ts = event.get("ts", time.time())
    
    if history:
        last_event = history[-1]
        time_since_last = ts - last_event["ts"]
    else:
        # Safe default for first event from this IP
        time_since_last = 3600.0 
        
    recent_failures = 0
    distinct_usernames_set = set()
    distinct_usernames_set.add(event.get("username", ""))
    
    for h_evt in reversed(history):
        if ts - h_evt["ts"] <= 600:
            if h_evt.get("status") == "failed":
                recent_failures += 1
            distinct_usernames_set.add(h_evt.get("username", ""))
        else:
            # History is sorted, we can break early
            break
            
    distinct_usernames = len(distinct_usernames_set)
    
    try:
        hour = datetime.fromtimestamp(ts).hour
    except Exception:
        hour = 12
        
    return [time_since_last, recent_failures, distinct_usernames, hour]

def train_model(db_path):
    # Fetch historical data
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM login_events ORDER BY ts ASC").fetchall()
    conn.close()
    
    events = [dict(r) for r in rows]
    
    if len(events) < 50:
        logger.warning(f"Insufficient training data ({len(events)} events). Skipping training.")
        return False, {}
        
    history_by_ip = {}
    X = []
    
    # Build feature matrix simulating real-time extraction
    for evt in events:
        sip = evt["source_ip"]
        history = history_by_ip.get(sip, [])
        
        feats = extract_login_features(evt, history)
        X.append(feats)
        
        history.append(evt)
        history_by_ip[sip] = history

    X = np.array(X)
    
    # We evaluate small contamination values since anomalies should be rare.
    # Without ground truth, we pick a small contamination that flags a stable minority group.
    contaminations = [0.05, 0.10, 0.15, 0.20]
    best_contam = 0.10
    
    for c in contaminations:
        clf = IsolationForest(contamination=c, random_state=42)
        preds = clf.fit_predict(X)
        anomalies = np.sum(preds == -1)
        if anomalies > 0:
            best_contam = c
            break
            
    model = IsolationForest(contamination=best_contam, random_state=42)
    model.fit(X)
    
    joblib.dump(model, MODEL_PATH)
    
    results = {
        "events": len(events),
        "contamination": best_contam,
        "anomalies_flagged": np.sum(model.predict(X) == -1)
    }
    return True, results

def predict_anomaly(event_features):
    try:
        model = joblib.load(MODEL_PATH)
    except Exception:
        # Fail gracefully if model is not trained yet
        return 20, False
        
    X = np.array([event_features])
    
    pred = model.predict(X)[0]
    is_anomaly = bool(pred == -1)
    
    score_sample = model.score_samples(X)[0]
    
    # Map the IsolationForest score (-0.5 to 0.5 approx) to our 0-100 scale.
    # Note: This is a deterministic risk score, not a probability.
    if is_anomaly:
        threat_score = min(100, int(70 + abs(score_sample) * 100))
    else:
        threat_score = max(10, int(30 - (score_sample + 0.5) * 40))
        
    return threat_score, is_anomaly
