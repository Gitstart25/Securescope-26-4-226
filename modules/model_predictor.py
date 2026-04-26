import joblib
import pandas as pd

# ================================
# LOAD MODEL & CWE STATS
# ================================
MODEL_PATH = "model/voting_model.pkl"
CWE_STATS_PATH = "model/cwe_stats.pkl"

model = joblib.load(MODEL_PATH)
cwe_stats = joblib.load(CWE_STATS_PATH)

# ================================
# FEATURE ORDER (MUST MATCH TRAINING)
# ================================
FEATURE_COLUMNS = [
    "alert",
    "attack",
    "evidence",
    "param",
    "wascid",
    "cweid",
    "cwe-id",
    "vulnerability_fingerprint",

    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",

    "cisa_kev",
    "risk"
]

# ================================
# SAFE TEXT NORMALIZER
# ================================
def safe_text(val, default):
    if val is None:
        return default
    val = str(val).strip()
    return val if val else default

# ================================
# FEATURE BUILDER (CRITICAL)
# ================================
def build_feature_row(alert):
    # --- CWE HANDLING ---
    cwe_raw = alert.get("cweid")
    cwe = str(cwe_raw) if cwe_raw not in [None, "", "0"] else "UNKNOWN"

    stats = cwe_stats.get(cwe, cwe_stats.get("UNKNOWN", {}))

    # --- WASC ---
    wascid = str(alert.get("wascid")) if alert.get("wascid") else "WASC-UNKNOWN"

    # --- RISK ---
    risk = safe_text(alert.get("risk"), "Informational")

    return {
        "alert": safe_text(alert.get("alert"), "unknown_alert"),
        "attack": safe_text(alert.get("attack"), "no_attack"),
        "evidence": safe_text(alert.get("evidence"), "no_evidence"),
        "param": safe_text(alert.get("param"), "no_param"),
        "wascid": wascid,

        # BOTH KEPT FOR PIPELINE COMPATIBILITY
        "cweid": cwe,
        "cwe-id": cwe,

        # FINGERPRINT = MAJOR SIGNAL
        "vulnerability_fingerprint": (
            f"ZAP:{safe_text(alert.get('alert'),'alert')} | "
            f"PARAM:{safe_text(alert.get('param'),'none')} | "
            f"CWE:{cwe} | "
            f"RISK:{risk}"
        ),

        # CVSS / CWE STATS
        "attack_vector": stats.get("attack_vector", "NETWORK"),
        "attack_complexity": stats.get("attack_complexity", "LOW"),
        "privileges_required": stats.get("privileges_required", "NONE"),
        "user_interaction": stats.get("user_interaction", "NONE"),
        "scope": stats.get("scope", "UNCHANGED"),
        "confidentiality_impact": stats.get("confidentiality_impact", "LOW"),
        "integrity_impact": stats.get("integrity_impact", "LOW"),
        "availability_impact": stats.get("availability_impact", "LOW"),

        # MUST REMAIN CATEGORICAL
        "cisa_kev": stats.get("cisa_kev", "No"),
        "risk": risk
    }

# ================================
# MAIN PREDICTION FUNCTION
# ================================
def predict_true_positives(mapped_alerts, threshold=0.25):
    rows = [build_feature_row(alert) for alert in mapped_alerts]
    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)

    probs = model.predict_proba(df)[:, 1]

    results = []
    for alert, prob in zip(mapped_alerts, probs):

        # Ignore only pure noise
        if alert.get("risk") == "Informational" and prob < 0.3:
            continue

        if prob >= threshold:
            alert["true_positive_score"] = round(float(prob), 3)
            results.append(alert)

    return results
