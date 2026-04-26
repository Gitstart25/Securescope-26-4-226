import pandas as pd
import os
import json

# -------------------------
# LOAD DATASETS ONCE
# -------------------------

KAGGLE_CVE_PATH = "data/cve_cisa_epss_enriched_dataset.csv"
GLOBAL_CVE_PATH = "data/Global_Dataset.xlsx"

df_kaggle = pd.read_csv(KAGGLE_CVE_PATH)
df_global = pd.read_excel(GLOBAL_CVE_PATH, engine="openpyxl")

# Normalize columns
df_kaggle.columns = df_kaggle.columns.str.strip().str.lower()
df_global.columns = df_global.columns.str.strip().str.lower()

df_kaggle["cve_id"] = df_kaggle["cve_id"].astype(str).str.upper().str.strip()
df_global["cve-id"] = df_global["cve-id"].astype(str).str.upper().str.strip()

df_global["cwe-id"] = (
    df_global["cwe-id"]
    .astype(str)
    .str.replace("CWE-", "", regex=False)
    .str.strip()
)

# Merge Kaggle + Global CVE once
CVE_MASTER = pd.merge(
    df_kaggle,
    df_global,
    left_on="cve_id",
    right_on="cve-id",
    how="left"
)

# -------------------------
# HELPERS
# -------------------------

def normalize_cwe(cwe):
    if not cwe:
        return "NA"
    return str(cwe).replace("CWE-", "").strip()

def json_safe(value):
    if hasattr(value, "item"):
        return value.item()
    return value

def build_vulnerability_fingerprint(row):
    return (
        f"ZAP:{row.get('alert', 'NA')} | "
        f"CWE:{row.get('cweid', 'NA')} | "
        f"CVE:{row.get('cve_id', 'Unknown')} | "
        f"KEV:{row.get('cisa_kev', 'No')} | "
        f"EPSS:{row.get('epss_score', '0.0')}"
    )

# -------------------------
# MAIN MAPPING FUNCTION
# -------------------------

def map_zap_alerts(zap_alerts):
    """
    zap_alerts: list of alerts from ZAP JSON
    returns: list of enriched alerts
    """

    enriched_alerts = []

    for alert in zap_alerts:
        cweid = normalize_cwe(alert.get("cweid"))

        match = CVE_MASTER[CVE_MASTER["cwe-id"] == cweid]

        if not match.empty:
            row = match.iloc[0]

            alert["cweid"] = cweid
            alert["cve_id"] = row.get("cve_id", "Unknown")
            alert["cisa_kev"] = json_safe(row.get("cisa_kev", False))
            alert["epss_score"] = json_safe(row.get("epss_score", 0.0))
            alert["attack_vector"] = str(row.get("attack_vector", "NA"))
            alert["attack_complexity"] = str(row.get("attack_complexity", "NA"))
            alert["privileges_required"] = str(row.get("privileges_required", "NA"))
            alert["user_interaction"] = str(row.get("user_interaction", "NA"))
            alert["scope"] = str(row.get("scope", "NA"))

            alert["confidentiality_impact"] = str(row.get("confidentiality_impact", "NA"))
            alert["integrity_impact"] = str(row.get("integrity_impact", "NA"))
            alert["availability_impact"] = str(row.get("availability_impact", "NA"))


        else:
            alert["cweid"] = cweid
            alert["cve_id"] = "Unknown"
            alert["cisa_kev"] = "No"
            alert["epss_score"] = 0.0

        alert["vulnerability_fingerprint"] = build_vulnerability_fingerprint(alert)

        enriched_alerts.append(alert)
    json.dumps(enriched_alerts)  # will crash early if unsafe
    return enriched_alerts

