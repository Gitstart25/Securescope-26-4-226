import pandas as pd
import os

# -----------------------------
# PATH CONFIGURATION (EDIT ONLY THESE)
# -----------------------------

KAGGLE_CVE_PATH = r"C:\Users\Priyanka\Downloads\SecureScope_1-master\SecureScope_1-master\SecureScope\cve_cisa_epss_enriched_dataset.csv"
GLOBAL_CVE_PATH = r"C:\Users\Priyanka\Downloads\SecureScope_1-master\SecureScope_1-master\SecureScope\Global_Dataset.xlsx"
ZAP_SCANS_PATH  = r"C:\Users\Priyanka\Downloads\SecureScope_1-master\SecureScope_1-master\scans\ReWear_scan.csv"
OUTPUT_PATH    = r"C:\Users\Priyanka\Downloads\SecureScope_1-master\SecureScope_1-master\scans\unified_rewear_dataset.csv"

# -----------------------------
# LOAD & CLEAN CVE DATASETS
# -----------------------------

def load_and_merge_cve_datasets(kaggle_path, global_path):
    print("[+] Loading CVE datasets...")

    df_kaggle = pd.read_csv(kaggle_path)
    df_global = pd.read_excel(global_path, engine="openpyxl")

    # Normalize column names
    df_kaggle.columns = df_kaggle.columns.str.strip().str.lower()
    df_global.columns = df_global.columns.str.strip().str.lower()

    # Normalize IDs
    df_kaggle["cve_id"] = df_kaggle["cve_id"].astype(str).str.upper().str.strip()
    df_global["cve-id"] = df_global["cve-id"].astype(str).str.upper().str.strip()

    # Normalize CWE
    df_global["cwe-id"] = (
        df_global["cwe-id"]
        .astype(str)
        .str.replace("CWE-", "", regex=False)
        .str.strip()
    )

    print("[+] Merging Kaggle + Global CVE datasets...")
    merged_cve = pd.merge(
        df_kaggle,
        df_global,
        left_on="cve_id",
        right_on="cve-id",
        how="left"
    )

    return merged_cve


# -----------------------------
# MERGE ZAP SCANS WITH CVE DATA
# -----------------------------

def merge_zap_with_cve(zap_df, cve_df):
    print("[+] Merging ZAP scans with CVE/CWE data...")

    zap_df["cweid"] = (
        zap_df["cweid"]
        .astype(str)
        .str.replace("CWE-", "", regex=False)
        .str.strip()
    )

    cve_df["cwe-id"] = cve_df["cwe-id"].astype(str).str.strip()

    final_df = pd.merge(
        zap_df,
        cve_df,
        left_on="cweid",
        right_on="cwe-id",
        how="left"
    )

    return final_df


# -----------------------------
# CREATE SINGLE MAPPING STRING
# -----------------------------

def build_vulnerability_fingerprint(row):
    return (
        f"ZAP:{row.get('alert', 'NA')} | "
        f"CWE:{row.get('cweid', 'NA')} | "
        f"CVE:{row.get('cve_id', 'Unknown')} | "
        f"KEV:{row.get('cisa_kev', 'No')} | "
        f"EPSS:{row.get('epss_score', '0.0')}"
    )


# -----------------------------
# MAIN EXECUTION
# -----------------------------

def main():
    print("\n========== DATASET MERGING STARTED ==========\n")

    if not os.path.exists(ZAP_SCANS_PATH):
        raise FileNotFoundError("Merged ZAP scans file not found!")

    zap_df = pd.read_csv(ZAP_SCANS_PATH)
    merged_cve_df = load_and_merge_cve_datasets(KAGGLE_CVE_PATH, GLOBAL_CVE_PATH)
    final_df = merge_zap_with_cve(zap_df, merged_cve_df)

    print("[+] Building vulnerability fingerprint...")
    final_df["vulnerability_fingerprint"] = final_df.apply(
        build_vulnerability_fingerprint, axis=1
    )

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    final_df.to_csv(OUTPUT_PATH, index=False)

    print("\n[✓✓✓] FINAL DATASET CREATED SUCCESSFULLY")
    print(f"[✓] Saved at: {OUTPUT_PATH}")
    print("\n============================================\n")


if __name__ == "__main__":
    main()
