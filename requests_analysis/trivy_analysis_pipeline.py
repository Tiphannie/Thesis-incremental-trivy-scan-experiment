import json
import os
from glob import glob
import pandas as pd
import matplotlib.pyplot as plt

# CONFIG
# Define directories and output files
ARTIFACT_DIR_FULL = "artifacts_folder/artifacts_full"
ARTIFACT_DIR_INCREMENTAL = "artifacts_folder/artifacts_incremental"
OUTPUT_CSV_FULL = "scan_analysis_results_full.csv"
OUTPUT_CSV_INCREMENTAL = "scan_analysis_results_incremental.csv"
PLOTS_DIR = "plots"
os.makedirs(PLOTS_DIR, exist_ok=True)

# 1. Extraction Function 
def extract_artifacts_to_csv(artifact_dir, output_csv, scan_type_label):
    data = []
    json_files = glob(f"{artifact_dir}/*.json")
    for jf in json_files:
        sha = os.path.basename(jf).split('-')[-1].split('.')[0]
        with open(jf) as f:
            js = json.load(f)
        vuln_count = 0
        vuln_list = []
        if 'Results' in js and js['Results']:
            for result in js['Results']:
                if 'Vulnerabilities' in result and result['Vulnerabilities']:
                    vuln_count += len(result['Vulnerabilities'])
                    for v in result['Vulnerabilities']:
                        vuln_list.append(v['VulnerabilityID'])
        data.append({
            "commit_sha": sha,
            "vuln_count": vuln_count,
            "vuln_ids": ",".join(vuln_list),
            "source_file": jf,
            "scan_type": scan_type_label
        })

    log_files = glob(f"{artifact_dir}/*.txt")
    log_data = {}
    for lf in log_files:
        sha = os.path.basename(lf).split('-')[-1].split('.')[0]
        duration = None
        skipped = None
        with open(lf) as f:
            for line in f:
                if "Scan duration" in line:
                    duration = int(line.strip().split(':')[-1].strip().replace('s', '').replace('seconds', '').strip())
                if "Scan skipped" in line:
                    skipped = line.strip().split(':')[-1].strip()
        log_data[sha] = {"duration_sec": duration, "skipped": skipped}

    for d in data:
        sha = d['commit_sha']
        if sha in log_data:
            d.update(log_data[sha])
    df = pd.DataFrame(data)
    df.to_csv(output_csv, index=False)
    print(f"✅ CSV extracted to {output_csv}")
    return df

# 2. Process Full and Incremental Data 
df_full = extract_artifacts_to_csv(ARTIFACT_DIR_FULL, OUTPUT_CSV_FULL, "control_full")
df_incremental = extract_artifacts_to_csv(ARTIFACT_DIR_INCREMENTAL, OUTPUT_CSV_INCREMENTAL, "treatment_incremental")

# 3. Recall & False-Negative Calculation
recall_list = []

for idx, row in df_full.iterrows():
    sha = row['commit_sha']
    control_vulns = set(row['vuln_ids'].split(",")) if row['vuln_ids'] else set()
    treatment_row = df_incremental[df_incremental['commit_sha'] == sha]
    if not treatment_row.empty:
        treatment_vulns = set(treatment_row.iloc[0]['vuln_ids'].split(",")) if treatment_row.iloc[0]['vuln_ids'] else set()
        if len(control_vulns) > 0:
            recall = len(treatment_vulns.intersection(control_vulns)) / len(control_vulns)
            fn_rate = len(control_vulns - treatment_vulns) / len(control_vulns)
        else:
            recall = 1.0
            fn_rate = 0.0

        recall_list.append({
            "commit_sha": sha,
            "recall": recall,
            "false_negative_rate": fn_rate,
            "control_vuln_count": len(control_vulns),
            "treatment_vuln_count": len(treatment_vulns),
            "control_duration_sec": row['duration_sec'],
            "treatment_duration_sec": treatment_row.iloc[0]['duration_sec'],
            "scan_skipped": treatment_row.iloc[0]['skipped']
        })

recall_df = pd.DataFrame(recall_list)
recall_df.to_csv("recall_false_negative_analysis.csv", index=False)
print("✅ Recall and false-negative analysis exported to recall_false_negative_analysis.csv")

# 4. Visualization
# a) Recall Plot
plt.figure(figsize=(12, 6))
plt.plot(recall_df['commit_sha'], recall_df['recall'], marker='o', linestyle='-', color='blue')
plt.xticks(rotation=90)
plt.ylabel('Recall')
plt.title('Recall per Commit')
plt.tight_layout()
plt.savefig(f"{PLOTS_DIR}/recall_per_commit.png")

# b) False Negative Rate Plot
plt.figure(figsize=(12, 6))
plt.plot(recall_df['commit_sha'], recall_df['false_negative_rate'], marker='x', linestyle='-', color='red')
plt.xticks(rotation=90)
plt.ylabel('False Negative Rate')
plt.title('False Negative Rate per Commit')
plt.tight_layout()
plt.savefig(f"{PLOTS_DIR}/false_negative_rate_per_commit.png")

# c) Scan Duration Comparison
plt.figure(figsize=(12, 6))
plt.plot(recall_df['commit_sha'], recall_df['control_duration_sec'], marker='o', label='Control (Full Scan)', linestyle='-')
plt.plot(recall_df['commit_sha'], recall_df['treatment_duration_sec'], marker='x', label='Treatment (Incremental/Skip)', linestyle='-')
plt.xticks(rotation=90)
plt.ylabel('Scan Duration (seconds)')
plt.title('Scan Duration per Commit: Control vs Treatment')
plt.legend()
plt.tight_layout()
plt.savefig(f"{PLOTS_DIR}/scan_duration_comparison.png")

print(f"✅ Plots saved to {PLOTS_DIR}/")
print("✅ All analysis complete. Ready for thesis integration.")
