"""SHAP interpretability analysis for rf_v11 (global + local), using the
real production model, real val split, and real feature vectors from the
compiled extractor. See docs/limitations.md sec. 10 for the documented
UA-representation finding this local analysis cross-checks.
"""
import json
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap

REPO = "/Users/diego/Uvg/Proyecto de Graduacion/logSguarDian"
RESULTS = f"{REPO}/training/results"
DROP_COLS = [
    "status_code", "req_count_1s", "req_count_5s", "req_count_60s",
    "error_rate_4xx_60s", "endpoint_diversity_60s",
]
META_COLS = ["sample_id", "label", "timestamp", "_source", "_row_hash"]
CLASS_NAMES = ["benign", "cmdi", "path_traversal", "sqli", "xss"]

rf = joblib.load(f"{REPO}/training/models/rf_v11.pkl")
val = pd.read_parquet(f"{REPO}/training/splits/val.parquet")
y_val = val["label"]
X_val = val.drop(columns=[c for c in DROP_COLS + META_COLS if c in val.columns])
assert list(rf.classes_) == CLASS_NAMES
assert X_val.shape[1] == rf.n_features_in_ == 70

explainer = shap.TreeExplainer(rf)

# ---------- STEP 2: global feature importance per class ----------
shap_values = explainer.shap_values(X_val)  # shape (n, 70, 5)

global_report = {}
for i, cname in enumerate(CLASS_NAMES):
    sv_class = shap_values[:, :, i]
    mean_abs = np.abs(sv_class).mean(axis=0)
    order = np.argsort(mean_abs)[::-1][:10]
    top10 = [(X_val.columns[j], round(float(mean_abs[j]), 5)) for j in order]
    global_report[cname] = top10

    plt.figure()
    shap.summary_plot(
        sv_class, X_val, plot_type="bar", show=False, max_display=10,
    )
    plt.title(f"SHAP global feature importance — {cname}")
    plt.tight_layout()
    plt.savefig(f"{RESULTS}/shap_global_{cname}.png", dpi=150)
    plt.close()

with open(f"{RESULTS}/shap_global_report.json", "w") as f:
    json.dump(global_report, f, indent=2)

print("=== STEP 2: global top-10 features per class ===")
for cname, feats in global_report.items():
    print(f"\n{cname}:")
    for fname, val_ in feats:
        print(f"  {fname:30s} {val_:.5f}")

# ---------- STEP 3: local explanation — /profile UA case ----------
with open("/tmp/profile_no_ua2.json") as f:
    no_ua_raw = json.load(f)
with open("/tmp/profile_with_ua2.json") as f:
    with_ua_raw = json.load(f)

profile_df = pd.DataFrame([no_ua_raw, with_ua_raw])[X_val.columns]
profile_proba = rf.predict_proba(profile_df)
profile_sv = explainer.shap_values(profile_df)  # (2, 70, 5)

print("\n=== STEP 3: /profile UA-ablation local explanation ===")
for row_idx, label in enumerate(["no_ua", "with_ua"]):
    proba = dict(zip(CLASS_NAMES, profile_proba[row_idx]))
    top_class = max(proba, key=proba.get)
    print(f"\n{label}: top_class={top_class}@{proba[top_class]:.3f} full={proba}")
    class_idx = CLASS_NAMES.index(top_class)
    sv_row = profile_sv[row_idx, :, class_idx]
    order = np.argsort(np.abs(sv_row))[::-1][:8]
    print(f"  top SHAP contributors for predicted class '{top_class}':")
    for j in order:
        print(f"    {X_val.columns[j]:25s} shap={sv_row[j]:+.4f} value={profile_df.iloc[row_idx, j]}")

    plt.figure()
    shap.force_plot(
        explainer.expected_value[class_idx],
        sv_row,
        profile_df.iloc[row_idx],
        matplotlib=True,
        show=False,
    )
    plt.savefig(f"{RESULTS}/shap_local_profile_{label}.png", dpi=150, bbox_inches="tight")
    plt.close()

# ---------- STEP 4: local explanation — real detected attack (E2E fixture) ----------
import subprocess

extract_script = f"""
const {{ extractFeatures }} = require('{REPO}/packages/extractor/dist/index.js');
const fs = require('fs');
const lines = fs.readFileSync('{REPO}/e2e/fixtures/test_payloads.jsonl', 'utf-8').trim().split('\\n');
let picked = null;
for (const line of lines) {{
  const rec = JSON.parse(line);
  if (rec.label === 'sqli') {{ picked = rec; break; }}
}}
const feats = extractFeatures({{
  method: picked.method, path: picked.path, query: picked.query || '',
  body: picked.body || '', userAgent: picked.userAgent || '',
  contentType: picked.contentType || '', referer: picked.referer || '',
  cookie: picked.cookie || '', extraHeaders: picked.extraHeaders || {{}},
}});
fs.writeFileSync('/tmp/attack_case.json', JSON.stringify({{ request: picked, features: feats }}));
"""
with open("/tmp/extract_attack_case.js", "w") as f:
    f.write(extract_script)
subprocess.run(["node", "/tmp/extract_attack_case.js"], check=True)

with open("/tmp/attack_case.json") as f:
    attack_case = json.load(f)

attack_df = pd.DataFrame([attack_case["features"]])[X_val.columns]
attack_proba = rf.predict_proba(attack_df)[0]
attack_sv = explainer.shap_values(attack_df)[0]  # (70, 5)

print("\n=== STEP 4: real detected sqli attack — local explanation ===")
print(f"request path: {attack_case['request']['path'][:120]}")
proba_dict = dict(zip(CLASS_NAMES, attack_proba))
top_class = max(proba_dict, key=proba_dict.get)
print(f"predicted: top_class={top_class}@{proba_dict[top_class]:.3f} full={proba_dict}")
class_idx = CLASS_NAMES.index(top_class)
sv_row = attack_sv[:, class_idx]
order = np.argsort(np.abs(sv_row))[::-1][:8]
for j in order:
    print(f"  {X_val.columns[j]:25s} shap={sv_row[j]:+.4f} value={attack_df.iloc[0, j]}")

plt.figure()
shap.force_plot(
    explainer.expected_value[class_idx],
    sv_row,
    attack_df.iloc[0],
    matplotlib=True,
    show=False,
)
plt.savefig(f"{RESULTS}/shap_local_attack_sqli.png", dpi=150, bbox_inches="tight")
plt.close()

print("\nDone. PNGs + shap_global_report.json written to training/results/")
