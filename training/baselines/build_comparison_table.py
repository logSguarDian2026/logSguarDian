#!/usr/bin/env python3
"""
Assembles the task A34 comparative table from the JSON artifacts written by
train_mlp.py, train_autoencoder.py, train_rf_if_current_split.py,
measure_production_cost.py, and evaluate_test_once.py. Never hand-types a
number — every cell traces back to one of those files.

Usage:
    python3 training/baselines/build_comparison_table.py
"""
import json

from common import RESULTS_OUT

test_results = json.loads((RESULTS_OUT / "test_set_comparison.json").read_text())
mlp_meta = json.loads((RESULTS_OUT / "mlp_metadata.json").read_text())
ae_meta = json.loads((RESULTS_OUT / "autoencoder_metadata.json").read_text())
cost = json.loads((RESULTS_OUT / "production_cost.json").read_text())


def fmt_kb(n_bytes: int) -> str:
    return f"{n_bytes / 1024:.1f} KB" if n_bytes < 1024 * 1024 else f"{n_bytes / 1024 / 1024:.2f} MB"


rf = test_results["rf_v11"]
mlp = test_results["mlp"]
if_ = test_results["if_v10"]
ae = test_results["autoencoder"]

rows = [
    (
        "Random Forest (rf_v11)", "Supervisado",
        f"Macro F1={rf['macro_f1_test']:.4f} (cmdi={rf['per_class_f1_test']['cmdi']:.3f}, "
        f"path_traversal={rf['per_class_f1_test']['path_traversal']:.3f}, "
        f"sqli={rf['per_class_f1_test']['sqli']:.3f}, xss={rf['per_class_f1_test']['xss']:.3f})",
        f"{cost['rf_v11']['p95_ms']:.4f} ms", fmt_kb(cost["rf_v11"]["model_size_bytes"]),
    ),
    (
        "MLP", "Supervisado",
        f"Macro F1={mlp['macro_f1_test']:.4f} (cmdi={mlp['per_class_f1_test']['cmdi']:.3f}, "
        f"path_traversal={mlp['per_class_f1_test']['path_traversal']:.3f}, "
        f"sqli={mlp['per_class_f1_test']['sqli']:.3f}, xss={mlp['per_class_f1_test']['xss']:.3f})",
        f"{mlp_meta['latency_p95_ms']:.4f} ms", fmt_kb(mlp_meta["model_size_bytes"]),
    ),
    (
        "Isolation Forest (if_v10)", "No supervisado",
        f"Recall={if_['recall_test']:.4f}, FP={if_['fp_rate_test']:.4f}",
        f"{cost['if_v10']['p95_ms']:.4f} ms", fmt_kb(cost["if_v10"]["model_size_bytes"]),
    ),
    (
        "Autoencoder", "No supervisado",
        f"Recall={ae['recall_test']:.4f}, FP={ae['fp_rate_test']:.4f}",
        f"{ae_meta['latency_p95_ms']:.4f} ms", fmt_kb(ae_meta["model_size_bytes"]),
    ),
]

print("| Modelo | Tipo | F1/Recall (test, R2 one-time read) | Latencia inferencia (p95) | Tamano modelo serializado |")
print("|--------|------|-------------------------------------|----------------------------|----------------------------|")
for r in rows:
    print("| " + " | ".join(r) + " |")
