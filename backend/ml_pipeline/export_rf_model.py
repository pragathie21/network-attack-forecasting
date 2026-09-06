"""
Export trained Scikit-Learn Random Forest model, StandardScaler, and metadata
into an optimized JSON bundle for client-side evaluation in the browser.
"""

import json
import os
import sys
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

# Add backend directory to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.config import settings
from app.ml.preprocessor import preprocess_dataframe, load_feature_columns
from app.ml.mitre_mapper import MITRE_ATTACK_MAPPING

def export_bundle():
    print(f"Loading model from {settings.MODEL_PATH}...")
    model = joblib.load(settings.MODEL_PATH)
    scaler = joblib.load(settings.SCALER_PATH)
    label_encoder = joblib.load(settings.LABEL_ENCODER_PATH)
    feature_cols = load_feature_columns()

    classes = [str(c) for c in label_encoder.classes_]
    n_classes = len(classes)
    n_estimators = len(model.estimators_)

    print(f"Model: {n_estimators} estimators, {n_classes} classes: {classes}")
    print(f"Features: {len(feature_cols)} columns")

    # Export scaler params
    scaler_dict = {
        "mean": [round(float(m), 6) for m in scaler.mean_],
        "scale": [round(float(s), 6) for s in scaler.scale_]
    }

    # Export trees
    # To optimize JSON size:
    # children_left, children_right, feature: integers
    # threshold: round to 5 decimals
    # value: only store for leaf nodes or normalized distribution
    trees = []
    total_nodes = 0
    for i, est in enumerate(model.estimators_):
        t = est.tree_
        n_nodes = t.node_count
        total_nodes += n_nodes

        children_left = t.children_left.tolist()
        children_right = t.children_right.tolist()
        feature = t.feature.tolist()
        threshold = [round(float(th), 5) for th in t.threshold]

        # For leaf nodes, compute normalized probability distribution
        # t.value has shape (n_nodes, 1, n_classes)
        leaf_probs = {}
        for node_idx in range(n_nodes):
            if children_left[node_idx] == -1: # leaf node
                vals = t.value[node_idx, 0]
                s = vals.sum()
                if s > 0:
                    probs = [round(float(v / s), 4) for v in vals]
                else:
                    probs = [round(1.0 / n_classes, 4)] * n_classes
                leaf_probs[node_idx] = probs

        trees.append({
            "left": children_left,
            "right": children_right,
            "feat": feature,
            "th": threshold,
            "leaves": leaf_probs
        })

    print(f"Total nodes across {n_estimators} trees: {total_nodes}")

    bundle = {
        "classes": classes,
        "feature_columns": feature_cols,
        "scaler": scaler_dict,
        "trees": trees,
        "mitre_mapping": MITRE_ATTACK_MAPPING
    }

    # Verify python simulation matches sklearn exactly
    print("Verifying export against sklearn model...")
    test_csv_path = settings.SAMPLE_TEST_CSV
    if test_csv_path.exists():
        df = pd.read_csv(test_csv_path)
        df_proc = preprocess_dataframe(df, feature_cols)
        X_scaled = scaler.transform(df_proc)
        sklearn_probs = model.predict_proba(X_scaled)

        # Pure python inference
        X_test = X_scaled
        py_probs = np.zeros((len(X_test), n_classes), dtype=np.float64)
        for tree_data in trees:
            left = tree_data["left"]
            right = tree_data["right"]
            feat = tree_data["feat"]
            th = tree_data["th"]
            leaves = tree_data["leaves"]

            for row_idx, x in enumerate(X_test):
                curr = 0
                while left[curr] != -1:
                    f = feat[curr]
                    if x[f] <= th[curr]:
                        curr = left[curr]
                    else:
                        curr = right[curr]
                prob = leaves[curr]
                py_probs[row_idx] += prob

        py_probs /= len(trees)

        max_diff = np.max(np.abs(sklearn_probs - py_probs))
        print(f"Max absolute difference between pure Python and sklearn: {max_diff:.6f}")
        assert max_diff < 0.05, f"Validation failed! Max diff {max_diff} is too high."
        print("Validation PASSED! Predictions match scikit-learn.")

    # Save to frontend/src/services/rf_model_bundle.json and rf_model_bundle.js
    frontend_dir = BASE_DIR.parent / "frontend" / "src" / "services"
    frontend_dir.mkdir(parents=True, exist_ok=True)
    out_file = frontend_dir / "rf_model_bundle.json"
    out_js = frontend_dir / "rf_model_bundle.js"

    bundle_json_str = json.dumps(bundle, separators=(",", ":"))

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(bundle_json_str)

    with open(out_js, "w", encoding="utf-8") as f:
        f.write(f"const rfBundle = {bundle_json_str};\nexport default rfBundle;\n")

    size_kb = os.path.getsize(out_file) / 1024
    print(f"Exported model bundle to {out_file} ({size_kb:.1f} KB) and {out_js}")

if __name__ == "__main__":
    export_bundle()
