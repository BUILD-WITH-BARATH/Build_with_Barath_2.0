"""Trains a SECOND, SEPARATE anomaly model on real labeled data (not synthetic).

This is deliberately kept apart from the per-subject IsolationForest in app.py
(build_anomaly_model()), which is trained once on synthetic feature vectors and
scores individual subjects' request patterns. That model is unchanged by this
script.

This model instead scores API-ENDPOINT-level access-graph shape: given how many
sessions/users/unique-APIs touch an endpoint, how long between accesses, how
"unique" the access pattern is, etc, is that shape typical or anomalous? It's
trained on real ground-truth labels from a public Kaggle dataset (Tangodelta's
"API security: Access behaviour anomaly dataset"), not synthetic data - a
genuinely different (and more honest) kind of signal than the existing model.

Ground truth vs this app's data: the Kaggle dataset's features (num_sessions,
num_users, num_unique_apis, inter_api_access_duration, api_access_uniqueness,
sequence_length, vsession_duration) describe a THIRD-PARTY API's access graph,
not this app's record/subject model. There is no subject identity, allow/deny
outcome, or object ID in it - it cannot supervise a per-subject risk score.
What it CAN do is teach a classifier what "this endpoint's access graph looks
abnormal" looks like in general, which this app approximates for its own
records via compute_record_graph_features() in app.py (an analogous but not
identical proxy - documented there, not glossed over).

Usage:
    1. Download the dataset yourself (needs a free Kaggle account + API token):
       kaggle datasets download -d tangodelta/api-access-behaviour-anomaly-dataset -p ./data --unzip
    2. python train_endpoint_anomaly_model.py --data-dir ./data
       (writes models/endpoint_anomaly_model.joblib + models/endpoint_anomaly_features.json)
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

NUMERIC_FEATURES = [
    "inter_api_access_duration(sec)",
    "api_access_uniqueness",
    "sequence_length(count)",
    "vsession_duration(min)",
    "num_sessions",
    "num_users",
    "num_unique_apis",
]
CATEGORICAL_FEATURES = ["ip_type", "source"]
LABEL_COLUMN = "classification"

MODELS_DIR = Path(__file__).with_name("models")


def load_dataset(data_dir: Path) -> pd.DataFrame:
    """NOTE on remaining_behavior_ext.csv: its `behavior` column is NOT a clean
    label - it holds "outlier"/"Normal" for most rows but a bot user-agent
    string (e.g. "Googlebot/2.1") for automated-traffic rows instead. The clean
    4-class label is `behavior_type` (outlier / normal / bot / attack). Using
    `behavior` directly (an earlier version of this script did) leaks near-exact
    separability from user-agent strings rather than the real access-graph
    features, producing a suspiciously perfect ROC-AUC. `bot` rows are treated
    as normal here (distinct benign automated-crawler category, not malicious),
    `attack` rows as outliers, matching supervised_dataset.csv's binary scheme.
    """
    frames = []
    for name in ("supervised_dataset.csv", "remaining_behavior_ext.csv"):
        path = data_dir / name
        if not path.exists():
            continue
        df = pd.read_csv(path)
        if LABEL_COLUMN not in df.columns and "behavior_type" in df.columns:
            df[LABEL_COLUMN] = df["behavior_type"].replace({"bot": "normal", "attack": "outlier"})
        frames.append(df)
    if not frames:
        raise FileNotFoundError(
            f"No dataset CSVs found in {data_dir}. Expected supervised_dataset.csv "
            "and/or remaining_behavior_ext.csv from the Kaggle download."
        )
    combined = pd.concat(frames, ignore_index=True)
    combined[LABEL_COLUMN] = combined[LABEL_COLUMN].str.lower()
    combined = combined[combined[LABEL_COLUMN].isin(["normal", "outlier"])]
    combined = combined.dropna(subset=NUMERIC_FEATURES + [LABEL_COLUMN])
    return combined


def train(data_dir: Path) -> None:
    df = load_dataset(data_dir)
    print(f"Loaded {len(df)} labeled rows: {df[LABEL_COLUMN].value_counts().to_dict()}")

    X = df[NUMERIC_FEATURES + CATEGORICAL_FEATURES]
    y = (df[LABEL_COLUMN] == "outlier").astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    preprocess = ColumnTransformer([
        ("num", "passthrough", NUMERIC_FEATURES),
        ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
    ])
    model = Pipeline([
        ("preprocess", preprocess),
        ("classifier", RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42, class_weight="balanced")),
    ])

    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]
    print("\n=== Held-out test performance (real labeled data, not self-graded) ===")
    print(classification_report(y_test, preds, target_names=["normal", "outlier"]))
    print(f"ROC-AUC: {roc_auc_score(y_test, probs):.4f}")

    clf = model.named_steps["classifier"]
    preprocess = model.named_steps["preprocess"]
    feature_names = list(preprocess.transformers_[0][2]) + list(
        preprocess.named_transformers_["cat"].get_feature_names_out()
    )
    importances = sorted(zip(feature_names, clf.feature_importances_), key=lambda x: -x[1])
    print("\n=== Feature importances (read before trusting the AUC above) ===")
    for name, imp in importances:
        print(f"  {imp:.4f}  {name}")
    top_two_share = sum(imp for _, imp in importances[:2])
    if top_two_share > 0.6:
        print(
            f"\nWARNING: top 2 features carry {top_two_share:.0%} of the model's importance. "
            "The near-perfect AUC above is likely dominated by a small number of near-binary "
            "features (e.g. num_users), not a subtle multivariate signal. Report this honestly, "
            "don't quote the raw AUC as evidence of sophisticated detection."
        )

    MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump(model, MODELS_DIR / "endpoint_anomaly_model.joblib")
    (MODELS_DIR / "endpoint_anomaly_features.json").write_text(
        json.dumps({"numeric": NUMERIC_FEATURES, "categorical": CATEGORICAL_FEATURES}, indent=2)
    )
    print(f"\nSaved model to {MODELS_DIR / 'endpoint_anomaly_model.joblib'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=Path("./data"),
                         help="Directory containing the unzipped Kaggle dataset CSVs")
    args = parser.parse_args()
    train(args.data_dir)
