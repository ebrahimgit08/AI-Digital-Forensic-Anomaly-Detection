"""BGL parsing, feature engineering, Isolation Forest and descriptive analysis."""
from __future__ import annotations
import io
import re
from dataclasses import dataclass
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

FEATURES = ["message_length", "word_count", "number_count", "error_keywords", "component_frequency"]
KEYWORDS = re.compile(r"\b(?:error|fail|failed|failure|fatal|critical)\b", re.I)


def load_logs(data: bytes, filename: str) -> pd.DataFrame:
    """Read LogHub BGL structured CSV or original whitespace-delimited raw logs."""
    if not data:
        raise ValueError("The selected file is empty.")
    if filename.lower().endswith(".csv"):
        df = pd.read_csv(io.BytesIO(data), low_memory=False)
        columns = {str(c).strip().lower(): c for c in df.columns}
        message_col = next((columns[x] for x in ("content", "message", "logmessage", "text") if x in columns), None)
        if message_col is None:
            raise ValueError("CSV needs a Content or Message column (e.g., BGL_2k.log_structured.csv).")
        result = pd.DataFrame({
            "line_id": df[columns["lineid"]] if "lineid" in columns else np.arange(1, len(df)+1),
            "label": df[columns["label"]] if "label" in columns else pd.Series([None]*len(df)),
            "component": df[columns["component"]] if "component" in columns else "unknown",
            "level": df[columns["level"]] if "level" in columns else "unknown",
            "message": df[message_col],
        })
        if "date" in columns and "time" in columns:
            result["timestamp"] = df[columns["date"]].astype(str) + " " + df[columns["time"]].astype(str)
        elif "timestamp" in columns:
            result["timestamp"] = df[columns["timestamp"]]
        else:
            result["timestamp"] = ""
    elif filename.lower().endswith((".log", ".txt")):
        rows = []
        for idx, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
            parts = line.strip().split(maxsplit=9)
            # Standard LogHub BGL raw format:
            # Label Id Date Code1 Time Code2 Component Level Content
            # Some variants have an additional token before Content.
            if len(parts) < 9:
                continue
            if len(parts) >= 10:
                label, _, date, _, time, _, component, level, extra, message = parts
                # Preserve the entire content when field 8 is actually the start of it.
                message = extra + " " + message
            else:
                label, _, date, _, time, _, component, level, message = parts
            rows.append({"line_id": idx, "label": label, "timestamp": f"{date} {time}",
                         "component": component, "level": level, "message": message})
        result = pd.DataFrame(rows)
    else:
        raise ValueError("Upload a .csv, .log or .txt file.")
    if result.empty:
        raise ValueError("No usable log records were found.")
    result["message"] = result["message"].fillna("").astype(str)
    result["component"] = result["component"].fillna("unknown").astype(str)
    result["level"] = result["level"].fillna("unknown").astype(str)
    result["label"] = result["label"].astype("string").str.strip()
    return result.reset_index(drop=True)


def make_features(logs: pd.DataFrame) -> pd.DataFrame:
    msg = logs["message"].fillna("").astype(str)
    counts = logs["component"].value_counts()
    return pd.DataFrame({
        "message_length": msg.str.len().astype(float),
        "word_count": msg.str.split().str.len().astype(float),
        "number_count": msg.str.count(r"\d+").astype(float),
        "error_keywords": msg.map(lambda s: len(KEYWORDS.findall(s))).astype(float),
        "component_frequency": logs["component"].map(counts).astype(float),
    }).fillna(0.0)


def make_model(contamination: str | float = "auto", trees: int = 100) -> Pipeline:
    return Pipeline([("scaler", StandardScaler()),
                     ("isolation_forest", IsolationForest(n_estimators=trees,
                                                           contamination=contamination,
                                                           random_state=42, n_jobs=-1))])


def reference_labels(logs: pd.DataFrame) -> pd.Series | None:
    """BGL labels: '-' means normal; any nonempty, non-'-' label means anomaly."""
    labels = logs["label"].astype("string").str.strip()
    valid = labels.notna() & labels.ne("")
    if not bool(valid.all()):
        return None
    return labels.ne("-").astype(int)


def risk_assessment(logs: pd.DataFrame) -> pd.DataFrame:
    """Heuristic triage labels, NOT probabilities or validated security severity."""
    result = logs.copy()
    unusual = result["prediction"].eq(-1)
    scores = result["anomaly_score"].to_numpy()
    # Percentile ranks of lower scores: 0 is most unusual.
    rank = pd.Series(scores).rank(pct=True, method="average").to_numpy()
    msg = result["message"].str.lower()
    level = result["level"].str.lower()
    keyword = msg.str.contains(r"\b(?:fatal|critical|panic|failure|failed)\b", regex=True)
    severe_level = level.str.contains(r"fatal|critical|error|severe", regex=True)
    points = (rank <= .05).astype(int) + keyword.astype(int) + severe_level.astype(int)
    result["risk_level"] = np.where(~unusual, "Not flagged", np.where(points >= 2, "High", np.where(points == 1, "Medium", "Low")))
    result["risk_reason"] = np.where(~unusual, "Not flagged by model", "Anomalous model score")
    result.loc[unusual & keyword, "risk_reason"] += "; critical/failure keyword"
    result.loc[unusual & severe_level, "risk_reason"] += "; severe log level"
    result.loc[unusual & (rank <= .05), "risk_reason"] += "; bottom 5% score"
    return result


@dataclass
class Analysis:
    logs: pd.DataFrame
    features: pd.DataFrame
    model: Pipeline
    metrics: dict | None


def analyze(logs: pd.DataFrame, contamination: str | float = "auto", trees: int = 100) -> Analysis:
    if len(logs) < 10:
        raise ValueError("At least 10 log records are required for this demonstration.")
    features = make_features(logs)
    model = make_model(contamination, trees)
    predictions = model.fit_predict(features)
    result = logs.copy()
    result["prediction"] = predictions
    result["anomaly_score"] = model.decision_function(features)
    result["status"] = np.where(predictions == -1, "Anomaly", "Normal")
    result = risk_assessment(result)
    labels = reference_labels(logs)
    metrics = None
    if labels is not None and labels.nunique() == 2:
        y_pred = (predictions == -1).astype(int)
        precision, recall, f1, _ = precision_recall_fscore_support(labels, y_pred, average="binary", zero_division=0)
        metrics = {"precision": float(precision), "recall": float(recall), "f1": float(f1),
                   "confusion_matrix": confusion_matrix(labels, y_pred, labels=[0,1]).tolist(),
                   "reference_anomalies": int(labels.sum())}
    return Analysis(result, features, model, metrics)


def explain_record(analysis: Analysis, index: int) -> pd.DataFrame:
    """One-feature-at-a-time perturbation relative to dataset median.

    Descriptive sensitivity, NOT SHAP and NOT a causal explanation.
    Positive change means replacing the feature with its median increases
    the decision score (makes the record appear less anomalous).
    """
    row = analysis.features.iloc[[index]].copy()
    base = float(analysis.model.decision_function(row)[0])
    medians = analysis.features.median()
    records = []
    for feature in FEATURES:
        changed = row.copy()
        changed.loc[:, feature] = medians[feature]
        new_score = float(analysis.model.decision_function(changed)[0])
        records.append({"feature": feature, "observed": float(row.iloc[0][feature]),
                        "dataset_median": float(medians[feature]),
                        "score_increase_if_replaced": new_score - base})
    return pd.DataFrame(records).sort_values("score_increase_if_replaced", ascending=False)
