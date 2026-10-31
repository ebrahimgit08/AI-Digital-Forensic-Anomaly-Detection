# Explainable AI-Based Anomaly Detection and Risk Assessment for Digital Forensic Logs

A complete **college mini-project research prototype** using Python, Streamlit and scikit-learn. It supports BGL structured CSV or raw log upload, feature engineering, Isolation Forest anomaly detection, interactive tables, model score plots, local feature-sensitivity diagnostics, heuristic risk triage, label-based evaluation, and CSV/model export.

## Run on Windows (VS Code PowerShell)

```powershell
cd forensic_full_project
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt --default-timeout=120 --retries=5
python -m streamlit run app.py
```

If activation is blocked, run `.venv\Scripts\python.exe -m pip install -r requirements.txt` and `.venv\Scripts\python.exe -m streamlit run app.py` instead.

Open the localhost URL shown by Streamlit, usually http://localhost:8501. Enable **Use included synthetic demo dataset** and click **Run analysis**, or upload your own `BGL_2k.log_structured.csv` from LogHub. **Synthetic demo data is artificial, not BGL.**

## Project files

- `app.py` — Streamlit dashboard, charts, filters and exports.
- `forensic/pipeline.py` — log parsing, five features, Isolation Forest, evaluation, heuristic triage and local feature sensitivity.
- `data/demo_bgl.csv` — artificial demo records, not real-world evidence.
- `tests/test_pipeline.py` — basic smoke tests.
- `requirements.txt` — Python dependencies.

## Research methodology and limitations

**Features:** message length, word count, count of numeric groups, count of error-related keywords, and frequency of each component in the uploaded dataset. Labels are **never used to train the model**. StandardScaler and Isolation Forest are fitted on the uploaded dataset. `decision_function` scores are lower for more unusual records; negative scores are flagged as anomalies.

**Explainability:** The feature explanation tab is **not SHAP**. It computes a one-feature-at-a-time change in decision score when that feature is replaced by its dataset median. This is an understandable diagnostic but does not provide causal or faithful SHAP attributions. Correlated features can complicate interpretation.

**Risk:** Risk tiers are heuristic review priorities, not probabilities or validated security severity. Only anomalous records receive a tier, using a bottom-5%-score indicator, a keyword indicator, and a log-level indicator.

**Evaluation:** When the BGL `Label` column contains both normal `-` and anomaly (non-`-`) values, the app shows precision, recall, F1 and confusion matrix. Metrics are in-sample descriptive results and do not establish generalization. BGL system anomalies are not necessarily cyberattacks.

**Raw BGL parsing:** BGL raw formats can vary. Prefer `BGL_2k.log_structured.csv` and verify column mapping before relying on raw `.log` results. Forensic-grade processing would additionally require timestamp normalization, evidence provenance, audit logs, integrity hashes, held-out evaluation, and validation of triage criteria.

**Security:** Files are processed locally by the Streamlit Python process. Do not upload sensitive or restricted logs to third-party hosting without permission. Only load trusted joblib files.

## Run tests

```powershell
python -m pytest -q
```

## Next research extensions

- Properly validated SHAP or other model-specific explanation methods.
- Sequence-aware temporal features, parser-derived event templates and richer component context.
- Held-out validation and comparative baselines (e.g. LOF, One-Class SVM).
- Documented, expert-reviewed risk scoring and evidence-handling controls.
