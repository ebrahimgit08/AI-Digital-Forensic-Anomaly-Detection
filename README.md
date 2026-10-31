# AI-Based Anomaly Detection and Risk Assessment for Digital Forensic Logs

An explainable AI-based prototype for detecting unusual patterns in digital forensic logs using Isolation Forest, feature-sensitivity analysis, and rule-based risk assessment.

## Project Overview

Digital systems generate large volumes of log records. Manually analysing these records can be time-consuming, making it difficult to identify unusual system behaviour efficiently.

This project aims to simplify log analysis by developing an interactive application that processes digital forensic logs, identifies anomalous records, provides feature-sensitivity explanations, and assigns risk categories to flagged events.

The application is developed using Python and Streamlit.

## Key Features

- **Log Processing:** Supports structured BGL CSV files and compatible raw log inputs.
- **Feature Engineering:** Extracts five numerical features from log records.
- **Anomaly Detection:** Uses the Isolation Forest algorithm to identify unusual records.
- **Feature Explanations:** Performs median-based feature-sensitivity analysis to inspect changes in model decision scores.
- **Risk Assessment:** Assigns Low, Medium, and High risk categories using rule-based conditions.
- **Interactive Dashboard:** Displays anomaly distributions, decision scores, searchable log records, and analysis results.
- **Model Evaluation:** Calculates a confusion matrix, precision, recall, and F1-score when suitable reference labels are available.
- **Data Export:** Supports downloading analysis results and extracted features as CSV files and exporting the fitted model.

## Technologies Used

- Python
- Streamlit
- Scikit-learn
- Pandas
- NumPy
- Matplotlib / Plotly (as used in the application)
- Joblib

## System Architecture

The application follows this workflow:

1. Upload digital forensic log data.
2. Parse and preprocess the records.
3. Extract numerical features.
4. Train the Isolation Forest model.
5. Generate anomaly predictions and decision scores.
6. Perform feature-sensitivity analysis.
7. Assign rule-based risk categories.
8. Evaluate predictions against reference labels when available.
9. Visualise and export the results.

## Features Used for Anomaly Detection

The current implementation extracts five numerical features:

| Feature | Description |
|---|---|
| Message Length | Number of characters in the log message |
| Word Count | Number of words in the message |
| Number Count | Number of numerical values in the message |
| Error Keywords | Count of selected error-related keywords |
| Component Frequency | Frequency of the corresponding component in the dataset |

These features are supplied to the Isolation Forest model.

## Machine Learning Algorithm

### Isolation Forest

Isolation Forest is an unsupervised anomaly detection algorithm.

It identifies unusual observations by isolating them through randomly constructed decision trees. Observations that are easier to isolate are considered more anomalous.

The application uses the model's decision scores to distinguish between normal and anomalous records.

### Explainability

The application uses median-based feature-sensitivity analysis.

It replaces individual feature values with their corresponding dataset medians and observes the resulting changes in the model's decision scores.

This helps inspect how individual numerical features influence a particular prediction.

**Note:** This implementation is a feature-sensitivity approach, not a SHAP implementation.

### Risk Assessment

The application assigns risk categories to flagged records using three rule-based conditions:

- Relative anomaly-score ranking.
- Selected critical and failure-related keywords.
- Severity indicators in the log records.

Records are assigned Low, Medium, or High risk categories according to the implemented rules.

These categories are investigation priorities, not calibrated probabilities of malicious activity.

## Experimental Results

The application was evaluated using the `BGL_2k.log_structured.csv` dataset containing 2,000 records.

### Anomaly Detection Results

| Category | Records |
|---|---:|
| Total Records | 2,000 |
| Normal Predictions | 1,467 |
| Anomaly Predictions | 533 |
| Flagged Percentage | 26.6% |

### Evaluation Metrics

| Metric | Result |
|---|---:|
| Accuracy | 76.7% |
| Precision | 19.7% |
| Recall | 73.4% |
| F1-score | 0.311 |

### Confusion Matrix

| | Predicted Normal | Predicted Anomaly |
|---|---:|---:|
| Actual Normal | 1,429 | 428 |
| Actual Anomaly | 38 | 105 |

**Evaluation limitation:** The current implementation fits and evaluates the model on the same uploaded records. Therefore, these are in-sample results and should not be interpreted as independent performance on unseen data.

The relatively low precision indicates that many flagged records do not match the reference anomaly labels. Further investigation and model improvements are required.

## Project Structure

```text
forensic_full_project/
│
├── app.py
├── requirements.txt
├── README.md
│
├── forensic/
│   ├── __init__.py
│   └── pipeline.py
│
├── data/
│   └── demo_bgl.csv
│
├── outputs/
│
└── tests/
    └── test_pipeline.py
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/AI-Digital-Forensic-Anomaly-Detection.git
```

### 2. Navigate into the project

```bash
cd AI-Digital-Forensic-Anomaly-Detection
```

### 3. Create a virtual environment

```bash
python -m venv .venv
```

### 4. Activate the environment

Windows:

```bash
.venv\Scripts\activate
```

### 5. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 6. Run the application

```bash
python -m streamlit run app.py
```

Open the local Streamlit URL displayed in the terminal.

Upload a compatible structured BGL CSV file or raw BGL log file to begin analysis.

## Limitations

- The current model uses five numerical features and does not fully understand log-message semantics.
- Feature explanations use median-based sensitivity analysis rather than SHAP.
- Risk categories are based on heuristic rules.
- Current evaluation uses the same records for model fitting and evaluation.
- An anomaly does not necessarily indicate malicious activity.
- Predictions require contextual interpretation and human investigation.

## Future Improvements

- Incorporate semantic text representations.
- Introduce temporal and event-sequence features.
- Evaluate the model using separate training and testing datasets.
- Investigate methods to improve precision while maintaining useful recall.
- Implement and validate more advanced explainability techniques such as SHAP.
- Improve risk assessment using validated risk criteria.
- Explore additional anomaly detection algorithms for comparison.

## Contributors

- Mohammed Ebrahim Khan
- Sandesh Hiremath
- Vivek B H
- Shushant

## Project Context

Academic mini-project developed under the Artificial Intelligence and Data Science department.

**Disclaimer:** This project is an academic research prototype intended for log analysis and anomaly detection. It does not independently establish malicious activity or replace professional digital forensic investigation.
