"""Run with: python -m streamlit run app.py"""
import io
import joblib
import pandas as pd
import plotly.express as px
import streamlit as st
from forensic.pipeline import analyze, explain_record, load_logs, FEATURES

st.set_page_config(page_title="Forensic Log Intelligence", page_icon="🔎", layout="wide")
st.markdown("""<style>
.block-container {padding-top: 1.5rem; max-width: 1450px}
[data-testid="stMetric"] {background: #f3f6fa; padding: 15px; border-radius: 12px}
</style>""", unsafe_allow_html=True)
st.title("🔎 Digital Forensic Log Intelligence")
st.caption("Explainable AI-Based Anomaly Detection & Risk Assessment ")
st.info(
        "A flagged anomaly is not proof of an attack. Risk tiers are not calibrated security probabilities.")

with st.sidebar:
    st.header("Data & model")
    upload = st.file_uploader("Upload BGL structured CSV or raw log", type=["csv", "log", "txt"])
    demo = st.checkbox("Use included synthetic demo dataset", value=False, disabled=upload is not None)
    contamination_choice = st.selectbox("Anomaly threshold", ["auto", "1%", "3%", "5%", "10%"], index=0,
        help="For fixed percentages, Isolation Forest adjusts its threshold to approximately the selected fraction.")
    trees = st.slider("Isolation trees", 50, 300, 100, step=50)
    run = st.button("Run analysis", type="primary", use_container_width=True)
    st.caption("Model fits to the uploaded dataset for each run. No external server or cloud API is required.")

if run:
    if upload is None and not demo:
        st.warning("Upload a dataset or enable the synthetic demo dataset.")
    else:
        try:
            if upload is not None:
                logs = load_logs(upload.getvalue(), upload.name)
            else:
                with open("data/demo_bgl.csv", "rb") as f:
                    logs = load_logs(f.read(), "demo_bgl.csv")
            contamination = "auto" if contamination_choice == "auto" else float(contamination_choice.strip("%"))/100
            with st.spinner("Extracting features and training Isolation Forest..."):
                st.session_state["analysis"] = analyze(logs, contamination=contamination, trees=trees)
                st.session_state["dataset_name"] = upload.name if upload else "SYNTHETIC DEMO DATA"
        except Exception as exc:
            st.error(f"Analysis failed: {exc}")

if "analysis" not in st.session_state:
    st.subheader("Get started")
    st.write("Upload `BGL_2k.log_structured.csv` from LogHub, or select the included synthetic demonstration data. Then click **Run analysis**.")
    st.write("The app provides overview statistics, interactive log exploration, anomaly scores, per-record feature sensitivity, heuristic risk triage, evaluation (when labels are available), and CSV/model exports.")
    st.stop()

a = st.session_state["analysis"]
df = a.logs
st.caption(f"Dataset: **{st.session_state['dataset_name']}** · {len(df):,} records")
total = len(df)
anomalies = int((df["prediction"] == -1).sum())
normal = total - anomalies
c1,c2,c3,c4 = st.columns(4)
c1.metric("Total logs", f"{total:,}")
c2.metric("Normal", f"{normal:,}")
c3.metric("Anomalies", f"{anomalies:,}")
c4.metric("Flagged percentage", f"{100*anomalies/total:.1f}%")

tabs = st.tabs(["Overview", "Log explorer", "Feature explanations", "Risk triage", "Evaluation", "Export & methods"])
with tabs[0]:
    left,right = st.columns(2)
    with left:
        counts = df["status"].value_counts().rename_axis("Status").reset_index(name="Count")
        st.plotly_chart(px.pie(counts, names="Status", values="Count", title="Detected status distribution", hole=.45), use_container_width=True)
    with right:
        st.plotly_chart(px.histogram(df, x="anomaly_score", color="status", nbins=40,
                      title="Isolation Forest decision scores"), use_container_width=True)
    st.subheader("Most unusual records")
    st.dataframe(df.nsmallest(10, "anomaly_score")[["line_id","component","level","message","anomaly_score","risk_level"]],
                 use_container_width=True, hide_index=True)

with tabs[1]:
    st.subheader("Search and filter records")
    status_filter = st.multiselect("Detection status", ["Normal", "Anomaly"], default=["Normal", "Anomaly"])
    query = st.text_input("Search message or component", "")
    view = df[df["status"].isin(status_filter)]
    if query:
        view = view[view["message"].str.contains(query, case=False, regex=False) |
                    view["component"].str.contains(query, case=False, regex=False)]
    st.caption(f"Showing {len(view):,} records")
    st.dataframe(view, use_container_width=True, hide_index=True, height=450)

with tabs[2]:
    st.subheader("Why was a record unusual?")
    st.write("**One-feature-at-a-time sensitivity:** replace a feature with its dataset median and observe how the model score changes. "
             "A positive increase means that replacement makes the record appear less unusual. "
             "This is a local diagnostic heuristic, **not SHAP**, causal attribution, or a proof of malicious behavior.")
    flagged = df.index[df["prediction"].eq(-1)].tolist()
    choices = flagged if flagged else df.index.tolist()
    idx = st.selectbox("Choose a record (row index)", choices, format_func=lambda i: f"Row {i+1} | {str(df.iloc[i]['message'])[:85]}")
    st.code(str(df.iloc[idx]["message"]), language="text")
    exp = explain_record(a, idx)
    st.dataframe(exp, use_container_width=True, hide_index=True)
    st.plotly_chart(px.bar(exp, x="score_increase_if_replaced", y="feature", orientation="h",
                           title="Decision-score change when feature is replaced with median"), use_container_width=True)

with tabs[3]:
    st.subheader("Heuristic risk triage")
    st.warning("Risk tiers are simple rules for prioritizing review, **not validated threat severity or attack probabilities**.")
    flagged_df = df[df["prediction"].eq(-1)]
    if flagged_df.empty:
        st.info("No records flagged by the current threshold.")
    else:
        risk_counts = flagged_df["risk_level"].value_counts().rename_axis("Risk").reset_index(name="Count")
        st.plotly_chart(px.bar(risk_counts, x="Risk", y="Count", title="Flagged records by triage tier"), use_container_width=True)
        st.dataframe(flagged_df.sort_values("anomaly_score")[["line_id","component","level","message","anomaly_score","risk_level","risk_reason"]],
                     use_container_width=True, hide_index=True)
    with st.expander("How are risk tiers assigned?"):
        st.write("Only flagged records are assigned Low/Medium/High. Add one point each for: score in the lowest 5% of all records; a critical/failure keyword in the message; or an error/critical/fatal/severe level. Two or more points → High; one → Medium; zero → Low. This rule is illustrative and needs validation.")

with tabs[4]:
    st.subheader("Comparison against BGL reference labels")
    if a.metrics is None:
        st.info("Evaluation requires a complete Label column containing both '-' normal records and non-'-' anomalous records. No metrics are reported when labels are absent or only one class is present.")
    else:
        m=a.metrics
        p,r,f=st.columns(3)
        p.metric("Precision", f"{m['precision']:.3f}")
        r.metric("Recall", f"{m['recall']:.3f}")
        f.metric("F1", f"{m['f1']:.3f}")
        matrix=pd.DataFrame(m["confusion_matrix"], index=["Actual normal","Actual anomaly"],
                            columns=["Predicted normal","Predicted anomaly"])
        st.dataframe(matrix, use_container_width=True)
        st.caption("Reference labels are used only for evaluation, never as model input. These are in-sample descriptive results, not an independent generalization estimate.")

with tabs[5]:
    st.subheader("Download analysis")
    st.download_button("Download results CSV", data=df.to_csv(index=False).encode("utf-8"),
                       file_name="forensic_anomaly_results.csv", mime="text/csv")
    st.download_button("Download extracted features CSV", data=a.features.to_csv(index=False).encode("utf-8"),
                       file_name="forensic_features.csv", mime="text/csv")
    buffer=io.BytesIO()
    joblib.dump({"model":a.model,"features":FEATURES}, buffer)
    st.download_button("Download fitted model (joblib)", data=buffer.getvalue(),
                       file_name="isolation_forest_model.joblib", mime="application/octet-stream")
    st.warning("Only load joblib models from trusted sources; loading arbitrary joblib files can execute code.")
    st.subheader("Methodology")
    st.markdown("""1. Read BGL structured CSV or raw logs.
2. Extract five numerical features: message length, word count, number count, error keyword count, and component frequency.
3. Standardize features and fit Isolation Forest (100 trees by default).
4. Predict normal (`1`) versus anomaly (`-1`), and calculate decision scores (lower = more unusual).
5. Inspect per-record sensitivity and heuristic risk tiers.
6. Compare predictions with reference labels where possible; export tables.

**Limitations:** This is a proof-of-concept trained and scored on the same uploaded dataset. Component frequency depends on the uploaded dataset. Feature sensitivity is not SHAP. BGL labels indicate system anomalies, not necessarily security incidents. No automated incident-response action is performed.""")
