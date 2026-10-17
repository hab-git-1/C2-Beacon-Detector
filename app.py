import streamlit as st
import pandas as pd
import plotly.express as px
from detector import detect_c2_beacons

st.set_page_config(page_title="C2 Beacon Detector Dashboard", layout="wide")

st.title("C2 Beacon Detector & Threat Hunting Dashboard")
st.markdown("Analyze network proxy logs for Command and Control (C2) beaconing patterns using statistical periodicity scoring.")

uploaded_file = st.sidebar.file_uploader("Upload Proxy Log (CSV)", type=["csv"])
min_score_threshold = st.sidebar.slider("Minimum Threat Score Filter", 0.0, 1.0, 0.50, 0.05)

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.subheader("Raw Log Preview")
    st.dataframe(df.head(5), use_container_width=True)

    with st.spinner("Analyzing traffic patterns and computing threat scores..."):
        detections = detect_c2_beacons(df)

    if not detections.empty:
        filtered = detections[detections['beacon_score'] >= min_score_threshold]

        if not filtered.empty:
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Endpoints Analyzed", len(detections))
            col2.metric("Flagged High-Risk Beacons", len(filtered))
            col3.metric("Max Threat Score Detected", f"{detections['beacon_score'].max():.2f}")

            st.subheader("Beacon Analysis Results")
            st.dataframe(filtered, use_container_width=True)

            st.subheader("Threat Distribution Visualization")
            fig = px.scatter(
                filtered, 
                x="avg_interval_sec", 
                y="beacon_score",
                size="total_requests", 
                color="beacon_score",
                hover_name="destination",
                labels={"avg_interval_sec": "Average Interval (Seconds)", "beacon_score": "Beacon Threat Score"},
                title="C2 Beacon Score vs. Check-in Interval Frequency"
            )
            st.plotly_chart(fig, use_container_width=True)

            csv_data = filtered.to_csv(index=False).encode('utf-8')
            st.download_button("Download Threat Hunting Report (CSV)", csv_data, "c2_detection_report.csv", "text/csv")
        else:
            st.warning("⚠️ No endpoints meet the selected minimum threat score filter. Try lowering the threshold slider in the sidebar.")
    else:
        st.info("No suspicious beaconing behavior detected in the uploaded log.")
else:
    st.info("Please upload a CSV proxy log file to begin analysis.")