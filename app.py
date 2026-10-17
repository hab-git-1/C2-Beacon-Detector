import streamlit as st
import pandas as pd
import numpy as np

st.set_page_config(page_title="C2 Beacon Detector", page_icon="🛡️", layout="wide")

st.title("🛡️ C2 Beaconing Activity Detector")
st.markdown("Upload network proxy logs to analyze and detect Command and Control (C2) beacon patterns.")

# Sidebar file uploader
st.sidebar.header("Configuration")
uploaded_file = st.sidebar.file_uploader("Upload Proxy Log CSV", type=["csv"])

if uploaded_file is not None:
    # Load dataset
    df = pd.read_csv(uploaded_file)
    
    st.subheader("📄 Raw Log Preview")
    st.dataframe(df.head(10), use_container_width=True)

    # Process data
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values(by=['src_ip', 'dest_host', 'timestamp'])
    df['time_delta'] = df.groupby(['src_ip', 'dest_host'])['timestamp'].diff().dt.total_seconds()

    metrics = df.groupby(['src_ip', 'dest_host']).agg(
        total_requests=('timestamp', 'count'),
        avg_delta=('time_delta', 'mean'),
        std_delta=('time_delta', 'std'),
        avg_bytes=('response_bytes', 'mean')
    ).reset_index()

    metrics['std_delta'] = metrics['std_delta'].fillna(9999)

    # Detection Threshold Slider
    st.sidebar.subheader("Detection Settings")
    min_reqs = st.sidebar.slider("Min Requests", min_value=2, max_value=20, value=5)
    max_std = st.sidebar.slider("Max Timing Std Dev (Seconds)", min_value=0.0, max_value=30.0, value=15.0)

    beacon_candidates = metrics[
        (metrics['total_requests'] >= min_reqs) &
        (metrics['std_delta'] <= max_std)
    ]

    st.subheader("🚨 Detection Results")
    if beacon_candidates.empty:
        st.success("No suspicious beaconing patterns detected based on current thresholds.")
    else:
        st.warning(f"Potential C2 Beacons Identified: {len(beacon_candidates)}")
        st.dataframe(beacon_candidates, use_container_width=True)
else:
    st.info("👈 Please upload a proxy log CSV file in the sidebar to begin the analysis.")