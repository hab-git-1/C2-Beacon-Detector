"""
Advanced Self-Contained C2 Beacon Detection Engine.
Combines Timing Autocorrelation, Payload Size CV, Shannon Entropy, and Local IOCs.
"""

import numpy as np
import pandas as pd
import math
from scipy.signal import find_peaks

LOCAL_IOC_BLOCKLIST = {
    "evil-strict-c2.com",
    "evil-jitter-c2.net",
    "malware-dropzone.xyz",
    "command-control-node.io",
    "phishing-redirect.org"
}

def check_local_ioc(destination: str) -> bool:
    """Checks if a destination matches the local offline blocklist."""
    if not isinstance(destination, str):
        return False
    return destination.strip().lower() in LOCAL_IOC_BLOCKLIST

def calculate_shannon_entropy(data_str: str) -> float:
    """Calculates Shannon Entropy for domain randomness (DGA detection)."""
    if not data_str:
        return 0.0
    prob = [float(data_str.count(c)) / len(data_str) for c in set(data_str)]
    return -sum([p * math.log(p, 2) for p in prob])

def calculate_autocorrelation_score(timestamps: np.ndarray) -> float:
    """Computes a periodicity score using autocorrelation on request timestamps."""
    if len(timestamps) < 5:
        return 0.0

    sorted_ts = np.sort(timestamps)
    intervals = np.diff(sorted_ts)
    
    if len(intervals) < 3:
        return 0.0

    min_time, max_time = sorted_ts[0], sorted_ts[-1]
    if max_time == min_time:
        return 0.0

    bins = np.arange(min_time, max_time + 1, 1)
    if len(bins) < 10:
        return 0.0
        
    hist, _ = np.histogram(sorted_ts, bins=bins)
    mean_centered = hist - np.mean(hist)
    c = np.correlate(mean_centered, mean_centered, mode='full')
    
    half_len = len(c) // 2
    autocorr = c[half_len:]
    
    if np.max(autocorr) == 0:
        return 0.0
        
    autocorr = autocorr / autocorr[0]
    peaks, _ = find_peaks(autocorr[1:], height=0.1)
    
    if len(peaks) > 0:
        peak_strength = np.mean(autocorr[peaks + 1])
        return float(min(peak_strength, 1.0))
    
    return 0.0

def get_risk_tier(score: float, is_ioc: bool) -> str:
    """Assigns an operational severity tier based on composite score."""
    if is_ioc or score >= 0.80:
        return "🔴 Critical"
    elif score >= 0.40:
        return "🟡 Suspicious"
    else:
        return "🟢 Low Risk"

def analyze_proxy_logs(df: pd.DataFrame) -> pd.DataFrame:
    """Executes multi-factor analysis including payload consistency and jitter."""
    results = []
    
    if 'destination' not in df.columns or 'timestamp' not in df.columns:
        raise ValueError("Dataset must contain 'destination' and 'timestamp' columns.")

    grouped = df.groupby('destination')
    
    for destination, group in grouped:
        timestamps = group['timestamp'].values
        total_requests = len(timestamps)
        is_ioc = check_local_ioc(destination)
        
        if total_requests < 3 and not is_ioc:
            continue
            
        if total_requests >= 3:
            sorted_ts = np.sort(timestamps)
            intervals = np.diff(sorted_ts)
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            
            # Timing CV & Autocorrelation
            cv = (std_interval / mean_interval) if mean_interval > 0 else 1.0
            cv_score = max(0.0, 1.0 - cv)
            jitter_score = calculate_autocorrelation_score(timestamps)
            
            # Payload Consistency (CV of bytes if column exists)
            payload_score = 0.5
            if 'bytes_received' in group.columns:
                bytes_arr = group['bytes_received'].values
                mean_bytes = np.mean(bytes_arr)
                std_bytes = np.std(bytes_arr)
                bytes_cv = (std_bytes / mean_bytes) if mean_bytes > 0 else 0.0
                payload_score = max(0.0, 1.0 - bytes_cv)

            entropy_score = min(calculate_shannon_entropy(str(destination)) / 4.5, 1.0)
            
            # Composite Scoring Formula: 40% Autocorrelation + 25% CV + 20% Payload + 15% Entropy
            composite_score = (0.40 * jitter_score) + (0.25 * cv_score) + (0.20 * payload_score) + (0.15 * entropy_score)
        else:
            mean_interval = 0.0
            composite_score = 0.0

        if is_ioc:
            composite_score = 1.0
            
        risk_tier = get_risk_tier(composite_score, is_ioc)
            
        results.append({
            'destination': destination,
            'total_requests': total_requests,
            'avg_interval_sec': round(mean_interval, 2),
            'beacon_score': round(composite_score, 2),
            'risk_tier': risk_tier,
            'ioc_matched': "YES" if is_ioc else "NO"
        })
        
    return pd.DataFrame(results).sort_values(by='beacon_score', ascending=False)