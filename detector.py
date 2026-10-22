import numpy as np
import pandas as pd
from scipy.signal import find_peaks

# Local offline IOC blocklist (can be expanded or loaded from a local JSON/CSV file)
LOCAL_IOC_BLOCKLIST = {
    "evil-strict-c2.com",
    "evil-jitter-c2.net",
    "malware-dropzone.xyz",
    "command-control-node.io",
    "phishing-redirect.org"
}

def check_local_ioc(destination):
    """
    Checks if a destination matches the local offline IOC blocklist.
    Runs entirely offline with zero third-party API dependencies.
    """
    if not isinstance(destination, str):
        return False
    return destination.strip().lower() in LOCAL_IOC_BLOCKLIST

def calculate_autocorrelation_score(timestamps):
    """Computes a periodicity score using autocorrelation on request timestamps."""
    if len(timestamps) < 5:
        return 0.0

    sorted_ts = np.sort(timestamps)
    intervals = np.diff(sorted_ts)
    
    if len(intervals) < 3:
        return 0.0

    min_time = sorted_ts[0]
    max_time = sorted_ts[-1]
    total_duration = max_time - min_time
    
    if total_duration == 0:
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

def detect_c2_beacons(df):
    """
    Enhanced detection engine combining Statistical CV, 
    Jitter-tolerant Autocorrelation, and Local Offline IOC Matching.
    """
    results = []
    grouped = df.groupby('destination')
    
    for destination, group in grouped:
        timestamps = group['timestamp'].values
        total_requests = len(timestamps)
        
        # 1. Check Local Offline IOC Match First
        is_ioc_match = check_local_ioc(destination)
        
        if total_requests < 3 and not is_ioc_match:
            continue
            
        # 2. Timing Regularity via Interval CV
        if total_requests >= 3:
            sorted_ts = np.sort(timestamps)
            intervals = np.diff(sorted_ts)
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            
            cv = (std_interval / mean_interval) if mean_interval > 0 else 1.0
            cv_score = max(0.0, 1.0 - cv)
            
            # 3. Jitter Defense via Autocorrelation
            jitter_score = calculate_autocorrelation_score(timestamps)
            
            # Base behavioral score
            beacon_score = (0.4 * cv_score) + (0.6 * jitter_score)
        else:
            mean_interval = 0.0
            beacon_score = 0.0

        # 4. If matched in local IOC blocklist, override score to maximum threat (1.0)
        if is_ioc_match:
            beacon_score = 1.0
            
        results.append({
            'destination': destination,
            'total_requests': total_requests,
            'avg_interval_sec': round(mean_interval, 2),
            'beacon_score': round(beacon_score, 2),
            'ioc_matched': "YES" if is_ioc_match else "NO"
        })
        
    return pd.DataFrame(results)