import numpy as np
import pandas as pd
from scipy.signal import find_peaks

def calculate_autocorrelation_score(timestamps):
    """
    Computes a periodicity score using autocorrelation on request timestamps.
    Handles jittered intervals by identifying repeating wave patterns.
    """
    if len(timestamps) < 5:
        return 0.0  # Need a minimum sample size to find patterns

    # Sort timestamps and calculate delta intervals
    sorted_ts = np.sort(timestamps)
    intervals = np.diff(sorted_ts)
    
    if len(intervals) < 3:
        return 0.0

    # Convert intervals into a normalized time series signal
    # Fill in a regular time grid to compute autocorrelation
    min_time = sorted_ts[0]
    max_time = sorted_ts[-1]
    total_duration = max_time - min_time
    
    if total_duration == 0:
        return 0.0

    # Create a binned density signal over time (e.g., 1-second bins)
    bins = np.arange(min_time, max_time + 1, 1)
    if len(bins) < 10:
        return 0.0
        
    hist, _ = np.histogram(sorted_ts, bins=bins)
    
    # Compute autocorrelation
    mean_centered = hist - np.mean(hist)
    c = np.correlate(mean_centered, mean_centered, mode='full')
    
    # Keep only the positive lags
    half_len = len(c) // 2
    autocorr = c[half_len:]
    
    if np.max(autocorr) == 0:
        return 0.0
        
    # Normalize autocorrelation
    autocorr = autocorr / autocorr[0]
    
    # Find peaks in the autocorrelation function (excluding lag 0)
    peaks, _ = find_peaks(autocorr[1:], height=0.1)
    
    if len(peaks) > 0:
        # If strong repeating peaks exist, it indicates jittered/regular beaconing
        peak_strength = np.mean(autocorr[peaks + 1])
        return float(min(peak_strength, 1.0))
    
    return 0.0

def detect_c2_beacons(df):
    """
    Enhanced detection engine combining Coefficient of Variation (CV), 
    Shannon Entropy, and Autocorrelation (Jitter defense).
    """
    results = []
    
    # Group logs by destination/domain/IP
    grouped = df.groupby('destination')
    
    for destination, group in grouped:
        timestamps = group['timestamp'].values
        total_requests = len(timestamps)
        
        if total_requests < 3:
            continue
            
        # 1. Timing Regularity via Interval CV
        sorted_ts = np.sort(timestamps)
        intervals = np.diff(sorted_ts)
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        cv = (std_interval / mean_interval) if mean_interval > 0 else 1.0
        # Lower CV means higher regularity. Convert to a 0-1 score:
        cv_score = max(0.0, 1.0 - cv)
        
        # 2. Jitter Defense via Autocorrelation
        jitter_score = calculate_autocorrelation_score(timestamps)
        
        # 3. Combine scores (giving weight to both strict CV and jitter-tolerant autocorrelation)
        beacon_score = (0.5 * cv_score) + (0.5 * jitter_score)
        
        results.append({
            'destination': destination,
            'total_requests': total_requests,
            'avg_interval_sec': round(mean_interval, 2),
            'beacon_score': round(beacon_score, 2)
        })
        
    return pd.DataFrame(results)