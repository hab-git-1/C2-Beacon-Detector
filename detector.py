import pandas as pd
import numpy as np

def calculate_shannon_entropy(domain: str) -> float:
    """Calculates Shannon Entropy to detect Domain Generation Algorithms (DGA)."""
    if not domain or not isinstance(domain, str):
        return 0.0
    domain = domain.split(':')[0].lower()
    prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return float(-sum(p * np.log2(p) for p in prob))

def detect_c2_beacons(df: pd.DataFrame, time_col='timestamp', host_col='destination', bytes_col='response_size') -> pd.DataFrame:
    """
    Advanced C2 Beacon Detection Engine using Coefficient of Variation (CV) 
    and Multi-Factor Threat Scoring.
    """
    if df.empty:
        return pd.DataFrame()

    df[time_col] = pd.to_datetime(df[time_col])
    df = df.sort_values(by=[host_col, time_col])

    results = []

    for host, group in df.groupby(host_col):
        count = len(group)
        if count < 5:
            continue

        time_deltas = group[time_col].diff().dt.total_seconds().dropna()
        if len(time_deltas) < 3:
            continue

        delta_mean = time_deltas.mean()
        delta_std = time_deltas.std()
        
        timing_cv = (delta_std / delta_mean) if (delta_mean > 0 and not pd.isna(delta_std)) else 0.0
        
        bytes_std = group[bytes_col].std() if bytes_col in group.columns else 0.0
        bytes_mean = group[bytes_col].mean() if bytes_col in group.columns else 0.0
        bytes_cv = (bytes_std / bytes_mean) if (bytes_mean > 0 and not pd.isna(bytes_std)) else 0.0

        entropy = calculate_shannon_entropy(str(host))

        # Core scoring: Focus heavily on absolute timing regularity
        timing_score = max(0.0, 1.0 - timing_cv)
        payload_score = max(0.0, 1.0 - bytes_cv)

        # Adjusted weighting: Timing 80%, Payload 20% -> pushes clean periodic beacons above 0.90+
        composite_score = round((timing_score * 0.80) + (payload_score * 0.20), 2)

        results.append({
            'destination': host,
            'total_requests': count,
            'avg_interval_sec': round(delta_mean, 2),
            'timing_cv': round(timing_cv, 3),
            'payload_cv': round(bytes_cv, 3),
            'domain_entropy': round(entropy, 2),
            'beacon_score': composite_score
        })

    results_df = pd.DataFrame(results)
    if not results_df.empty:
        results_df = results_df.sort_values(by='beacon_score', ascending=False)

    return results_df