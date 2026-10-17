import pandas as pd
import numpy as np

def analyze_beacon_traffic(csv_file):
    print(f"[*] Loading network proxy logs from {csv_file}...")
    
    # Load dataset into pandas DataFrame
    try:
        df = pd.read_csv(csv_file)
    except FileNotFoundError:
        print("[-] Error: Log file not found.")
        return

    # Parse timestamps
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Sort logs by client IP, destination host, and time
    df = df.sort_values(by=['src_ip', 'dest_host', 'timestamp'])
    
    # Calculate time difference (in seconds) between consecutive requests
    df['time_delta'] = df.groupby(['src_ip', 'dest_host'])['timestamp'].diff().dt.total_seconds()
    
    # Aggregate statistics per connection pair
    metrics = df.groupby(['src_ip', 'dest_host']).agg(
        total_requests=('timestamp', 'count'),
        avg_delta=('time_delta', 'mean'),
        std_delta=('time_delta', 'std'),
        avg_bytes=('response_bytes', 'mean'),
        std_bytes=('response_bytes', 'std'),
        unique_uris=('uri', 'nunique')
    ).reset_index()

    # Fill NaN values (e.g., single connection pairs with no delta)
    metrics['std_delta'] = metrics['std_delta'].fillna(9999)
    metrics['std_bytes'] = metrics['std_bytes'].fillna(9999)

    # Filter potential C2 beacons based on:
    # 1. High request volume (e.g., >= 5 requests)
    # 2. Low standard deviation in timing (consistent sleep interval)
    # 3. Low standard deviation in payload sizes
    beacon_candidates = metrics[
        (metrics['total_requests'] >= 5) &
        (metrics['std_delta'] <= 15) &   # Low variation in timing delta (seconds)
        (metrics['std_bytes'] <= 200)   # Similar response sizes
    ]

    print("\n[+] Detection Scan Completed.")
    if beacon_candidates.empty:
        print("[!] No suspicious beaconing patterns detected.")
    else:
        print("ALERT: Potential C2 Beacons Identified!\n")
        print(beacon_candidates[['src_ip', 'dest_host', 'total_requests', 'avg_delta', 'std_delta', 'avg_bytes']])

if __name__ == "__main__":
    analyze_beacon_traffic("proxy_logs.csv")
