import argparse
import pandas as pd
import numpy as np

def analyze_beacon_traffic(csv_file):
    print(f"[*] Loading network proxy logs from: {csv_file}")
    
    try:
        df = pd.read_csv(csv_file)
    except FileNotFoundError:
        print("[-] Error: Log file not found.")
        return

    # Parse timestamps and sort logs chronologically
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values(by=['src_ip', 'dest_host', 'timestamp'])
    
    # Calculate time difference (seconds) between consecutive connections
    df['time_delta'] = df.groupby(['src_ip', 'dest_host'])['timestamp'].diff().dt.total_seconds()

    # Group and aggregate behavioral metrics per connection pair
    metrics = df.groupby(['src_ip', 'dest_host']).agg(
        total_requests=('timestamp', 'count'),
        avg_delta=('time_delta', 'mean'),
        std_delta=('time_delta', 'std'),
        avg_bytes=('response_bytes', 'mean'),
        std_bytes=('response_bytes', 'std')
    ).reset_index()

    # Fill NaN values for single connection records
    metrics['std_delta'] = metrics['std_delta'].fillna(9999)

    # Flag potential C2 beacons
    beacon_candidates = metrics[
        (metrics['total_requests'] >= 5) &
        (metrics['std_delta'] <= 15)
    ]

    print("\n[+] Detection Scan Completed.")
    if beacon_candidates.empty:
        print("[!] No suspicious beaconing patterns detected.")
    else:
        print("\nALERT: Potential C2 Beacons Identified!\n")
        print(beacon_candidates[['src_ip', 'dest_host', 'total_requests', 'avg_delta', 'std_delta', 'avg_bytes']])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="C2 Beacon Detector using Proxy Logs")
    parser.add_argument("--log", type=str, default="proxy_logs.csv", help="Path to the proxy log CSV file")
    args = parser.parse_args()
    
    analyze_beacon_traffic(args.log)