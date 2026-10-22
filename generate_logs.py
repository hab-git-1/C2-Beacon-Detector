import pandas as pd
import numpy as np
import time

# Base timestamp (e.g., start of today)
base_time = int(time.time()) - 86400

data = []

# 1. Strict C2 Beacon (Every exactly 30 seconds)
for i in range(50):
    data.append({
        'timestamp': base_time + (i * 30),
        'destination': 'evil-strict-c2.com',
        'bytes_out': 250,
        'bytes_in': 1024
    })

# 2. Jittered C2 Beacon (Target 30s interval + random jitter between -8 and +8 sec)
np.random.seed(42)
curr_time = base_time
for i in range(50):
    jitter = np.random.randint(-8, 9)
    curr_time += max(5, 30 + jitter)
    data.append({
        'timestamp': curr_time,
        'destination': 'evil-jitter-c2.net',
        'bytes_out': 300,
        'bytes_in': 2048
    })

# 3. Normal Browsing / Random Noise
np.random.seed(100)
curr_time = base_time
for i in range(100):
    curr_time += np.random.randint(2, 600)  # Random gaps up to 10 minutes
    data.append({
        'timestamp': curr_time,
        'destination': 'legit-cdn-service.org',
        'bytes_out': 15000,
        'bytes_in': 450000
    })

df = pd.DataFrame(data)
df.to_csv("test_proxy_logs.csv", index=False)
print("Generated test_proxy_logs.csv successfully!")