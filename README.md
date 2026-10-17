# C2 Beacon Detector

A Python-based network proxy log analysis tool designed to detect Command and Control (C2) beaconing patterns (such as regular sleep intervals and uniform response payload sizes). Inspired by threat analysis concepts from Dominic Chell's *"Hiding in Plain Sight"* talk.

## Features
- **Time Delta Analysis:** Calculates time differences between consecutive requests to identify consistent sleep cycles.
- **Statistical Filtering:** Uses standard deviation metrics to spot low-variance beaconing behavior.
- **Command-Line Interface:** Easily pass custom log datasets using the `--log` flag.

## Installation & Requirements
Ensure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt