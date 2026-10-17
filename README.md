# C2 Beacon Detector Web Dashboard

An interactive, web-based proxy log analysis tool designed to detect Command and Control (C2) beaconing behavior (such as regular sleep intervals and uniform response payload sizes). Inspired by threat analysis concepts from Dominic Chell's "Hiding in Plain Sight" talk.

---

## Key Features

- Log Upload & Parsing: Upload proxy log datasets (CSV) directly through the interactive web dashboard.
- Time Delta Analysis: Calculates time differences between consecutive requests to identify consistent sleep cycles.
- Statistical Filtering: Leverages standard deviation metrics to spot low-variance beaconing patterns.
- Dynamic Threshold Controls: Interactive sidebar sliders allow real-time tuning of detection sensitivity.

---

## Tech Stack

- Python 3
- Streamlit (Web Application Framework)
- Pandas (Data Manipulation & Log Analysis)
- NumPy (Statistical Calculation)

---

## Getting Started

### Clone the Repository & Setup Environment
Clone the project and set up an isolated Python virtual environment:

git clone https://github.com/hab-git-1/C2-Beacon-Detector.git
cd C2-Beacon-Detector

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

### Install Dependencies
Install all required libraries inside the active virtual environment:

pip install -r requirements.txt

### Launch the Application
Start the Streamlit web app:

streamlit run app.py

Once executed, open your browser and go to http://localhost:8501 to access the dashboard.
