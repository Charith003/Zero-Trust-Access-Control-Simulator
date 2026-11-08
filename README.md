# Zero Trust Access Control Simulator

An academic Flask application that evaluates access requests using device, location, login, MFA, behaviour and resource-sensitivity signals. It calculates an explainable risk score and returns **ALLOW**, **CHALLENGE**, or **DENY**.

## Features

- Interactive access-request simulator
- Weighted, normalized risk score from 0 to 100
- Adjustable policy thresholds
- Three one-click demonstration scenarios
- SQLite decision/audit log and CSV export
- CSV and JSON dataset batch analysis with flexible column aliases
- Responsive dashboard; no internet connection required after installation

## Run in Visual Studio Code

1. Open this folder in VS Code.
2. Open **Terminal > New Terminal**.
3. Create a virtual environment:

   Windows:

   ```powershell
   py -m venv .venv
   .venv\Scripts\activate
   ```

   macOS/Linux:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

4. Install and run:

   ```bash
   pip install -r requirements.txt
   python app.py
   ```

5. Open http://127.0.0.1:5000

The SQLite database (`zero_trust.db`) is created automatically on the first run.

## Dataset

The dataset named in the project presentation is **User activity dataset** by Rasika Ekanayaka:

https://www.kaggle.com/datasets/rasikaekanayakadevlk/user-activity-dataset

Kaggle may require a free account to download the file. The complete supplied dataset is included at `data/user_activity_data.json`. A smaller compatible demonstration file is included at `data/sample_user_activity.csv`.

## Risk model

The project uses transparent weighted rules. Unknown device, unusual location, missing MFA, anomalous activity, failed transactions, incident reports, repeated password resets, long sessions, high access frequency and sensitive-data access add risk. The default policy is:

- 0–34: ALLOW
- 35–64: CHALLENGE
- 65–100: DENY

These thresholds can be changed from **Policy Settings**.

## Test

```bash
python -m unittest discover -s tests -v
```

## Academic scope

This simulator demonstrates Zero Trust policy evaluation. It is not a production identity provider, firewall or real enterprise enforcement system.
