# Zero Trust Access Control Simulator

A lightweight academic web application that demonstrates **context-aware access evaluation** using the principles of Zero Trust. The simulator evaluates an access request against device, location, login, multi-factor authentication (MFA), activity and resource-sensitivity signals. It calculates an explainable risk score from **0 to 100** and applies configurable policy thresholds to produce one of three outcomes:

- **ALLOW** — the request falls within the low-risk range.
- **CHALLENGE** — the request falls within the medium-risk range and would require additional verification in a real deployment.
- **DENY** — the request falls within the high-risk range.

The application is built with **Python, Flask, SQLite, HTML, CSS and Jinja2**. It includes an interactive simulator, demonstration scenarios, a dashboard, policy-threshold settings, decision history, CSV export and CSV/JSON batch analysis.

> **Academic prototype:** This project simulates policy decisions. It does not authenticate real users, perform an actual MFA challenge, enforce access on enterprise resources, or replace an identity provider, firewall, endpoint security product or production Zero Trust platform.

---

## Table of contents

- [Project objectives](#project-objectives)
- [Features](#features)
- [How the system works](#how-the-system-works)
- [Risk assessment model](#risk-assessment-model)
- [Default policy thresholds](#default-policy-thresholds)
- [Technology stack](#technology-stack)
- [Project structure](#project-structure)
- [Requirements](#requirements)
- [Installation and setup](#installation-and-setup)
- [Running the application](#running-the-application)
- [Application pages](#application-pages)
- [Using the access simulator](#using-the-access-simulator)
- [Using the demonstration scenarios](#using-the-demonstration-scenarios)
- [Dataset and batch analysis](#dataset-and-batch-analysis)
- [Supported dataset fields](#supported-dataset-fields)
- [Database and audit logs](#database-and-audit-logs)
- [Policy configuration](#policy-configuration)
- [Running the tests](#running-the-tests)
- [Risk model limitations](#risk-model-limitations)
- [Security considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Possible future enhancements](#possible-future-enhancements)
- [Dataset attribution](#dataset-attribution)
- [Academic scope](#academic-scope)

---

## Project objectives

The project provides a practical environment for understanding how a Zero Trust-style policy decision can consider more than a user's identity or predefined permissions.

Its objectives are to:

1. Evaluate an access request using multiple contextual security signals.
2. Convert detected risk conditions into a weighted score.
3. Produce an explainable `ALLOW`, `CHALLENGE` or `DENY` decision.
4. Allow users to adjust the decision thresholds and observe how policy strictness changes.
5. Store individual simulation results in a local SQLite audit database.
6. Process compatible CSV and JSON activity datasets in batch.
7. Present risk results and historical decisions through a browser-based dashboard.

## Features

### Access-request simulation

- Enter a user identifier and requested resource.
- Set device, location, login, MFA, anomaly and sensitive-resource conditions.
- Enter activity values such as failed transactions, incident reports, password resets, session duration and access frequency.
- Calculate a risk score and receive an access decision.
- View the reasons that contributed to the score.

### Risk assessment

- Weighted, rule-based scoring.
- Risk score normalized to the range `0–100`.
- Risk levels: `Low`, `Medium` and `High`.
- Explainable reason messages for triggered conditions.
- Configurable decision thresholds.

### Demonstration scenarios

The application provides three one-click scenarios:

- **Normal:** a known device, expected location, normal login pattern and verified MFA.
- **Suspicious:** a mixture of trust and risk signals.
- **Critical:** multiple simultaneous risk indicators.

Each scenario is evaluated and its result is added to the decision log.

### Dashboard and audit history

- Total number of recorded requests.
- Counts of `ALLOW`, `CHALLENGE` and `DENY` decisions.
- Average recorded risk score.
- Recent decisions.
- Decision-history filtering.
- CSV export of recorded decisions.

### Dataset Lab

- Upload CSV or JSON files.
- Recognize supported field aliases, including common camelCase dataset fields.
- Evaluate up to 2,000 records per upload.
- Display aggregate decision counts and average risk score.
- Preview up to the first 10 evaluated records.
- Download the included full JSON dataset or sample CSV.

### Local operation

- Flask development server.
- SQLite database stored in the project directory.
- No external API is required for the core simulation.
- Once Python and the Flask dependency are installed, the application can run locally without an internet connection.

---

## How the system works

The application follows this sequence:

1. **Access request:** The user supplies an identity, resource and request context.
2. **Context normalization:** The risk engine maps submitted values and supported dataset aliases into a consistent internal record.
3. **Signal evaluation:** The engine checks each configured risk condition.
4. **Risk calculation:** Risk points are added for triggered conditions and the total is capped at 100.
5. **Policy decision:** The score is compared with the current policy thresholds.
6. **Explanation:** The engine returns the score, risk level, decision and reasons.
7. **Audit logging:** For an individual simulation or demonstration scenario, the request and decision are stored in SQLite.

### Decision flow

```text
Access Request
      |
      v
Normalize Request Data
      |
      v
Evaluate Security Signals
      |
      v
Calculate Weighted Risk Score (0-100)
      |
      v
Apply Policy Thresholds
      |
      +----------------+------------------+
      |                |                  |
      v                v                  v
    ALLOW           CHALLENGE            DENY
   0-34              35-64              65-100
      |                |                  |
      +----------------+------------------+
                       |
                       v
              Explain Decision
                       |
                       v
              Store Audit Record
```

The diagram represents the application's simulated decision flow. `CHALLENGE` is a policy outcome label; the current application does not initiate or verify a real MFA transaction.

---

## Risk assessment model

The project uses a **deterministic weighted rule-based model**. It is not a trained machine-learning model.

Each risk condition contributes points when its condition is met. The points are summed, rounded to an integer and capped at 100.

### Default risk weights

| Security signal | Trigger condition | Risk points |
|---|---|---:|
| Unknown device | Device consistency is false | +16 |
| Unusual location | Location consistency is false | +14 |
| Inconsistent login | Login consistency is false | +8 |
| MFA not verified | MFA status is false | +15 |
| Anomalous activity | Anomaly flag is true | +20 |
| Failed transactions | 2 points per failed transaction, capped at 10 | Up to +10 |
| Incident reports | 3 points per incident report, capped at 7 | Up to +7 |
| Multiple password resets | More than one password reset | +4 |
| Long session | Session duration is greater than 120 minutes | +3 |
| High access frequency | Access frequency is greater than 50 | +3 |
| Sensitive data | Sensitive-data access flag is true | +10 |

### Scoring formula

Let each risk condition contribute a value when its trigger condition is met:

```text
Raw Risk Score =
    Unknown Device
  + Unusual Location
  + Inconsistent Login
  + Missing MFA
  + Anomalous Activity
  + Failed Transaction Points
  + Incident Report Points
  + Password Reset Points
  + Long Session Points
  + High Access Frequency Points
  + Sensitive Data Points
```

The final score is:

```text
Final Risk Score = min(100, round(Raw Risk Score))
```

The engine returns:

- `score`: final integer risk score.
- `decision`: `ALLOW`, `CHALLENGE` or `DENY`.
- `level`: `Low`, `Medium` or `High`.
- `reasons`: a list describing the conditions that added risk.

If no risk condition is triggered, the engine returns the explanation `No abnormal security signals detected`.

### Example calculation

Consider a request with the following conditions:

| Triggered condition | Points |
|---|---:|
| Unknown device | +16 |
| MFA not verified | +15 |
| Anomalous activity | +20 |
| **Total** | **51** |

The resulting score is `51/100`. With the default thresholds, the request receives a **CHALLENGE** decision and a **Medium** risk level.

---

## Default policy thresholds

The default policy is:

| Risk score | Decision | Risk level |
|---:|---|---|
| 0–34 | `ALLOW` | Low |
| 35–64 | `CHALLENGE` | Medium |
| 65–100 | `DENY` | High |

The maximum score for `ALLOW` and the maximum score for `CHALLENGE` can be changed from the **Policy Settings** page.

The application validates that:

```text
0 <= allow_max < challenge_max <= 100
```

The signal weights are defined in `risk_engine.py` and are displayed in the policy page. They are not editable through the current web interface.

---

## Technology stack

| Technology | Role in the project |
|---|---|
| Python | Application logic, data normalization and risk evaluation |
| Flask | Web framework, routing and request handling |
| HTML | Page structure |
| CSS | Layout, styling and responsive presentation |
| Jinja2 | Server-side HTML templates |
| SQLite | Local decision history and policy-threshold storage |
| CSV | Dataset import and decision-log export |
| JSON | Dataset import and included activity records |
| `unittest` | Automated tests for the risk engine |

### Dependency

The current `requirements.txt` contains:

```text
Flask==3.1.2
```

The other modules used by the application are part of the Python standard library.

---

## Project structure

```text
Zero_Trust_Access_Control_Simulator/
│
├── app.py
│   └── Flask application, routes, SQLite operations,
│       dataset upload, batch analysis and CSV export
│
├── risk_engine.py
│   └── Default risk policy, field aliases, input
│       normalization and weighted access evaluation
│
├── requirements.txt
│   └── Python dependency list
│
├── README.md
│   └── Project documentation and setup instructions
│
├── zero_trust.db
│   └── SQLite database created automatically at runtime
│
├── data/
│   ├── user_activity_data.json
│   │   └── Included user activity dataset
│   │
│   └── sample_user_activity.csv
│       └── Small compatible sample dataset
│
├── static/
│   └── style.css
│       └── Application styling
│
├── templates/
│   ├── base.html
│   │   └── Shared page layout
│   ├── dashboard.html
│   │   └── Dashboard and recent decisions
│   ├── simulate.html
│   │   └── Access-request form and result
│   ├── dataset.html
│   │   └── Dataset upload and batch-analysis results
│   ├── logs.html
│   │   └── Decision history and export
│   ├── policy.html
│   │   └── Policy threshold configuration
│   └── about.html
│       └── System architecture and project scope
│
└── tests/
    └── test_risk_engine.py
        └── Automated risk-engine tests
```

The `zero_trust.db` file is generated when the application initializes. It may not be present in a clean source-code download until the first run.

---

## Requirements

Before running the project, install:

- Python 3.10 or later recommended.
- Visual Studio Code or another Python-compatible editor.
- `pip`, the Python package installer.
- A modern web browser.

The application is designed to run locally on Windows, macOS and Linux.

---

## Installation and setup

### 1. Download and extract the project

Extract the project ZIP file.

Open the extracted `Zero_Trust_Access_Control_Simulator` folder in Visual Studio Code.

Make sure the folder you open contains `app.py`, `risk_engine.py` and `requirements.txt`.

### 2. Open the terminal

In Visual Studio Code, select:

```text
Terminal → New Terminal
```

Confirm that the terminal is inside the project directory.

### 3. Create a virtual environment

**Windows (PowerShell):**

```powershell
py -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use Command Prompt:

```cmd
.venv\Scripts\activate.bat
```

**macOS/Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 5. Start the application

```bash
python app.py
```

### 6. Open the application

Visit the following address in your browser:

[http://127.0.0.1:5000](http://127.0.0.1:5000)

The SQLite database, `zero_trust.db`, is initialized automatically when `app.py` is run directly.

### 7. Stop the application

Return to the terminal and press:

```text
CTRL + C
```

To run the application again, activate the virtual environment and execute `python app.py`.

---

## Application pages

### 1. Dashboard — `/`

The dashboard provides an overview of previously recorded individual decisions.

It displays:

- Total recorded requests.
- Number of allowed requests.
- Number of challenged requests.
- Number of denied requests.
- Average recorded risk score.
- Recent decision records.
- Links to the simulation and demonstration scenarios.

The dashboard statistics are based on records stored in SQLite. Dataset batch-analysis results are not automatically added to this decision history.

### 2. Access Simulator — `/simulate`

The simulator accepts a single access request.

The user can provide:

- User ID.
- Requested resource.
- Device consistency.
- Location consistency.
- Login consistency.
- MFA status.
- Anomalous activity.
- Sensitive-data access.
- Failed transactions.
- Incident reports.
- Password resets.
- Session duration.
- Access frequency.

After submission, the application normalizes the request, evaluates its risk, displays the result and stores the decision in SQLite.

### 3. Dataset Lab — `/dataset`

The Dataset Lab accepts CSV and JSON files and performs batch risk evaluation.

It displays:

- Number of rows processed.
- Average risk score.
- `ALLOW` count.
- `CHALLENGE` count.
- `DENY` count.
- A preview of up to 10 evaluated records.

The current implementation processes a maximum of 2,000 rows per upload. Batch results are displayed for that request but are not inserted into the individual decision audit table.

### 4. Decision Logs — `/logs`

The logs page displays saved individual simulation and demonstration decisions.

Available filters:

- All decisions.
- `ALLOW`.
- `CHALLENGE`.
- `DENY`.

The **Export CSV** action downloads the recorded decision history as `zero_trust_decisions.csv`.

### 5. Policy Settings — `/policy`

The policy page allows the user to change:

- Maximum score for `ALLOW`.
- Maximum score for `CHALLENGE`.

It also displays the configured risk weights.

A policy update is stored in SQLite and is used for subsequent evaluations. Existing audit records retain their original decisions and scores.

### 6. System Architecture — `/about`

The About page explains the five main stages:

1. Access request.
2. Context collection.
3. Risk engine.
4. Policy decision.
5. Audit log.

It also describes the academic scope and limitations of the simulator.

---

## Using the access simulator

1. Start the Flask application.
2. Open the Dashboard.
3. Select **Access Simulator**.
4. Enter a user ID and requested resource.
5. Select the relevant trust and activity conditions.
6. Submit the request.
7. Review the risk score and decision.
8. Read the reasons explaining the result.
9. Open **Decision Logs** to review the stored record.

For example, select:

- Known device: No.
- Expected location: Yes.
- Normal login pattern: No.
- MFA verified: Yes.
- Anomaly detected: No.
- Sensitive data request: Yes.
- Failed transactions: 1.
- Session duration: 130 minutes.

The engine evaluates all applicable conditions and returns a policy decision based on the current thresholds.

---

## Using the demonstration scenarios

The simulator includes three routes for quick demonstrations:

| Scenario | Route | Purpose |
|---|---|---|
| Normal | `/scenarios/normal` | Demonstrates a low-risk request |
| Suspicious | `/scenarios/suspicious` | Demonstrates a request with mixed trust signals |
| Critical | `/scenarios/critical` | Demonstrates a request with multiple risk indicators |

These routes can be opened from the dashboard.

Each scenario is evaluated using the current policy thresholds and its result is saved in the SQLite decision log.

---

## Dataset and batch analysis

### Included datasets

The project contains two data files:

| File | Description |
|---|---|
| `data/user_activity_data.json` | Full supplied activity dataset containing 437 records |
| `data/sample_user_activity.csv` | Smaller CSV dataset with compatible input fields |

The full JSON dataset includes fields such as:

- User ID.
- Failed login attempts.
- Access frequency.
- Login consistency.
- Device consistency.
- Access-location consistency.
- Dwell time.
- Mouse movements.
- Scroll behavior.
- Incident reports.
- Password resets.
- Anomalous activity.
- Session duration.
- MFA status.
- Failed transactions.
- Sensitive-data access.

Not every field in the original dataset is currently used by the risk engine. Mouse movements and scroll behavior, for example, are not included in the current scoring calculation.

### Uploading a dataset

1. Open the **Dataset Lab** page.
2. Select a compatible `.csv` or `.json` file.
3. Upload the file.
4. The application normalizes supported field names.
5. Each processed record is evaluated using the current risk policy.
6. Review the aggregate summary and record preview.

### Upload constraints

- Supported formats: CSV and JSON.
- Maximum HTTP upload size: 5 MB.
- Maximum records evaluated: 2,000 per upload.
- Preview size: up to 10 records.
- JSON input must be a list of objects or an object containing a `data` or `records` list.
- CSV input must contain a header row.

---

## Supported dataset fields

The risk engine supports normalized internal field names and several common aliases.

| Internal field | Recognized examples |
|---|---|
| `user_id` | `user_id`, `userid`, `user`, `identity`, `employee_id` |
| `resource` | `resource`, `resource_name`, `requested_resource`, `application` |
| `device_consistency` | `device_consistency`, `deviceconsistent`, `device_consistent` |
| `location_consistency` | `location_consistency`, `access_location_consistency`, `locationconsistent` |
| `login_consistency` | `login_consistency`, `loginconsistent` |
| `mfa_status` | `mfa_status`, `mfa`, `mfa_enabled`, `multifactor_authentication` |
| `anomalous_activity` | `anomalous_activity`, `anomaly`, `is_anomalous` |
| `failed_transactions` | `failed_transactions`, `failed_logins`, `failed_attempts` |
| `incident_reports` | `incident_reports`, `incidents` |
| `password_resets` | `password_resets`, `password_reset_count` |
| `session_duration` | `session_duration`, `dwell_time`, `duration` |
| `access_frequency` | `access_frequency`, `frequency`, `access_count` |
| `sensitive_data` | `sensitive_data`, `access_to_sensitive_data`, `sensitive_access` |

Field matching ignores capitalization and punctuation differences. For example, `userId` can be matched to `user_id`.

### Value normalization

The normalizer converts common boolean representations such as `true`, `false`, `yes`, `no`, `1` and `0` into binary values.

It also supports time-like duration strings in `HH:MM:SS` format and converts them into minutes.

For login consistency, numeric values greater than 1 are interpreted using a threshold of 5: values of 5 or more are considered consistent. Values from 0 to 1 use a threshold of 0.5.

Fields not found in the uploaded file use the normalizer's built-in defaults. Therefore, uploaded datasets should be checked to ensure that their columns map correctly to the expected signals.

---

## Database and audit logs

The project uses SQLite and creates the database file:

```text
zero_trust.db
```

The database is stored in the project directory.

### `decisions` table

The decision table stores:

- Record ID.
- Timestamp.
- User ID.
- Requested resource.
- Risk score.
- Risk level.
- Access decision.
- Explanation reasons.
- Device consistency.
- Location consistency.
- Login consistency.
- MFA status.
- Anomalous activity.
- Failed transactions.
- Incident reports.
- Password resets.
- Session duration.
- Access frequency.
- Sensitive-data flag.

### `policy` table

The policy table stores:

- Maximum score for `ALLOW`.
- Maximum score for `CHALLENGE`.

The policy record is initialized with the default values when the database is created.

### Database behavior

- Individual simulations are stored in the decision table.
- One-click scenarios are stored in the decision table.
- Batch dataset results are not stored in the decision table.
- Policy threshold updates are persisted in SQLite.
- Exporting logs generates a CSV file from the stored decision records.

The database can be removed to reset the local application data. A new database and default policy record will be created the next time the application is initialized. **Back up the database first if its audit history is required.**

---

## Policy configuration

The default thresholds are:

```python
DEFAULT_POLICY = {
    "allow_max": 34,
    "challenge_max": 64
}
```

The policy page allows these two threshold values to be changed.

For example, a stricter demonstration policy could use:

```text
ALLOW:     0–24
CHALLENGE: 25–54
DENY:      55–100
```

This is an example configuration, not the default.

The signal weights remain defined in `risk_engine.py`. Changing thresholds changes how scores are classified; it does not change how the score itself is calculated.

---

## Running the tests

The project uses Python's built-in `unittest` framework.

From the project root, activate the virtual environment and run:

```bash
python -m unittest discover -s tests -v
```

The current test file covers:

| Test | Expected behavior |
|---|---|
| Normal request | Returns `ALLOW` |
| Mixed risk signals | Returns `CHALLENGE` |
| Multiple anomalies | Returns `DENY` |
| Uploaded JSON aliases | Normalizes supported camelCase fields and duration values |

The included test suite contains four risk-engine tests. These tests validate core scoring and normalization behavior; they do not constitute full end-to-end testing of every Flask route or database operation.

---

## Risk model limitations

The current implementation is intentionally simple and explainable. The following limitations should be considered:

1. **Rule-based scoring:** The engine uses fixed weighted conditions. It does not train or load an ML model.
2. **Fixed signal weights:** The web interface displays weights, but only the decision thresholds can currently be changed.
3. **Selected dataset features:** Mouse movement and scroll behavior from the supplied dataset are not currently used.
4. **Simulated challenge:** The `CHALLENGE` result does not initiate a real MFA transaction.
5. **No live threat intelligence:** The application does not query external threat feeds or reputation services.
6. **No continuous session monitoring:** It evaluates submitted requests rather than continuously monitoring active sessions.
7. **No production enforcement:** The result is recorded and displayed; it is not enforced against a real enterprise application or network.
8. **Input defaults:** Missing fields are normalized using default values, which may affect scores if an uploaded dataset does not map to the expected schema.

---

## Security considerations

This project is intended for local academic demonstration.

Before adapting it for deployment beyond a trusted local environment, address the following:

- Replace the fallback Flask secret key with a strong, randomly generated secret stored in an environment variable.
- Disable Flask debug mode outside local development.
- Add authentication and authorization for dashboard, policy and log access.
- Add CSRF protection for state-changing forms.
- Validate uploaded file content and impose appropriate resource limits.
- Review error handling and logging so sensitive information is not exposed.
- Protect the SQLite database and exported audit records.
- Use HTTPS and a production-ready WSGI server if deployed.
- Add tests for routes, database behavior, policy updates, file uploads and exports.

The current application binds to `127.0.0.1`, which is appropriate for local development but does not make it a production deployment.

---

## Troubleshooting

### `python` is not recognized

On Windows, try:

```powershell
py --version
```

If Python is installed, use `py` instead of `python` for the environment setup.

### `pip` is not recognized

Use:

```bash
python -m pip install -r requirements.txt
```

### `ModuleNotFoundError: No module named 'flask'`

Activate the virtual environment and install the dependencies:

```bash
python -m pip install -r requirements.txt
```

### PowerShell does not allow virtual-environment activation

Use Command Prompt:

```cmd
.venv\Scripts\activate.bat
```

Alternatively, use the appropriate PowerShell execution-policy settings for your machine.

### Port 5000 is already in use

Stop the other process using port 5000, then restart the application. The current development configuration uses port 5000.

### The dashboard contains no records

Run an individual simulation or select one of the demonstration scenarios. The dashboard's statistics are based on saved decision records.

### A dataset upload does not work

Check that:

- The file is valid UTF-8 CSV or JSON.
- The file is smaller than 5 MB.
- CSV files contain a header row.
- JSON files contain a list of objects or a supported `data`/`records` wrapper.
- The data uses supported field names and compatible values.

### The result differs from an expected score

Check the normalized field values, current policy thresholds and the conditions that trigger each weighted rule. Missing fields use defaults, and numeric values may be interpreted according to the normalization rules described above.

---

## Possible future enhancements

The following are possible extensions; they are not claims about features already implemented.

### Authentication and enforcement

- Integrate an identity provider.
- Implement an actual MFA challenge flow.
- Connect policy decisions to a protected test application.
- Introduce role and resource-level authorization.

### Risk engine improvements

- Allow administrators to configure individual signal weights.
- Add a policy editor with validation and version history.
- Add additional device and session context.
- Investigate behavioral anomaly detection using machine-learning models.
- Evaluate model quality using precision, recall, F1-score and other suitable metrics if a trained model is introduced.

### Dataset and analytics improvements

- Incorporate additional behavioral fields such as mouse movement and scroll behavior.
- Add data-quality validation and missing-value reports.
- Save batch-analysis summaries separately from individual access decisions.
- Add visual analytics for risk distributions and decision trends.
- Support larger datasets through streaming or background processing.

### Testing and deployment

- Add Flask route and integration tests.
- Add database and file-upload tests.
- Add security testing and dependency checks.
- Containerize the application.
- Deploy behind a production-ready WSGI server with appropriate security controls.

---

## Dataset attribution

The project references the **User activity dataset** published by **Rasika Ekanayaka** on Kaggle:

[User Activity Dataset — Kaggle](https://www.kaggle.com/datasets/rasikaekanayakadevlk/user-activity-dataset)

The dataset is included in this project at:

```text
data/user_activity_data.json
```

A smaller compatible demonstration file is provided at:

```text
data/sample_user_activity.csv
```

The Kaggle listing identifies the dataset license as MIT. Review the source listing and its current terms before redistributing the dataset independently.

---

## Academic scope

The Zero Trust Access Control Simulator is an academic prototype designed to demonstrate the concepts of:

- Explicit verification.
- Context-aware access evaluation.
- Weighted risk assessment.
- Policy-based authorization decisions.
- Explainable security outcomes.
- Audit logging and review.

It provides a controlled environment for exploring how changes in security signals and policy thresholds affect simulated access decisions.

**The project is a simulation and educational demonstration, not a production Zero Trust implementation or a substitute for enterprise identity, endpoint, network or access-enforcement systems.**
