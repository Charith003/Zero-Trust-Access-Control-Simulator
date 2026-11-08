from __future__ import annotations


DEFAULT_POLICY = {
    "allow_max": 34,
    "challenge_max": 64,
    "weights": {
        "unknown_device": 16,
        "unusual_location": 14,
        "inconsistent_login": 8,
        "missing_mfa": 15,
        "anomalous_activity": 20,
        "failed_transactions": 10,
        "incident_reports": 7,
        "password_resets": 4,
        "long_session": 3,
        "high_access_frequency": 3,
        "sensitive_data": 10,
    },
}


ALIASES = {
    "user_id": ["user_id", "userid", "user", "identity", "employee_id"],
    "resource": ["resource", "resource_name", "requested_resource", "application"],
    "device_consistency": ["device_consistency", "deviceconsistent", "device_consistent"],
    "location_consistency": ["location_consistency", "access_location_consistency", "locationconsistent"],
    "login_consistency": ["login_consistency", "loginconsistent"],
    "mfa_status": ["mfa_status", "mfa", "mfa_enabled", "multifactor_authentication"],
    "anomalous_activity": ["anomalous_activity", "anomaly", "is_anomalous"],
    "failed_transactions": ["failed_transactions", "failed_logins", "failed_attempts"],
    "incident_reports": ["incident_reports", "incidents"],
    "password_resets": ["password_resets", "password_reset_count"],
    "session_duration": ["session_duration", "dwell_time", "duration"],
    "access_frequency": ["access_frequency", "frequency", "access_count"],
    "sensitive_data": ["sensitive_data", "access_to_sensitive_data", "sensitive_access"],
}


def _key(value):
    return "".join(char.lower() for char in str(value) if char.isalnum())


def _value(source, field, default):
    lookup = {_key(key): value for key, value in source.items()}
    for alias in ALIASES[field]:
        if _key(alias) in lookup and lookup[_key(alias)] not in (None, ""):
            return lookup[_key(alias)]
    return default


def _binary(value, default=0):
    if isinstance(value, bool):
        return int(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "enabled", "consistent", "success", "successful"}:
        return 1
    if text in {"0", "false", "no", "n", "disabled", "inconsistent", "failed"}:
        return 0
    try:
        return 1 if float(text) >= 0.5 else 0
    except ValueError:
        return default


def _number(value, default=0.0):
    text = str(value).strip()
    if ":" in text:
        try:
            parts = [float(part) for part in text.split(":")]
            if len(parts) == 3:
                return max(0.0, parts[0] * 60 + parts[1] + parts[2] / 60)
        except ValueError:
            return default
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return default


def normalise_record(source):
    login_raw = _number(_value(source, "login_consistency", 1), 1)
    login_consistency = int(login_raw >= 5) if login_raw > 1 else int(login_raw >= 0.5)
    return {
        "user_id": str(_value(source, "user_id", "UNKNOWN")),
        "resource": str(_value(source, "resource", "Enterprise Resource")),
        "device_consistency": _binary(_value(source, "device_consistency", 1), 1),
        "location_consistency": _binary(_value(source, "location_consistency", 1), 1),
        "login_consistency": login_consistency,
        "mfa_status": _binary(_value(source, "mfa_status", 0), 0),
        "anomalous_activity": _binary(_value(source, "anomalous_activity", 0), 0),
        "failed_transactions": int(_number(_value(source, "failed_transactions", 0))),
        "incident_reports": int(_number(_value(source, "incident_reports", 0))),
        "password_resets": int(_number(_value(source, "password_resets", 0))),
        "session_duration": _number(_value(source, "session_duration", 30)),
        "access_frequency": _number(_value(source, "access_frequency", 10)),
        "sensitive_data": _binary(_value(source, "sensitive_data", 0), 0),
    }


def evaluate_access(record, thresholds=None):
    thresholds = thresholds or DEFAULT_POLICY
    weights = DEFAULT_POLICY["weights"]
    score = 0.0
    reasons = []

    def add(condition, points, reason):
        nonlocal score
        if condition:
            score += points
            reasons.append(f"+{points} {reason}")

    add(not record["device_consistency"], weights["unknown_device"], "unfamiliar device")
    add(not record["location_consistency"], weights["unusual_location"], "unusual access location")
    add(not record["login_consistency"], weights["inconsistent_login"], "inconsistent login pattern")
    add(not record["mfa_status"], weights["missing_mfa"], "MFA not verified")
    add(record["anomalous_activity"], weights["anomalous_activity"], "anomalous activity detected")
    add(record["failed_transactions"] > 0, min(weights["failed_transactions"], 2 * record["failed_transactions"]),
        f"{record['failed_transactions']} failed transaction(s)")
    add(record["incident_reports"] > 0, min(weights["incident_reports"], 3 * record["incident_reports"]),
        f"{record['incident_reports']} incident report(s)")
    add(record["password_resets"] > 1, weights["password_resets"], "multiple password resets")
    add(record["session_duration"] > 120, weights["long_session"], "unusually long session")
    add(record["access_frequency"] > 50, weights["high_access_frequency"], "high access frequency")
    add(record["sensitive_data"], weights["sensitive_data"], "sensitive resource requested")

    score = min(100, round(score))
    if score <= thresholds["allow_max"]:
        decision, level = "ALLOW", "Low"
    elif score <= thresholds["challenge_max"]:
        decision, level = "CHALLENGE", "Medium"
    else:
        decision, level = "DENY", "High"
    if not reasons:
        reasons.append("No abnormal security signals detected")
    return {"score": score, "decision": decision, "level": level, "reasons": reasons}
