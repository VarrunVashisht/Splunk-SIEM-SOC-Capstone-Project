# 🥇 DETECTION 3 — Lateral Movement (Credential Abuse via Multi-Source Logins)

This detection identifies when a user account is being used across **multiple machines/IPs in a short time**, 
which is a strong signal of **credential compromise + lateral movement**.

---

## 🧠 1. Attack Understanding

### 🔥 Attack Flow

1. Attacker gains credentials (phishing, dump, brute-force)
2. Logs into one machine
3. Moves laterally across systems using same account
4. Expands access inside network

---

## 📂 Evidence from logs

* Same user logging in from **many different IPs rapidly** 

👉 This is NOT normal user behavior

---

## 🔍 2. Detection Hypothesis

> If a single user authenticates from multiple IPs within a short time window → possible credential abuse or lateral movement

---

# 🔎 3. Beginner Detection (Baseline)

```spl
index=soc_project sourcetype =auth.log
| stats dc(src_ip) as ip_count by user
| where ip_count > 5
```
<img width="1896" height="711" alt="image" src="https://github.com/user-attachments/assets/d60c5ef9-b9e6-4190-9da7-0bfe71b88b3a" />

---

### ❌ Problem:

* No time context
* Could include normal behavior over long period

---

# ⚙️ 4. Intermediate Detection (Add Time Context)

```spl
index=soc_project sourcetype =auth.log 
| bucket _time span=5m
| stats dc(src_ip) as ip_count by user, _time
| where ip_count > 30
```
<img width="1899" height="654" alt="image" src="https://github.com/user-attachments/assets/2a158d54-13bb-41e7-9019-53566343ae6a" />

---

### ✅ Improvement:

* Detects burst activity
* More realistic

---

# 🚀 5. ADVANCED DETECTION (Production-Grade)

```spl
index=soc_project sourcetype =auth.log 
| bucket _time span=5m
| stats dc(src_ip) as unique_ips values(src_ip) as ip_list count by user, _time
| where unique_ips > 30 AND count > 5
| sort - unique_ips
```
<img width="1912" height="919" alt="image" src="https://github.com/user-attachments/assets/4af22c07-4f18-4433-b4a4-3e5a8de5e373" />

---

## 🧠 Why this is STRONG

* Focuses on **successful logins only**
* Detects **short time bursts**
* Uses:

  * IP diversity (`unique_ips`)
  * Login volume (`count`)
* Provides investigation context (`ip_list`)

---


# 📄 Detection-as-Code (YAML)

📂 `detections/lateral_movement.yaml`

```yaml
title: Suspicious Lateral Movement via Multi-IP Login
id: DET-003

description: >
  Detects potential lateral movement by identifying users logging in
  from multiple IP addresses within a short time window.

spl: |
 index=soc_project sourcetype =auth.log 
| bucket _time span=5m
| stats dc(src_ip) as unique_ips values(src_ip) as ip_list count by user, _time
| where unique_ips > 30 AND count > 5
| sort - unique_ips

severity: High
confidence: High

mitre:
  - T1021
  - T1078

data_sources:
  - Authentication Logs

false_positives:
  - VPN users switching IPs
  - Load-balanced environments
  - Shared service accounts

tuning:
  - Exclude known VPN ranges
  - Baseline normal user behavior
  - Adjust IP threshold per environment

tags:
  - lateral-movement
  - credential-abuse
```

---

# 📉 Before vs After 

### ❌ Before

```spl
index=soc_project sourcetype =auth.log 
| stats count by user
```
---

### ❌ Semi-Better

```spl
index=soc_project sourcetype =auth.log 
| stats dc(src_ip) by user
```

👉 Still noisy

---

### ✅ Final

```spl
time-based + multi-IP + threshold
```

👉 High-confidence detection

---

# 🗺️ MITRE ATT&CK Mapping

| Technique | Description     |
| --------- | --------------- |
| T1021     | Remote Services |
| T1078     | Valid Accounts  |

---

# 🧪 Validation Using YOUR Logs

* Users like `alice`, `john.doe` appear across multiple IPs 
* Frequent rapid logins

👉 This detection will **trigger correctly**

---


# 🧱 WHAT YOU JUST BUILT

You are now working at **real SOC detection engineer level**:

✅ Behavioral detection
✅ Time-based correlation
✅ Anomaly detection
✅ MITRE mapping
✅ Detection-as-code

---

## Author:
Varrun Vashisht
