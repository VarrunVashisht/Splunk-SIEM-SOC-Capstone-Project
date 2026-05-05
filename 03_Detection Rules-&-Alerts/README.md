# 🛡️ Detection Engineering 

## 📌 Overview

Detection Engineering is the process of **designing, building, testing, and maintaining security detections** that identify malicious activity within an environment.

In a modern SOC, detections are not just queries — they are **structured, version-controlled, continuously improved security logic**.

This folder contains **Detection-as-Code (DaC)** implementations using Splunk SPL, mapped to real-world attack scenarios.

---

## 🎯 Objectives

* Detect malicious activity using log data
* Reduce false positives through tuning
* Align detections with MITRE ATT&CK framework
* Implement Detection-as-Code (YAML/JSON)
* Simulate real-world SOC detection workflows

---

## 🧠 What is Detection Engineering?

Detection Engineering sits between:

| Domain              | Role                   |
| ------------------- | ---------------------- |
| Threat Intelligence | What attackers do      |
| Security Monitoring | What logs show         |
| Incident Response   | What actions are taken |

👉 A Detection Engineer translates attacker behavior into **log-based detection logic**

---

## 🔁 Detection Lifecycle

Every detection in this project follows a structured lifecycle:

1. **Hypothesis**

   * Example: “Attackers may exfiltrate data via DNS”

2. **Data Source Identification**

   * DNS logs, Windows logs, Email logs, etc.

3. **SPL Query Development**

   * Build initial query (usually noisy)

4. **Validation**

   * Test against real/simulated data

5. **Tuning**

   * Reduce noise (false positives)
   * Improve accuracy

6. **Deployment**

   * Convert into alert

7. **Monitoring & Improvement**

   * Continuous refinement

---

## 📂 Folder Structure

```
detections/
│
├── dns_exfiltration.yaml
├── phishing_macro.yaml
├── brute_force.yaml
└── README.md
```
<img width="1906" height="400" alt="image" src="https://github.com/user-attachments/assets/cf1884e2-315c-41c1-9e5b-b70bfc7be460" />

---

## 🧾 Detection-as-Code (DaC)

Each detection is written in **YAML format** for:

* Version control (GitHub)
* Reusability
* Standardization
* Automation readiness

---

## 🧩 Detection Template (Standard Format)

```yaml
title: <Detection Name>
id: <Unique ID>
description: <What this detects>

spl: <Splunk Query>

severity: Low / Medium / High / Critical
confidence: Low / Medium / High

mitre: <MITRE Technique ID>

data_sources:
  - DNS
  - Windows
  - Email

false_positives:
  - Possible legitimate scenarios

tuning:
  - Improvements to reduce noise

references:
  - MITRE / Blogs / Threat Reports
```

---

## 🗺️ MITRE ATT&CK Mapping

Each detection is mapped to MITRE ATT&CK to:

* Standardize detection coverage
* Align with industry frameworks
* Improve threat visibility

Example:

| Detection        | MITRE Technique |
| ---------------- | --------------- |
| DNS Exfiltration | T1048           |
| Phishing         | T1566           |
| Lateral Movement | T1021           |

---

## ⚠️ False Positives vs True Positives

### False Positives (FP)

Legitimate activity that looks malicious

Example:

* Large file transfer by backup system

### True Positives (TP)

Actual malicious activity

Example:

* Data exfiltration to unknown domain

👉 Goal: Reduce FP without missing TP

---

## 🔧 Tuning Strategy

Tuning is critical in detection engineering.

### Before Tuning:

* Too many alerts
* Analyst fatigue
* Low trust

### After Tuning:

* High-confidence alerts
* Actionable signals
* Reduced noise

### Common Techniques:

* Threshold filtering
* Whitelisting trusted entities
* Time-based analysis
* Behavior baselining

---

## 📊 Example: Before vs After

### ❌ Before (Noisy Detection)

```spl
index=dns,log
| stats sum(bytes_out) by src_ip
```

### ✅ After (Tuned Detection)

```spl
index=dns.log query="*.evil.com"
| stats sum(bytes_out) by src_ip
| where sum(bytes_out) > 10000000
```

---

## 🔍 Types of Detections Covered

This project includes:

### 1. Signature-Based Detection

* Known patterns
* Example: malicious domain

### 2. Behavior-Based Detection

* Unusual activity
* Example: login from multiple IPs

### 3. Anomaly Detection

* Deviations from baseline
* Example: rare processes

---

## 🧪 Data Sources Used

* Authentication Logs
* DNS Logs
* Email Logs
* File Access Logs
* Windows Event Logs
* Web Traffic Logs

---

## 🚨 Severity Classification

| Severity | Meaning         |
| -------- | --------------- |
| P1       | Critical threat |
| P2       | High risk       |
| P3       | Medium          |
| P4       | Low             |

---

## 🧠 Key Concepts You Must Understand

* Logs ≠ Detection (logic is required)
* Noise is normal (tuning is key)
* Context matters (user, time, behavior)
* Detection is iterative (never “done”)

---

## ⚡ Best Practices

* Always map to MITRE ATT&CK
* Keep queries simple and readable
* Document everything
* Use version control (Git)
* Continuously tune detections
* Test with real or simulated data

---

## 🔗 How This Connects to SOC

Detection Engineering feeds directly into:

```
Detection → Alert → Triage → Incident → Response
```

---

## 🚀 Next Steps

After building detections:

* Convert them into alerts (`alerting/`)
* Investigate triggered alerts (`incident response`)
* Perform proactive searches (`threat hunting/`)
* Visualize insights (`dashboards/`)

---

## 🏁 Final Thought

> “A good detection finds attacks.
> A great detection finds attacks without overwhelming analysts.”

---

## Author:
Varrun Vashisht
