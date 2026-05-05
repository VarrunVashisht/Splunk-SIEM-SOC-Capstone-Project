# 🛡️ Detection (DR) 1 — DNS Data Exfiltration

---

## 📌 Overview

This detection identifies potential **data exfiltration over DNS**, a common attacker technique used to bypass traditional network monitoring controls.

Attackers encode sensitive data into DNS queries and send it to attacker-controlled domains.

---

## 🧠 Attack Understanding

### 🔍 Why DNS?

* DNS is almost always allowed in networks
* Often not deeply inspected
* Easy channel for covert data transfer

### 🚨 Attack Pattern

1. Data is collected from the system
2. Encoded into DNS queries
3. Sent to malicious domain (e.g., `data.exfil.evil.com`)
4. Attacker reconstructs the data

---

## 📂 Evidence from Logs

Observed behavior:

* Repeated DNS queries to suspicious domain
* High volume of outbound data

Example:

* `query=data.exfil.evil.com`
* Large `bytes_out` values 

---

## 🔍 Detection Hypothesis

> If a host sends unusually large DNS traffic to suspicious domains, it may indicate data exfiltration.

---

## 🔎 SPL Development (Step-by-Step)

### ❌ Step 1 — Initial (Noisy Detection)

```spl
index=soc_project sourcetype="dns.log"
| stats sum(bytes_out) as total_bytes by src_ip, query
| sort - total_bytes
```

**Issues:**

* Too many results
* Includes legitimate traffic
* Not actionable

<img width="1887" height="816" alt="image" src="https://github.com/user-attachments/assets/1b6ec1cb-61b6-49bf-ab0d-7cf7c34e1b1e" />

---

### ⚙️ Step 2 — Improved Detection

```spl
index=soc_project sourcetype="dns.log"
| where like(query, "%.com")
| stats sum(bytes_out) as total_bytes by src_ip, query
| where total_bytes > 100000000
```
<img width="1898" height="753" alt="image" src="https://github.com/user-attachments/assets/d3616796-f75a-460e-8b69-61b85b9525dc" />

**Improvements:**

* Filters large data transfers
* Still includes noise

---

### 🚀 Step 3 — Final (Production-Ready Detection)

```spl
index=soc_project sourcetype="dns.log" query="*.evil.com"
| stats sum(bytes_out) as total_bytes count by src_ip
| where total_bytes >  100000000 AND count >= 5
| sort - total_bytes
```

**Why this works:**

* Focuses on suspicious domain pattern
* Applies threshold (10MB+)
* Requires repeated activity, `count`
* Reduces false positives significantly

<img width="1910" height="534" alt="image" src="https://github.com/user-attachments/assets/d1f713d0-cd3c-4f1b-80d8-0df497bb7945" />

---

## 📄 Detection-as-Code (YAML)

```yaml
title: Suspicious DNS Data Exfiltration
id: DET-001
description: Detects potential data exfiltration via DNS queries to suspicious domains

spl: |
   index=soc_project sourcetype="dns.log" query="*.evil.com"
   | stats sum(bytes_out) as total_bytes count by src_ip
   | where total_bytes >  100000000 AND count >= 5
   | sort - total_bytes

severity: Critical
confidence: High

mitre:
  - T1048

data_sources:
  - DNS Logs

false_positives:
  - Misconfigured applications generating high DNS traffic
  - Legitimate CDN or telemetry services

tuning:
  - Add domain whitelist
  - Adjust thresholds based on environment baseline
  - Add time-based anomaly detection

tags:
  - exfiltration
  - dns
  - data-loss
```

---

## 📉 Before vs After Tuning

### ❌ Before (Noisy)

```spl
 index=soc_project sourcetype="dns.log"
 | stats sum(bytes_out) by src_ip
```

* Produces excessive results
* Not useful for analysts

---

### ✅ After (Optimized)

```spl
  index=soc_project sourcetype="dns.log" query="*.evil.com"
   | stats sum(bytes_out) as total_bytes count by src_ip
   | where total_bytes >  100000000 AND count >= 5
   | sort - total_bytes
```

* Focused results
* High-confidence detection

---

## 🗺️ MITRE ATT&CK Mapping

| Technique | Name                                   |
| --------- | -------------------------------------- |
| T1048     | Exfiltration Over Alternative Protocol |

---

## 🧪 Validation (Using Project Logs)

The dataset shows:

* Multiple hosts sending large DNS traffic
* Repeated queries to suspicious domain

Example:

* `data.exfil.evil.com` with high `bytes_out` 

👉 This confirms the detection logic is valid and effective.

---

## 🚨 SOC Analyst Response

When this alert triggers:

1. Identify affected host (`src_ip`)
2. Check associated user activity
3. Correlate with:

   * File access logs
   * Authentication logs
4. Block malicious domain
5. Isolate compromised system

---

## 🧠 Advanced Enhancements

### ⏱️ Time-Based Detection

```spl
| bucket _time span=5m
```

### 📊 Baseline Comparison

```spl
| eventstats avg(total_bytes) as avg_bytes by src_ip
```

### ⚠️ Risk Scoring

```spl
| eval risk_score = total_bytes / 1000000
```

---

## 🧱 Key Learnings

* Detection requires iteration (not one query)
* Noise reduction is critical
* Context improves accuracy
* Mapping to MITRE strengthens detection value
* Real logs validation is essential

---

## 🏁 Final Thought

> “High-quality detections don’t just find threats — they reduce noise and drive action.”

---

## Author:
Varrun Vashisht
