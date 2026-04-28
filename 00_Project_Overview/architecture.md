# 🏗️ SOC Architecture Overview

## 🎯 Purpose

This document defines the architecture of the simulated Security Operations Center (SOC) environment built using Splunk. 
It outlines how logs are generated, ingested, processed, and analyzed to detect and investigate security incidents.

---

## 🧩 Architecture Components

### 1. Log Sources (Simulated Environment)

The project simulates multiple enterprise log sources:

* 🖥️ **Windows Endpoints**

  * Process creation (EventCode 4688)
  * Registry changes (EventCode 4657)
  * Service creation (EventCode 7045)

* 🌐 **Web/Proxy Logs**

  * URL access
  * File downloads
  * HTTP methods and responses

* 🌍 **DNS Logs**

  * Domain queries
  * Data exfiltration indicators
  * Command & Control communication

* 📧 **Email Logs**

  * Phishing campaigns
  * Attachments (macro-enabled vs benign)
  * Sender/recipient analysis

---

### 2. Data Generation Layer

* Synthetic log generation using Python scripts
* Combines:

  * Baseline (normal activity)
  * Attack simulation
  * Noise (false positives)

This ensures:

* Realistic investigation scenarios
* Analyst decision-making complexity

---

### 3. Splunk SIEM Layer

#### 🔹 Indexing Strategy

| Log Source   | Splunk Index  |
| ------------ | ------------- |
| Web Logs     | index=web     |
| Windows Logs | index=windows |
| DNS Logs     | index=dns     |
| Email Logs   | index=email   |

---

#### 🔹 Data Processing

* Parsing raw logs into searchable fields
* Timestamp normalization
* Field extraction (user, IP, process, domain)

---

### 4. Detection Layer

Detection is implemented using SPL queries:

* Signature-based detection
* Behavior-based detection
* Anomaly detection

Examples:

* Suspicious PowerShell execution
* Rare domain access
* High-volume DNS queries

---

### 5. Investigation Layer

SOC-style investigation workflow:

1. Alert triggered
2. Analyst triage
3. Data pivoting across sources
4. Correlation of events
5. Timeline reconstruction

---

### 6. Reporting Layer

Each case includes:

* Incident report
* Attack timeline
* Indicators of Compromise (IOCs)
* Remediation steps

---

## 🔗 Architecture Flow (High-Level)

```
Log Sources → Data Generation → Splunk Ingestion → Parsing + Indexing → Detection → Investigation → Reporting
```

---

## 🧠 Key Design Principles

* **Multi-source correlation**
* **Realistic noise inclusion**
* **Behavior-driven detection**
* **Scalable dataset design**
* **Analyst-first approach**

---

## 🚀 Outcome

This architecture simulates a real enterprise SOC environment and demonstrates:

* End-to-end attack visibility
* Cross-domain investigation capability
* Practical SIEM usage skills
