# 🔄 Data Flow Design

## 🎯 Purpose

This document explains how data flows through the SOC pipeline—from log generation to final investigation and reporting.

---

## 🧩 End-to-End Data Flow

```
Log Generation → Log Files → Splunk Ingestion → Parsing + Indexing → Search & Detection → Investigation → Reporting
```

---

## 🪵 Step 1: Log Generation

Logs are generated using Python scripts and structured into:

* Baseline logs (normal user behavior)
* Attack logs (malicious activity)
* Noise logs (irrelevant events)

---

## 📁 Step 2: Log Storage

Logs are stored in structured directories:

```
case1_phishing/
├── web.log
├── windows.log
├── dns.log
├── email.log
├── combined.log
```

---

## 📥 Step 3: Splunk Ingestion

Logs are ingested into Splunk using:

* Add Data (manual upload)
* Assigned indexes per log type

---

## 🗂️ Step 4: Indexing Strategy

| Index         | Description                   |
| ------------- | ----------------------------- |
| index=web     | Web traffic and user browsing |
| index=windows | Endpoint activity             |
| index=dns     | DNS queries and exfiltration  |
| index=email   | Email/phishing logs           |

---

## 🔍 Step 5: Search & Detection

Analysts use SPL queries to:

* Identify anomalies
* Detect known attack patterns
* Correlate multi-source events

---

### 🔹 Detection Types

* Rule-based detection
* Behavioral detection
* Statistical anomaly detection

---

## 🔗 Step 6: Correlation

Correlation is performed by pivoting across:

* User
* IP address
* Domain
* Process

Example:

* Email → Web → Endpoint → DNS

---

## 🧠 Step 7: Investigation Workflow

1. Identify suspicious event
2. Validate anomaly
3. Pivot across logs
4. Build attack chain
5. Confirm compromise

---

## 🕒 Step 8: Timeline Reconstruction

Events are ordered chronologically to map:

* Initial access
* Execution
* Persistence
* Exfiltration

---

## 📊 Step 9: Output & Reporting

Final outputs include:

* Investigation notes
* Attack timeline
* Indicators of Compromise (IOCs)
* Recommendations

---

## ⚡ Key Data Flow Concepts

* **Separation of log sources**
* **Correlation across indexes**
* **Noise vs signal analysis**
* **Time-based investigation**
* **User-centric tracking**

---

## 🚀 Outcome

This data flow design enables:

* Realistic SOC investigations
* Multi-layer threat detection
* End-to-end attack visibility
