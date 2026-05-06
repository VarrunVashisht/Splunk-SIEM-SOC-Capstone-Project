# 🛡️ Splunk SOC Detection Engineering Project

## 📌 Overview

This project demonstrates practical **Security Operations Center (SOC)** skills using Splunk SIEM through real-world attack simulations, log analysis, and incident reporting.

The goal is to showcase **detection engineering, threat hunting, and incident response capabilities** aligned with industry standards.

All use cases are built using realistic multi-source logs, including:

* Authentication logs
* Email logs
* DNS logs
* File activity logs
* Web traffic logs

Each case includes:

* SPL detection queries (intermediate + advanced)
* Full incident investigation
* MITRE ATT&CK mapping
* Professional incident reports

---

## 🎯 Project Objectives

* Develop hands-on experience with Splunk SIEM
* Simulate real-world cyber attack scenarios
* Build detection logic using SPL
* Correlate multi-source logs
* Create industry-standard incident reports
* Demonstrate SOC analyst and detection engineering skills

---

## 🚨 Use Cases Covered

### 1️⃣ Phishing Attack → Data Exfiltration

**Scenario:**
A phishing campaign delivers a malicious macro-enabled attachment (`reset.docm`) to multiple users. Upon execution, compromised systems initiate DNS-based data exfiltration.

**Key Skills Demonstrated:**

* Email threat analysis
* Malicious attachment detection
* DNS exfiltration detection
* File access correlation
* Full attack chain reconstruction

**Detection Highlights:**

* Mass phishing campaign identification
* High-volume DNS traffic anomaly detection
* Sensitive file access prior to exfiltration

**MITRE ATT&CK Techniques:**

* T1566 – Phishing
* T1204 – User Execution
* T1071.004 – DNS Tunneling
* T1041 – Exfiltration Over C2 Channel

---

### 2️⃣ Brute Force Attack → Account Takeover

**Scenario:**
Multiple login attempts from different source IPs target user accounts. After repeated failures, the attacker successfully authenticates, leading to account compromise.

**Key Skills Demonstrated:**

* Authentication log analysis
* Brute force detection
* Credential compromise identification
* Behavioral anomaly detection

**Detection Highlights:**

* Failed login spike detection
* Successful login after multiple failures
* Multi-IP login anomaly detection

**MITRE ATT&CK Techniques:**

* T1110 – Brute Force
* T1078 – Valid Accounts

---

## 🧠 Detection Engineering Approach

This project follows a structured detection methodology:

1. **Log Analysis** – Identify relevant data sources
2. **Threat Hypothesis** – Define attacker behavior
3. **SPL Query Development** – Build detection logic
4. **Correlation** – Link events across logs
5. **Investigation** – Validate suspicious activity
6. **Reporting** – Document findings professionally

---

## 🔍 Sample SPL Queries

### Detect Phishing Campaign

```spl
index=soc_project sourcetype=email.log
| stats count by sender, recipient, attachment
| where count > 5
```

### Detect DNS Data Exfiltration

```spl
index=soc_project sourcetype=dns.log 
| stats sum(bytes_out) as total_data by src_ip, query
| where total_data > 10000000
```

### Detect Brute Force + Successful Login

```spl
index=soc_project sourcetype=auth.log
| stats count(eval(status="failure")) as failed_attempts 
        count(eval(status="success")) as success_attempts 
        by user
| where failed_attempts > 5 AND success_attempts > 0
```

---

## 📊 Skills Demonstrated

* Splunk SIEM (SPL Querying)
* Log Correlation & Analysis
* Threat Detection & Hunting
* Incident Response
* MITRE ATT&CK Mapping
* Security Reporting
* Cyber Attack Simulation

---

## 🧩 Tools & Technologies

* Splunk Enterprise
* Windows Logs
* DNS Logs
* Email Logs
* Web Logs

---

## 🚀 Why This Project Matters

This project demonstrates the ability to:

* Detect real-world attack patterns
* Correlate events across multiple data sources
* Build actionable detections
* Communicate findings clearly through professional reports

It reflects practical skills expected from:

* SOC Analyst (Tier 1 / Tier 2)
* Detection Engineer
* Blue Team Security Analyst

---

## 📬 About Me:
Name: Varrun Vashisht

Cyber Security Professional with hands-on experience in:

* Splunk SIEM
* Threat Detection
* Incident Analysis

Focused on building real-world, job-ready security projects.

---
