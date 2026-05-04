# 🔐 Splunk SIEM SOC Capstone Project

## 📌 Overview

This repository contains a comprehensive **Security Operations Center (SOC) Capstone Project** built using **Splunk SIEM**. It simulates real-world cyber attack scenarios and provides structured investigation workflows across multiple attack types.

Each case is broken down into **10 detailed subcases**, covering detection, analysis, correlation, and full attack timeline reconstruction.

---

## 🎯 Objectives

* Develop hands-on SOC investigation skills
* Detect and analyze real-world attack patterns
* Build and refine Splunk queries for threat detection
* Correlate events across multiple data sources
* Reconstruct complete attack timelines

---

## 🛠️ Tools & Technologies

* Splunk SIEM
* SPL (Search Processing Language)
* Windows Event Logs
* Sysmon Logs
* Network Logs (DNS, HTTP, Traffic)

---

## 📂 Project Structure

```
02_Investigation_Cases/
│
├── case1_phishing_investigation.md
├── case2_bruteforce_investigation.md
├── case3_ransomware_investigation.md
├── case4_command&control_C2_investigation.md
├── case5_privilege_escalation_investigation.md
├── case6_cloud_attack.md
├── case7_Living-off-the-Land_(LotL)_Attacks.md
├── case8_Advanced_Persistent_Threat_(APT)_Detection_&_Analysis.md
└── readme.md
```

---

# 🚨 Investigation Cases

## 1️⃣ Phishing Attack

* Phishing Domain Identification
* Email Campaign Analysis
* User Click Behavior
* Malicious Attachment Execution
* Suspicious Process Creation
* PowerShell Abuse Detection
* Persistence Mechanism Identification
* DNS Callback Analysis
* Data Exfiltration Detection
* Full Attack Timeline Reconstruction

---

## 2️⃣ Brute Force Attack

* Failed Login Spike Detection
* Source IP Analysis
* Username Enumeration
* Successful Login After Failures
* Account Lockout Events
* Geographic Anomalies
* Credential Stuffing Patterns
* Multi-Account Targeting
* Persistence After Access
* Attack Timeline Reconstruction

---

## 3️⃣ Ransomware

* Suspicious File Execution
* Mass File Modification Detection
* Encryption Activity Patterns
* Shadow Copy Deletion
* Registry Changes for Persistence
* Network Spread Detection
* Command-Line Indicators
* C2 Communication Detection
* Data Exfiltration Indicators
* Full Incident Timeline

---

## 4️⃣ Command & Control (C2)

* Suspicious DNS Queries
* Beaconing Behavior Detection
* Known Malicious IP Communication
* Encrypted Traffic Anomalies
* Domain Generation Algorithm (DGA) Detection
* Unusual Port Usage
* Persistent Outbound Connections
* Data Transfer Patterns
* Endpoint Correlation
* C2 Timeline Reconstruction

---

## 5️⃣ Privilege Escalation

* Unauthorized Privilege Changes
* Suspicious Admin Logins
* Token Manipulation Detection
* Exploit Execution Indicators
* Service Creation Abuse
* Scheduled Task Abuse
* Credential Dumping Detection
* Lateral Movement Indicators
* Elevated Process Execution
* Escalation Timeline

---

## 6️⃣ Cloud Attack

* Suspicious API Calls
* Unauthorized Access Attempts
* IAM Role Abuse
* Data Exposure Events
* Unusual Resource Creation
* Geographic Access Anomalies
* Credential Leakage Detection
* Storage Access Patterns
* Data Exfiltration from Cloud
* Cloud Attack Timeline

---

## 7️⃣ Living-off-the-Land (LotL) Attacks

* Legitimate Tool Abuse Detection
* PowerShell Misuse
* WMI Execution Analysis
* Scheduled Task Abuse
* Registry Manipulation
* Fileless Malware Indicators
* Command-Line Anomalies
* Lateral Movement via Native Tools
* Persistence via Built-in Utilities
* Activity Timeline Reconstruction

---

## 8️⃣ Advanced Persistent Threat (APT)

* Initial Access Detection
* Reconnaissance Activity
* Credential Harvesting
* Lateral Movement Detection
* Persistence Mechanisms
* Command & Control Communication
* Data Collection Activities
* Data Exfiltration Detection
* Long-Term Presence Indicators
* Full APT Timeline Reconstruction

---

## 🔍 Key Features

* End-to-end attack investigations
* Realistic SOC workflows
* Advanced SPL query development
* Threat detection + correlation logic
* Timeline reconstruction for every attack

---

## 📈 Learning Outcomes

By completing this project, you will:

* Understand attacker behavior across multiple stages
* Gain expertise in Splunk-based threat detection
* Improve incident investigation and response skills
* Learn how to correlate logs across endpoints and network

---


## Author:
Varrun Vashisht
