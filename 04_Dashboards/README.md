## 📊 Dashboards – Security Monitoring & Threat Detection

This section showcases **production-grade Splunk dashboards** designed to simulate real-world Security Operations Center (SOC) investigations. 
Each dashboard is built using structured detection logic, correlated data sources, and analyst-driven insights to provide actionable visibility into security incidents.

The dashboards focus on **end-to-end attack detection**, moving beyond isolated alerts to present a complete attack narrative - from initial access to post-compromise activity.

---

## 🔍 What is Covered

### 🚨 Phishing Campaign Overview

This dashboard provides visibility into large-scale phishing operations by analyzing email telemetry.

It identifies:

* High-volume email campaigns from suspicious senders
* Targeted users and attack spread patterns
* Reused malicious attachments (e.g., macro-enabled files)
* Time-based spikes indicating automated phishing activity

The goal is to enable early detection of phishing campaigns and prioritize at-risk users before compromise occurs.

---

### 📡 Data Exfiltration Investigation

This dashboard focuses on detecting covert data exfiltration using DNS activity.

It highlights:

* Suspicious domains associated with data exfiltration
* High-volume outbound data transfers
* Compromised hosts communicating with external infrastructure
* Time-based patterns indicating data extraction behavior

By correlating DNS activity with abnormal data transfer volumes, this dashboard helps identify stealthy data breaches and supports rapid incident response.

---

## 🧠 Key Design Principles

* **Correlation-Driven Detection**
  Combines multiple log sources (Email, DNS, etc.) to reconstruct attack scenarios.

* **Analyst-Centric Visualization**
  Dashboards are designed to reduce investigation time and highlight critical signals.

* **Real-World Attack Simulation**
  Each dashboard reflects realistic adversary techniques such as phishing campaigns and DNS-based exfiltration.

* **Actionable Insights**
  Focuses on decision-making, not just data display — enabling faster triage and response.

---

## 💼 Why This Matters

These dashboards demonstrate the ability to:

* Build **end-to-end detection workflows**
* Translate raw logs into **security intelligence**
* Design **SOC-ready monitoring solutions**
* Communicate threats clearly to both technical and business stakeholders

---

## Author:
Varrun Vashisht
