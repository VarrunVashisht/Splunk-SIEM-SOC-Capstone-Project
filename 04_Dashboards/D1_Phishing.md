## 📊 Dashboard: Phishing Campaign Overview

### 🎯 Objective

This dashboard detects and visualizes phishing campaigns using email log data. 
It helps identify malicious senders, targeted users, and suspicious attachment patterns.

---

### 📂 Data Source

* **index** soc_project
* **sourcetype:** email.log
* **Fields Used:** sender, recipient, attachment, timestamp
                    sender → Who sent the email
                    recipient → Who received it
                    attachment → File attached
                    timestamp → When it happened
---

### 🔍 Problem Statement

Phishing attacks are one of the most common initial access vectors used by attackers. 
These attacks typically involve sending malicious emails with infected attachments or links to multiple users within an organization.

---

### 🧠 Detection Approach

# 🧠 Phishing Detection Dashboard

This document outlines a detection strategy for identifying phishing campaigns using email data in Splunk.

---

## 📊 1. Volume Analysis

### Query

```spl
index=soc_project sourcetype=email.log
| stats count as total_emails
```
<img width="1894" height="248" alt="image" src="https://github.com/user-attachments/assets/59903717-1b97-4f5d-9caf-86728b4bfbe8" />

### Description

Counts the total number of email events.

### Purpose

A sudden spike in email volume may indicate a phishing campaign, as attackers typically send emails in bulk.

### Outcome

* Single metric: total emails
* Unusual spikes suggest potential phishing activity

---

## 🎯 2. Target Analysis

### Query

```spl
index=soc_project sourcetype=email.log
| stats count by recipient
| sort - count
```

### Description

Groups emails by recipient and counts how many emails each user received.

### Purpose

Attackers often target specific individuals (e.g., admins, finance teams).

### Outcome

* Ranked list of recipients
* High-volume recipients are potential targets

<img width="1891" height="279" alt="image" src="https://github.com/user-attachments/assets/ef4103c3-3d3a-46d2-8be8-a63edb137f72" />

---

## ⏱️ 3. Time-Based Analysis

### Query

```spl
index=soc_project sourcetype=email.log
| timechart span=1m count
```

### Description

Tracks email volume over time in 3-minute intervals.

### Purpose

Phishing campaigns often occur in bursts rather than steady traffic.

### Outcome

* Time-series visualization
* Sharp spikes indicate suspicious activity windows

<img width="1895" height="244" alt="image" src="https://github.com/user-attachments/assets/7dc86835-20db-4bfe-981b-6a56a2dc0181" />

---

## 📎 4. Attachment Analysis

### Query

```spl
index=soc_project sourcetype=email.log
| stats count by attachment
```

### Description

Counts how often each attachment appears.

### Purpose

Phishing campaigns frequently reuse the same malicious files (e.g., `.docm`, `.html`).

### Outcome

* List of attachments with frequency
* Repeated files may indicate malicious payloads

<img width="1894" height="202" alt="image" src="https://github.com/user-attachments/assets/760412c1-e6b9-4b4a-bc67-7997bf93ce94" />

---

## 📤 5. Sender Analysis

### Query

```spl
index=soc_project sourcetype=email.log
| stats count by sender
```

### Description

Counts how many emails each sender has sent.

### Purpose

A sender distributing a high volume of emails is a strong phishing indicator.

### Outcome

* Sender frequency list
* High-volume senders should be investigated
  
<img width="1911" height="117" alt="image" src="https://github.com/user-attachments/assets/4b2ea22f-2600-4af3-9f8e-02b9f8d44182" />

---
### 📊 Complete Dashboard - Phishing Campaign

[email_volume_analysis-2026-05-05.pdf](https://github.com/user-attachments/files/27400581/email_volume_analysis-2026-05-05.pdf)

---

### 📊 Key Insights

* A single sender (`it-support@secure-login.com`) is targeting multiple users
* Repeated use of `.docm` attachment indicates macro-based malware delivery
* Email activity shows burst patterns, indicating automated phishing campaigns
* Multiple users are targeted within a short time window

---

### 🚨 Security Impact

* High risk of malware infection via macro-enabled documents
* Potential credential theft or system compromise
* Widespread exposure across multiple users

---

### 💼 Business Value

* Enables early detection of phishing campaigns
* Helps SOC teams prioritize response efforts
* Reduces risk of initial compromise
* Supports proactive threat hunting

---

### 🧾 Author:
Varrun Vashisht


