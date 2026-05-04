# 📊 Synthetic Security Log Generator using Python

This project generates **realistic synthetic security logs** for use in **threat detection, SIEM testing, and cybersecurity training**.

It simulates both **normal activity (baseline noise)** and multiple **attack scenarios**, producing logs across different sources such as web, authentication, DNS, and system events.

---

## 🚀 Features

* Generates **multi-source logs**:

  * Web logs
  * Windows event logs
  * DNS logs
  * Email logs
  * Authentication logs
  * Cloud activity logs
  * File access logs

* Simulates **10 different security scenarios**, including:

  * Phishing attacks
  * Web exploitation (SQL injection, web shells)
  * Insider data exfiltration
  * Brute-force login attempts
  * Ransomware activity
  * Command & Control (C2) beaconing
  * Privilege escalation
  * Suspicious cloud uploads
  * Living-off-the-land binaries (LOLBins)
  * Advanced Persistent Threat (APT) behavior

* Outputs both **individual log files** and a **combined dataset**

---

## 📂 Generated Files

After running the script, the following files are created:

```
web.log
windows.log
dns.log
email.log
auth.log
cloud.log
file.log
combined.log
```

The `combined.log` file aggregates all logs for easier ingestion into SIEM tools.

---

## ⚙️ How It Works

The script:

1. Defines a set of:

   * Users
   * IP addresses
   * Domains
2. Generates timestamps starting from:

   ```
   2026-04-01 08:00:00
   ```
3. Creates:

   * **Baseline activity** (normal user behavior)
   * **Injected attack scenarios**
4. Writes logs into structured text files

Source reference: 

---

## 🧠 Simulated Attack Scenarios

### 1. Phishing Attack

* Malicious email with `.docm` attachment
* PowerShell execution via Word
* DNS-based data exfiltration

### 2. Web Attack

* SQL injection attempts
* File upload (web shell)
* Command execution via web shell

### 3. Insider Threat

* Large file access (`finance.xlsx`)
* Suspicious login time (02:30 AM)

### 4. Brute Force Attack

* Repeated failed logins
* Eventual successful login

### 5. Ransomware

* File renaming with `.encrypted`
* Suspicious process execution

### 6. Command & Control (C2)

* Periodic DNS beaconing (`interval=60s`)

### 7. Privilege Escalation

* Elevated privilege assignment (`SeDebugPrivilege`)

### 8. Cloud Exfiltration

* Large uploads to external bucket

### 9. LOLBins Abuse

* `certutil.exe` used for malicious downloads

### 10. APT Simulation

* Multi-stage attack:

  * Phishing
  * PowerShell execution
  * C2 communication
  * Data staging (`secret.zip`)

---

## 🛠️ Usage

### Requirements

* Python 3.x

### Run the script

```bash
python generate_logs.py
```

### Output

```bash
✅ Dataset generated successfully!
```

---

## 🔍 Example Log Entries

### Web Log

```
timestamp=2026-04-01 08:05:00 index=web user=alice url=http://google.com action=allowed
```

### Windows Log

```
EventCode=4688 index=windows User=alice ProcessName=chrome.exe ParentProcess=explorer.exe
```

### Auth Log

```
timestamp=2026-04-01 08:05:00 index=auth user=alice action=login status=success src_ip=192.168.1.23
```

---

## 🎯 Use Cases

* SIEM detection rule testing (Splunk, Elastic, Sentinel)
* Cybersecurity labs & training environments
* Threat hunting practice
* Machine learning datasets for anomaly detection

---

## 📌 Customization

You can easily modify:

* Number of logs generated
* Attack scenarios
* Users / IP ranges
* Time intervals
* Log formats

Example:

```python
users = ["john.doe", "alice", "bob"]
```

---

## Author:
Varrun Vashisht
Cybersecurity Professional

