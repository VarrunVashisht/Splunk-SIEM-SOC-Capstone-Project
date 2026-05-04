# 🛡️ Splunk SOC Project – APT Detection & Investigation Guide

## 📌 Overview

This project demonstrates how to detect and investigate a **multi-stage Advanced Persistent Threat (APT)** using Splunk.

### 📂 Data Sources (index = `soc_project`)

* Authentication Logs
* Cloud Activity Logs
* DNS Logs
* Email Logs
* File Access Logs
* Web Logs
* Windows Event Logs

---

# 🎯 APT Kill Chain Detection (10 Subcases)

---

# 🔐 Subcase 1: Initial Access Detection

## 📖 Goal

Identify suspicious login behavior such as:

* Multiple IP addresses for one user
* Rapid login attempts

## 🔍  Query

```spl
index=soc_project sourcetype=auth.log
| stats count by user, src_ip
| sort -count
```

## 🚀  Query

```spl
index=soc_project sourcetype=auth.log
| bucket _time span=5m
| stats dc(src_ip) as unique_ips count by user, _time
| where unique_ips > 5
```
<img width="1903" height="830" alt="image" src="https://github.com/user-attachments/assets/6be2b286-b31a-4e66-97a2-ca01a901159f" />

## 🧠 Explanation

* `count` → total login attempts
* `dc(src_ip)` → number of unique IPs
* `bucket` → groups events into 5-minute windows

## 📊 Insight

User **alice** logs in from many IPs → likely **credential compromise**

## What’s Happening

An attacker is attempting to log in using stolen credentials.

### What the Query Does
Counts login attempts
Tracks how many different IP addresses a user logs in from
### Why It Matters
Legitimate users typically log in from a small number of IPs. Multiple IPs in a short time suggests suspicious activity.

### Analyst Mindset
“Why is this user logging in from many locations at once?”

### Conclusion: 
 Possible credential compromised.
 
---

# 🛰️ Subcase 2: Reconnaissance Activity

## 📖 Goal

Detect unusual browsing patterns that suggest recon activity

## 🔍  Query

```spl
index=soc_project sourcetype=web.log
| stats count by user, url
```
## 🚀  Query

```spl
index=soc_project sourcetype=web.log
| stats dc(url) as unique_sites by user
| where unique_sites > 10
```

## 📊 Insight
High number of visited URLs → possible **internal reconnaissance**

### What’s Happening
The attacker explores the system after gaining access.

### What the Query Does
Counts how many unique URLs a user visits

### Why It Matters
Normal users access limited resources. Attackers browse widely to identify valuable targets.

### Analyst Mindset
“Is this normal browsing or someone mapping the environment?”

### Conclusion
👉 Possible internal reconnaissance

---

# 🎣 Subcase 3: Credential Harvesting (Phishing)

## 📖 Goal

Detect phishing campaigns

## 🔍  Query

```spl
index=soc_project sourcetype=email.log
| stats count by sender, attachment
```

## 🚀  Query

```spl
index=soc_project sourcetype=email attachment="*.docm"
| stats count by sender, recipient
| where count > 20
```

## 📊 Insight

Repeated `.docm` attachments → **macro-based phishing attack**

<img width="1902" height="549" alt="image" src="https://github.com/user-attachments/assets/e71841e5-2f01-42b8-8d86-4e99a03c813c" />


### What’s Happening
Attackers send phishing emails with malicious attachments.

### What the Query Does
Detects repeated emails with .docm files
Tracks sender-to-recipient patterns

### Why It Matters
.docm files can contain macros that execute malicious code.

### Analyst Mindset
“Why is one sender distributing many macro-enabled files?”

### Conclusion 
👉 Phishing campaign detected
---

# 🔁 Subcase 4: Lateral Movement

## 📖 Goal

Detect credential reuse across multiple systems

## 🔍  Query

```spl
index=soc_project sourcetype=auth.log
| stats values(src_ip) by user
```

## 🚀 Advanced Query

```spl
index=soc_project sourcetype=auth.log
| stats dc(src_ip) as ip_count by user
| where ip_count > 35
```
<img width="1906" height="557" alt="image" src="https://github.com/user-attachments/assets/729860e1-b1e2-4e32-a7d4-3686612fa023" />

## 📊 Insight
Multiple IP usage → **lateral movement using stolen credentials**

### What’s Happening
The attacker uses stolen credentials to access multiple systems.

### What the Query Does
Counts how many IPs a user connects from

### Why It Matters
A user accessing many systems is unusual and indicates possible spread of attack.

### Analyst Mindset
“Is this user moving across systems—or is someone else using their account?”

### Conclusion
👉 Lateral movement detected
---

# 🧬 Subcase 5: Persistence Mechanisms

## 📖 Goal
Detect repeated or automated process execution

## 🔍 Basic Query

```spl
index=soc_project sourcetype=windows.log EventCode=4688
| stats count by user, ProcessName
```

## 🚀 Advanced Query

```spl
index=soc_project sourcetype=windows.log EventCode=4688
| stats count by user, ProcessName, ParentProcess
| where count > 20
```
<img width="1896" height="565" alt="image" src="https://github.com/user-attachments/assets/c6514952-b4cc-4dfc-82ec-8c95463471b4" />

## 📊 Insight
Repeated processes (e.g., chrome.exe) → possible **persistence or beaconing**

### What’s Happening
The attacker establishes a way to stay in the system.

### What the Query Does
Tracks repeated execution of processes
Identifies unusually high execution counts

### Why It Matters
Malware often runs repeatedly or hides inside legitimate processes.

### Analyst Mindset
“Why is this process running excessively?”

### Conclusion 
👉 Possible persistence or malware activity
---

# 🌐 Subcase 6: Command & Control (C2)

## 📖 Goal
Detect communication with malicious domains

## 🔍  Query

```spl
index=soc_project sourcetype=dns.log
| stats count by query
```

<img width="1898" height="550" alt="image" src="https://github.com/user-attachments/assets/42d92f84-4389-4720-a195-a7d7e74460bd" />


## 🚀  Query

```spl
index=soc_project sourcetype=dns.log
| stats sum(bytes_out) as total_bytes by src_ip, query
| where total_bytes > 100000000
```
<img width="1876" height="733" alt="image" src="https://github.com/user-attachments/assets/ec4e4f9e-61ee-4ba0-8a29-8e58a53485ec" />

## 📊 Insight

High outbound traffic → possible **C2 communication**

### What’s Happening
The infected system communicates with the attacker’s server.

### What the Query Does
Measures outbound data sent to domains

### Why It Matters
Unusual outbound traffic may indicate communication with malicious infrastructure.

### Analyst Mindset
“Why is this system sending so much data to this domain?”

### Conclusion
👉 Active C2 communication
---

# 📦 Subcase 7: Data Collection

## 📖 Goal

Detect large-scale file access before exfiltration

## 🔍  Query

```spl
index=soc_project sourcetype=file.log
| stats count by user, file
```

## 🚀  Query

```spl
index=soc_project sourcetype=file.log
| stats sum(bytes) as total_bytes by user, file
| where total_bytes > 50000000
```
 <img width="1888" height="531" alt="image" src="https://github.com/user-attachments/assets/e16b05f8-407a-4e8a-a19a-5810e24191fc" />

## 📊 Insight

Repeated access to sensitive files → **data staging**

### What’s Happening
The attacker gathers sensitive data before exfiltration.

### What the Query Does
Tracks how much data is accessed per file

### Why It Matters
Frequent access to large or sensitive files may indicate staging for theft.

### Analyst Mindset
“Why is this user repeatedly accessing sensitive files?”

### Conclusion
👉 Data staging activity
---

# 🚨 Subcase 8: Data Exfiltration

## 📖 Goal

Detect outbound data transfers

## 🔍  Query

```spl
index=soc_project sourcetype=cloud.log action=PutObject
| stats sum(bytes) by bucket
```

## 🚀  Query

```spl
index=soc_project sourcetype=cloud.log action=PutObject bucket=external-data
| stats sum(bytes) as total_bytes by bucket
| where total_bytes > 100000000
```
<img width="1903" height="522" alt="image" src="https://github.com/user-attachments/assets/a55bc26f-1c0f-4423-8702-06d90226601d" />

## 📊 Insight

Large uploads → **confirmed data exfiltration**

### What’s Happening
The attacker transfers stolen data outside the organization.

### What the Query Does
Detects large uploads to external storage

### Why It Matters
Large outbound transfers are a strong indicator of data theft.

### Analyst Mindset
“Is this legitimate usage or unauthorized data transfer?”

### Conclusion
👉 Confirmed data exfiltration
---

# 🧩 Subcase 9: Long-Term Persistence

## 📖 Goal

Identify stealthy long-term attacker activity

## 🔍  Query

```spl
index=soc_project
| stats count by user
```

## 🚀  Query

```spl
index=soc_project
| timechart span=1h count by user
```

<img width="1884" height="614" alt="image" src="https://github.com/user-attachments/assets/ab16a09b-160b-47d1-824c-3b6d4ec145d0" />

## 📊 Insight

Continuous low activity → attacker maintaining **persistent access**

### What’s Happening
The attacker maintains access over time without being detected.

### What the Query Does
Tracks user activity over long time periods

### Why It Matters
APT attackers operate quietly and consistently to avoid detection.

### Analyst Mindset
“Why is this account continuously active at low levels?”

Conclusion
👉 Stealth persistence
---

# 🧠 Subcase 10: Full Attack Timeline

## 📖 Goal

Reconstruct the full attack sequence

## 🔍 Basic Query

```spl
index=soc_project
| table _time, sourcetype, user, src_ip, action
| sort _time
```

## 🚀 Advanced Query

```spl
index=soc_project
| eval stage=case(
    sourcetype="email","Initial Access",
    sourcetype="auth","Credential Use",
    sourcetype="web","Recon",
    sourcetype="file","Collection",
    sourcetype="dns","C2",
    sourcetype="cloud","Exfiltration"
)
| table _time, user, stage, src_ip, query, file
| sort _time
```
<img width="1791" height="882" alt="image" src="https://github.com/user-attachments/assets/d756864f-d840-44ae-b210-a020cb75fc5b" />

### What’s Happening
All attack stages are connected into a single timeline.

### What the Query Does
Categorizes events into attack stages
Orders events chronologically

### Why It Matters
Understanding the full attack helps:
Identify root cause
Measure impact
Improve defenses

### Analyst Mindset
“What is the attacker’s full journey from entry to data theft?”

Conclusion
👉 Complete attack reconstruction
---

# 🔥 Final Attack Summary

1. Phishing email delivered
2. Credentials stolen
3. Reconnaissance activity observed
4. Lateral movement across systems
5. Persistence established
6. C2 communication detected
7. Data collected and staged
8. Data exfiltrated
9. Long-term stealth presence maintained

---

# 🚨 Recommended SOC Actions

* Disable compromised accounts
* Block malicious domains
* Quarantine phishing emails
* Audit cloud storage usage
* Investigate endpoints for persistence

### 🔍 Detection Improvements

* Monitor macro-enabled attachments
* Detect unusual login behavior
* Identify DNS tunneling patterns

---

# 💡 Why This Project Matters

This project demonstrates:

* Real-world SOC investigation workflow
* Threat hunting skills
* Detection engineering mindset
* End-to-end APT analysis

---

## Author:
Varrun Vashisht
