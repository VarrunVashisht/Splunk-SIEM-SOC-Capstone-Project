# MITRE ATT&CK Mapping – SOC Detection Project

## 🎯 Objective
This document maps all detected attack scenarios from the Splunk SOC project to the MITRE ATT&CK framework.  
The goal is to demonstrate how raw log events correlate to real-world adversary tactics, techniques, and procedures (TTPs).

---

# 🧠 Why This Matters 
Mapping detections to MITRE ATT&CK shows:
- You understand attacker behavior (not just logs)
- You can align detections with industry standards
- You think like a SOC Analyst / Threat Hunter

---

# 🪝 ATTACK SCENARIO 1: PHISHING ATTACK

## 🔍 Observed Evidence
- Suspicious email campaign delivering macro-enabled attachment  
- Repeated emails from same sender across multiple users  
- DNS queries to suspicious domain  
- Data exfiltration observed post-compromise  

📌 Log Evidence:
- Email logs show attachment `reset.docm` sent to multiple users :contentReference[oaicite:0]{index=0}  
- DNS logs show communication with `data.exfil.evil.com` :contentReference[oaicite:1]{index=1}  
- File activity shows large data transfers from `finance.xlsx` :contentReference[oaicite:2]{index=2}  

---

## 🧩 MITRE ATT&CK Mapping

| Stage | Technique ID | Technique Name | Description | Evidence |
|------|-------------|---------------|------------|---------|
| Initial Access | T1566.001 | Spearphishing Attachment | Malicious macro document delivered via email | reset.docm |
| Execution | T1204.002 | User Execution | User opens malicious attachment | Email interaction |
| Execution | T1059.001 | PowerShell | Likely macro-triggered PowerShell execution | (inferred) |
| Persistence | T1547 | Boot/Logon Autostart | Potential persistence after execution | (inferred) |
| Command & Control | T1071.004 | DNS | Beaconing via DNS queries | data.exfil.evil.com |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Data exfil via DNS | High bytes_out |
| Collection | T1005 | Data from Local System | Access to finance.xlsx | File logs |

---

## 🔗 Attack Flow 

1. User receives phishing email  
2. Opens `reset.docm` attachment  
3. Macro executes malicious payload  
4. System connects to attacker-controlled DNS  
5. Sensitive file accessed (`finance.xlsx`)  
6. Data exfiltration begins  

---

# 🔐 ATTACK SCENARIO 2: BRUTE FORCE → ACCOUNT COMPROMISE

## 🔍 Observed Evidence
- High volume login attempts across users  
- Multiple successful logins from varying IPs  
- Same users logging in from multiple IPs quickly  

📌 Log Evidence:
- Multiple login events for same users from different IPs :contentReference[oaicite:3]{index=3}  

---

## 🧩 MITRE ATT&CK Mapping

| Stage | Technique ID | Technique Name | Description | Evidence |
|------|-------------|---------------|------------|---------|
| Credential Access | T1110 | Brute Force | Multiple login attempts | Auth logs |
| Credential Access | T1110.003 | Password Spraying | Multiple users targeted | Pattern observed |
| Initial Access | T1078 | Valid Accounts | Successful login after brute force | Login success |
| Discovery | T1087 | Account Discovery | Enumeration of valid users | Username patterns |
| Persistence | T1078 | Valid Accounts | Continued access using compromised accounts | Repeated logins |

---

## 🔗 Attack Flow

1. Attacker attempts multiple logins  
2. Targets multiple users (password spraying)  
3. Gains access to valid account  
4. Maintains persistence via repeated logins  

---

# 💣 ATTACK SCENARIO 3: DATA EXFILTRATION

## 🔍 Observed Evidence
- High volume outbound DNS traffic  
- Large `bytes_out` values  
- Repeated queries to same domain  

📌 Log Evidence:
- DNS logs show large outbound traffic to attacker domain :contentReference[oaicite:4]{index=4}  

---

## 🧩 MITRE ATT&CK Mapping

| Stage | Technique ID | Technique Name | Description | Evidence |
|------|-------------|---------------|------------|---------|
| Command & Control | T1071.004 | DNS | Data sent via DNS queries | DNS logs |
| Exfiltration | T1048.003 | Exfiltration Over Unencrypted Channel | Data via DNS | bytes_out |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Ongoing communication | Repeated queries |

---

## 🔗 Attack Flow

1. Malware establishes DNS communication  
2. Encodes data into DNS queries  
3. Sends data in chunks  
4. Maintains persistent exfiltration channel  

---

# ☁️ ATTACK SCENARIO 4: CLOUD DATA EXFILTRATION

## 🔍 Observed Evidence
- Multiple `PutObject` actions  
- Large data uploads to external bucket  
- High frequency in short time  

📌 Log Evidence:
- Cloud logs show repeated uploads to external-data bucket :contentReference[oaicite:5]{index=5}  

---

## 🧩 MITRE ATT&CK Mapping

| Stage | Technique ID | Technique Name | Description | Evidence |
|------|-------------|---------------|------------|---------|
| Exfiltration | T1567.002 | Exfiltration to Cloud Storage | Data uploaded to cloud bucket | PutObject |
| Impact | T1537 | Transfer Data to Cloud Account | External storage usage | external-data |

---

## 🔗 Attack Flow

1. Compromised account accesses cloud  
2. Uploads sensitive data  
3. Uses external bucket to avoid detection  

---

# 🧠 FINAL ANALYST SUMMARY

This investigation demonstrates a **multi-stage attack chain**:

- Initial Access → Phishing
- Execution → Macro / PowerShell
- Credential Access → Brute Force
- Persistence → Valid Accounts
- Command & Control → DNS Beaconing
- Exfiltration → DNS + Cloud Storage

---

# 🚀 Key Takeaways 

✔ Ability to map logs to MITRE ATT&CK  
✔ Understanding of full attack lifecycle  
✔ Correlation across multiple data sources  
✔ Real-world SOC investigation mindset  

---

# 📌 Author:
Varrun Vashisht

Cybersecurity Professional
