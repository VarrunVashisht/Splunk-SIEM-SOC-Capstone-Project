# 🛡️ Case 5: Privilege Escalation Investigation

## 📌 Overview

This project demonstrates how to detect **Privilege Escalation attacks** using Splunk by analyzing multiple log sources.

---

## 📂 Data Sources Used

* Authentication Logs → User login activity
* Windows Logs → Process creation & system events
* Email Logs → Phishing and attachments
* DNS Logs → Suspicious domain activity
* Cloud Logs → Data exfiltration indicators
* Web Logs → User browsing behavior
* File Access Logs → Sensitive file interaction

---

# 🧩 Subcase 1: Unauthorized Privilege Changes

## 🎯 Detection Goal

Detect users logging in unusually frequently or from many IP addresses.

---

## 🔎 Query

```spl
index=soc_project sourcetype=auth.log action=login status=success
| stats count by user src_ip
| where count > 5
| sort -count
```

### 🧠 Explanation (Step-by-Step)

* `index=soc_project` → Search in your dataset
* `sourcetype=auth.log` → Only authentication logs
* `action=login status=success` → Successful logins only
* `stats count by user src_ip` → Count logins per user per IP
* `where count > 5` → Filter abnormal login volume
* `sort -count` → Show highest first

👉 This helps identify brute force or scripted login activity.

<img width="1902" height="665" alt="image" src="https://github.com/user-attachments/assets/d56c436c-2a01-417b-9560-46f72e2e8e4f" />

---
## Another Query

```spl
index=soc_project index=auth.log
| stats dc(src_ip) as unique_ips count by user 
| where unique_ips > 5
'''
<img width="1879" height="768" alt="image" src="https://github.com/user-attachments/assets/e33ab5df-311d-43e4-839b-c5d76e0b802f" />


## 🚀 Advanced Query

```spl
index=soc_project sourcetype=auth.log action=login status=success
| bucket _time span=5m
| stats count dc(src_ip) as unique_ips by user _time
| eventstats avg(count) as avg stdev(count) as stdev by user
| eval anomaly=if(count > avg + (2*stdev), "YES", "NO")
| where anomaly="YES"
```

### 🧠 Explanation

* `bucket _time span=5m` → Group logs into 5-minute windows
* `count` → Total logins
* `dc(src_ip)` → Number of unique IPs
* `eventstats avg + stdev` → Calculate normal behavior baseline
* `eval anomaly` → Flag abnormal spikes
* `where anomaly="YES"` → Show only suspicious activity

👉 This detects behavior that deviates from a user’s normal pattern.

<img width="1872" height="839" alt="image" src="https://github.com/user-attachments/assets/8a3cb8b3-3ac3-403f-8f7b-75ebe8de8e93" />

---

## 📊 SOC Insight

* Credential theft
* Session hijacking
* Automated login abuse

---

# 🧩 Subcase 2: Suspicious Admin Logins

## 🎯 Detection Goal

Detect admin accounts logging in from multiple IP addresses.

---

## 🔎 Query

```spl
index=soc_project sourcetype=auth.log user=admin*
| stats count by user src_ip
| sort -count
```

### 🧠 Explanation

* Filters admin users
* Counts login attempts per IP

👉 Admin accounts should not frequently change IPs.

<img width="1883" height="846" alt="image" src="https://github.com/user-attachments/assets/89509ebb-9d69-408d-8e09-b493723de8c5" />

---

## 🚀  Query

```spl
index=soc_project sourcetype=auth.log user=admin
| stats count dc(src_ip) as unique_ip
by user
| where unique_ip > 5
```

<img width="1875" height="611" alt="image" src="https://github.com/user-attachments/assets/8f1fbb4d-e173-44da-99b1-3e28afcce1da" />


### 🧠 Explanation

* `dc(src_ip)` → Counts distinct IPs
* Flags users accessing from more than 3 IPs

👉 High IP diversity = possible compromise or VPN abuse.

---

## 📊 SOC Insight

* Privileged account compromise
* Lateral movement using admin credentials
---

# 🧩 Subcase 3: Token Manipulation Detection

## 🎯 Detection Goal

Attackers manipulate tokens to impersonate higher privileges.
Detect abnormal process creation patterns.

---

## 🔎 Query

```spl
index=soc_project sourcetype=windows.log EventCode=4688
| stats count by User ProcessName
```
<img width="1884" height="808" alt="image" src="https://github.com/user-attachments/assets/4200f382-e48c-4269-a33f-330959a49106" />


### 🧠 Explanation

* EventCode 4688 = Process creation
* Counts processes per user

---

## 🚀 Query

```spl
index=soc_project sourcetype=windows.log EventCode=4688
| stats count by User ParentProcess ProcessName
| where ParentProcess!="explorer.exe"
```

### 🧠 Explanation

* Looks at parent-child process relationships
* `explorer.exe` = normal parent process
* Flags unusual parents

👉 Attackers often spawn processes from scripts or malware.

---
<img width="1881" height="714" alt="image" src="https://github.com/user-attachments/assets/b0c91272-8a2b-47b7-8810-573cac89a0fb" />

## 📊 SOC Insight

* Token abuse, used parentprocess to make childprocess.
* Privilege escalation via process injection

---

# 🧩 Subcase 4: Exploit Execution Indicators

## 🎯 Detection Goal

Detect phishing emails leading to execution.

---

## 🔎 Query

```spl
index=soc_project sourcetype=email.log attachment="*.docm"
| stats count by recipient
```

### 🧠 Explanation

* `.docm` = macro-enabled file
* Counts who received them

<img width="1884" height="707" alt="image" src="https://github.com/user-attachments/assets/0ed82886-9a22-480a-bcf1-2790b50fd9e9" />

---

## 🚀 Query

```spl
index=soc_project sourcetype=email.log attachment="*.docm"
| rename recipient as User
| stats count as email_count by User
| join User [
    search index=soc_project sourcetype=windows.log EventCode=4688
    | stats count as process_count by User ProcessName
]
| stats sum(email_count) as total_emails sum(process_count) as total_processes by User ProcessName
| sort - total_processes
```
<img width="1888" height="788" alt="image" src="https://github.com/user-attachments/assets/296c689d-a18b-4cc7-ab73-e1936d8b2bbe" />

<img width="1869" height="738" alt="image" src="https://github.com/user-attachments/assets/0231f53c-d310-4cfb-ab48-89ba7744d062" />


### 🧠 Explanation

* rename recipient as User, to match column name in both logs.
* Correlates email + process execution
* Detects if user executed something after receiving file

👉 This links phishing → execution.

---

## 📊 SOC Insight

* Initial access vector
* Malware execution chain

---

# 🧩 Subcase 5: Service Creation Abuse

## 🎯 Detection Goal

Attackers create services for persistence.
Detect persistence via services.

---

## 🔎 Query

```spl
index=soc_project sourcetype=windows.log EventCode=4688
| search ProcessName="sc.exe"
```

### 🧠 Explanation

* `sc.exe` = service control tool
* Used to create services

---

## 🚀  Query

```spl
index=soc_project sourcetype=windows.log EventCode=4688
| eval suspicious=if(match(ProcessName,"sc.exe|powershell.exe"),"YES","NO")
| where suspicious="YES"
| stats count by ProcessName
```
<img width="1864" height="572" alt="image" src="https://github.com/user-attachments/assets/51ea6f18-9544-4c4b-9d90-1e87ddc3dd8e" />

### 🧠 Explanation

* Flags common attacker tools
* PowerShell often used in attacks

---

## 📊 SOC Insight

* Persistence
* Privilege escalation

---

# 🧩 Subcase 6: Scheduled Task Abuse

## 🎯 Detection Goal

Scheduled tasks allow stealthy persistence.
Detect persistence using scheduled tasks.

---

## 🔎 Query

```spl
index=soc_project sourcetype=windows.log
| search ProcessName="schtasks.exe"
```

### 🧠 Explanation

* Detects task scheduler usage

---

## 🚀  Query

```spl
index=soc_project sourcetype=windows.log
| stats count by User ProcessName
| where ProcessName="schtasks.exe"
```

### 🧠 Explanation

* Identifies which users create tasks frequently

---

## 📊 SOC Insight

* Stealth persistence mechanism

---

# 🧩 Subcase 7: Credential Dumping Detection

## 🎯 Detection Goal

Credential dumping tools target LSASS.
Detect credential theft tools.

---

## 🔎  Query

```spl
index=soc_project sourcetype=windows.log 
| search lsass
```

```spl
index=soc_project sourcetype=windows.log
| search ProcessName="*mimikatz*"
```

### 🧠 Explanation

* Detects known hacking tool

---

## 🚀 Advanced Query

```spl
index=soc_project sourcetype=windows.log
| eval suspicious=if(match(ProcessName,"mimikatz|lsass"),"YES","NO")
| where suspicious="YES"
```

### 🧠 Explanation

* `lsass` access = credential dumping
* Flags suspicious processes

## 🧠 What are these two?

### 🔐 Mimikatz
- A well-known hacking tool  
- Used to extract passwords and credentials from memory  
- Common in penetration testing and real attacks  

### ⚙️ LSASS
- A legitimate Windows system process  
- Stores user authentication data in memory  
- Attackers target it to steal credentials  
---

## 📊 SOC Insight

* Credential compromise
* Privilege escalation

---

# 🧩 Subcase 8: Lateral Movement Indicators

## 🎯 Detection Goal

Attackers move across systems after escalation.
Detect users accessing multiple systems quickly.

---

## 🔎 Query

```spl
index=soc_project sourcetype=auth.log
| stats dc(src_ip) by user
```

### 🧠 Explanation

* Counts unique systems accessed

---

## 🚀 Query

```spl
index=soc_project sourcetype=auth.log
| bucket _time span=10m
| stats dc(src_ip) as unique_ip 
by user _time
| where unique_ip > 15
| sort -unique_ip
```
<img width="1891" height="835" alt="image" src="https://github.com/user-attachments/assets/e4f64373-3867-45d3-81c1-b7dfb2eaaa32" />

### 🧠 Explanation

* Detects rapid spread across systems

---

## 📊 SOC Insight

* Lateral movement behavior

---

# 🧩 Subcase 9: Elevated Process Execution

## 🎯 Detection Goal

High-privilege processes indicate escalation success.
Detect abnormal process spikes.

---

## 🔎  Query

```spl
index=soc_project sourcetype=windows.log
| stats count by ProcessName
```

### 🧠 Explanation

* Baseline process frequency

---

## 🚀  Query

```spl
index=soc_project sourcetype=windows.log
| stats count by User ProcessName
| eventstats avg(count) as avg by ProcessName
| where count < avg
```
<img width="1877" height="823" alt="image" src="https://github.com/user-attachments/assets/b002d899-f5d2-49ae-8b69-686dcffdf744" />

### 🧠 Explanation

* Compares current vs normal behavior
* Flags spikes

---

## 📊 SOC Insight

* Exploit activity
* Automation

---

# 🧩 Subcase 10: Escalation Timeline

## 🎯 Detection Goal

Reconstruct full attack chain.

---

## 🔎 Query

```spl
index=soc_project
| stats count by _time, sourcetype
```

### 🧠 Explanation

* Shows activity timeline

---

## 🚀  Query

```spl
index=soc_project
| sort _time
| transaction user maxspan=30m
| table _time user sourcetype
```
<img width="1819" height="796" alt="image" src="https://github.com/user-attachments/assets/06757be0-d65c-469e-81e2-f6d7ee147ed2" />

### 🧠 Explanation

* Groups events by user
* Builds attack sequence

---

## 📊 Attack Story Example

1. Phishing email received
2. User logs in abnormally
3. Malicious process executed
4. DNS requests to attacker domain
5. Data uploaded to cloud

---

# 🧠 Final SOC Takeaways

## 🚨 What Happened?

* Phishing attack initiated
* Malware executed
* Credentials stolen
* Lateral movement observed
* Data exfiltration occurred

---

## 🛡️ Recommended Actions

* Disable compromised accounts
* Reset passwords
* Block malicious domains
* Isolate infected endpoints
* Monitor persistence mechanisms

---

# 🏁 Conclusion

This project shows how **Splunk queries can detect advanced attacks**.

Key detections:

* Privilege escalation
* Lateral movement
* Credential dumping
* Persistence techniques

---

## Author:
Varrun Vashisht

