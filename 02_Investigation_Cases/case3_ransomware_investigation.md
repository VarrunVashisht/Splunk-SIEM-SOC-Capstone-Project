# 🦠 Case 3: Ransomware Attack Investigation 

## 🎯 Objective

The goal of this investigation is to identify and analyze a ransomware attack using Splunk by correlating logs from multiple sources (Windows, File, DNS, Cloud, Auth, Email) log files.
All files are combined to one "combined".

We aim to:

* Detect execution of ransomware
* Identify file encryption behavior
* Confirm persistence and spread
* Detect command & control (C2)
* Identify data exfiltration
* Build a complete attack timeline

---

# 🔍 Subcase 1: Suspicious File Execution

## ❓ Why This Matters

Every ransomware attack begins with execution of a malicious file or script. If we detect this early, we can stop the attack before encryption begins.
---

## 🎯 What We Are Looking For

We want to identify:

* Unusual processes
* Suspicious parent-child relationships
* Execution chains like:
  Word → PowerShell → cmd
---

## 🔍 Basic Query

```spl
index="soc_project" sourcetype=windows.log EventCode=4688
| stats count by User, ProcessName, ParentProcess
| sort - count
```

### 🧠 How This Query Works

* `index="soc_project"` → Searches all data in your SOC project index
* `sourcetype=windows.log` → Filters only Windows logs
* `EventCode=4688` → This is **A new process creation event**

👉 So we are looking at **every process that was executed**

---

### 🔧 Function Breakdown

* `stats count by User, ProcessName, ParentProcess`

This groups results:

* `count` → how many times process executed
* `User` → who executed
* `ProcessName` → what ran
* `ParentProcess` → what launched it

### Output

<img width="1868" height="870" alt="image" src="https://github.com/user-attachments/assets/539b4094-e845-4ca8-8856-622e9cfe50ef" />

---

## 🔍 Advanced Query

```spl
index="soc_project" sourcetype="windows.log"  
EventCode=4688
| where ParentProcess!="explorer.exe"
| stats values(ProcessName) as ProcessRunAfter 
by User, ParentProcess
| search ProcessRunAfter="*powershell*" OR ProcessRunAfter="*cmd*"
```

---

### 🧠 How This Query Works

* `where ParentProcess!="explorer.exe"`
  👉 Removes normal user activity (Explorer launches most apps)

* `stats values(ProcessName) as ProcessRunAfter `
  👉 Shows unique processes instead of repeating rows which run after initial process

* `search ProcessRunAfter="*powershell*"`
  👉 Filters suspicious tools

---

## 🧠 Analyst Insight

Normal behavior:

* explorer.exe → chrome.exe (normal)

Suspicious:

* winword.exe → powershell.exe ❌

---
## Output:
<img width="1877" height="835" alt="image" src="https://github.com/user-attachments/assets/6ebf8c89-01cd-4356-8d86-b17fade98a6a" />


## ✅ Conclusion

A non-standard execution chain strongly suggests malicious activity.

---

# 🔍 Subcase 2: Mass File Modification Detection

## ❓ Why This Matters

    Ransomware encrypts files in bulk → sudden spike in file operations.
---

## 🔍 Basic Query

```spl
index="soc_project" sourcetype=file.log
| stats count by user
```

### 🧠 Explanation

* Counts how many file operations each user performed
* High count = suspicious

<img width="1876" height="700" alt="image" src="https://github.com/user-attachments/assets/02b21ed6-2b0b-4cfc-87ec-644a75819765" />

---

## 🔍 Advanced Query

```spl
index="soc_project" sourcetype=file
| timechart span=1m count by user
```
<img width="1876" height="846" alt="image" src="https://github.com/user-attachments/assets/50823cc7-8384-462e-872e-033e163560be" />

---

### 🔧 Function Breakdown

* `timechart` → creates time-based graph
* `span=1m` → groups data per minute
* `count by user` → shows activity per user

---

## 🧠 Analyst Insight

If one user suddenly spikes → likely encryption process
---

## ✅ Conclusion

High-frequency file operations indicate ransomware activity.

---

# 🔍 Subcase 3: Encryption Activity Patterns

## ❓ Why This Matters

Encryption produces repetitive high data writes.

---

## 🔍 Basic Query

```spl
index="soc_project" sourcetype=file.log
| stats avg(bytes), max(bytes) by user
```
<img width="1879" height="750" alt="image" src="https://github.com/user-attachments/assets/0e90c9fd-a246-49db-9595-6c107317fed9" />

---

### 🔧 Functions

* `avg(bytes)` → average file size
* `max(bytes)` → largest file processed

---

## 🔍 Advanced Query

```spl
index="soc_project" sourcetype=file.log
| bin _time span=30s
| stats sum(bytes) as Total
by _time, user
| where Total >300000000
```
<img width="1888" height="788" alt="image" src="https://github.com/user-attachments/assets/22a5a8ea-fcd3-4149-a8f4-b2b1b4f78f72" />

---

### 🧠 Explanation

* `bin _time span=30s` → groups logs into 30-second buckets
* `sum(bytes)` → total data processed
* `where > 30MB` → filters high activity

---

## 🧠 Insight

Large data processed quickly = automated encryption

---

## ✅ Conclusion

System is actively encrypting files.

---

# 🔍 Subcase 4: Shadow Copy Deletion

## ❓ Why This Matters

Ransomware deletes backups to prevent recovery.

---

## 🔍 Query

```spl
index="soc_project" sourcetype=windows
| search CommandLine="*vssadmin*"
```

---

### 🧠 Explanation

* Searches for `vssadmin` (used to delete backups)
vssadmin is a built-in Windows command-line tool used to manage Volume Shadow Copies (snapshots of your files used for backups and restore points).

---

## 🔍 Query

```spl
index="soc_project" sourcetype=windows.log
| search CommandLine="*delete shadows*"
| stats count by User, CommandLine
```

---

## 🧠 Insight

Direct indicator of ransomware behavior.

---

## ✅ Conclusion

Backup deletion attempt confirms malicious intent.

---

# 🔍 Subcase 5: Registry Persistence

## ❓ Why This Matters

Ransomware ensures it runs after reboot.

---

## 🔍 Query

```spl
index="soc_project" sourcetype=windows.log EventCode=4657
```

**EventCode 4657:** A Windows Security log event indicating that a **registry value was modified**. 
It records what changed, the old and new values, the user/account, and the process responsible.

---

## 🔍 Advanced Query

```spl
index="soc_project" sourcetype=windows.log EventCode=4657
| stats values(ObjectName), values(NewValue) by User
```
---

### 🔧 Functions
* `values()` → shows unique values

---

## 🧠 Insight
Registry Run keys = persistence mechanism

---

## ✅ Conclusion

Attacker maintains long-term access.

---

# 🔍 Subcase 6: Network Spread Detection

## ❓ Why This Matters

Ransomware spreads laterally.

---

## 🔍 Query

```spl
index="soc_project" sourcetype=auth.log
| stats count by src_ip, user
```

---

## 🔍 Query

```spl
index="soc_project" sourcetype=auth.log
| stats dc(user) as unique_users, 
        values(user) as user_names
by src_ip
| where unique_users > 5
```
<img width="1810" height="897" alt="image" src="https://github.com/user-attachments/assets/3b98d7bc-d377-4b90-808a-fdc3eaa7d22f" />

---

### 🔧 Function

* `dc(user)` → distinct count
* `values(user)` → distinct their names
---

## 🧠 Insight

One IP accessing many users = lateral movement
Hacker is using same IP location to access multiple compromissed users/ systems.

---

## ✅ Conclusion

Possible internal spread detected.

---

# 🔍 Subcase 7: Command-Line Indicators

## ❓ Why This Matters

Attackers use CLI tools to automate actions.

---

## 🔍 Medium Query

```spl
index="soc_project" sourcetype=windows
| stats count by CommandLine
```
<img width="1875" height="568" alt="image" src="https://github.com/user-attachments/assets/db9b1f0c-0c6b-4e99-9c21-99a6d9b6cf6e" />

---

## 🔍 Advanced Query

```spl
index="soc_project" sourcetype=windows.log
| search CommandLine="*powershell*" OR CommandLine="*cmd*"
| stats count by User, CommandLine
```

---

## 🧠 Insight

PowerShell = high-risk execution tool

---

## ✅ Conclusion

Command-line abuse detected.

---

# 🔍 Subcase 8: C2 Communication

## ❓ Why This Matters

Ransomware communicates externally.

---

## 🔍 Query

```spl
index="soc_project" sourcetype=dns.log
| stats count by query
```
<img width="1885" height="633" alt="image" src="https://github.com/user-attachments/assets/c5e6445b-86fe-489b-8886-c6d2e7a22d7a" />

---

## 🔍  Query

```spl
index="soc_project" sourcetype=dns.log
| stats sum(bytes_out) as exfiltration by src_ip
| where exfiltration > 100000000
```
<img width="1876" height="820" alt="image" src="https://github.com/user-attachments/assets/8f5296fa-e709-4c77-a8ab-d2db5d124dad" />

---

## 🧠 Insight

High outbound traffic = possible data transfer

---

## ✅ Conclusion

C2 or exfiltration detected.

---

# 🔍 Subcase 9: Data Exfiltration

## ❓ Why This Matters

Modern ransomware steals data before encrypting.

---

## 🔍 Query

```spl
index="soc_project" sourcetype=cloud.log
| stats sum(bytes) by bucket
```
<img width="1884" height="544" alt="image" src="https://github.com/user-attachments/assets/820e89dd-e98f-4358-b0dc-8b105977b3ae" />

---

## 🔍 Query

```spl
index="soc_project" sourcetype=cloud.log
| timechart span=3m sum(bytes)
```
<img width="1885" height="676" alt="image" src="https://github.com/user-attachments/assets/005cc633-2812-4635-895a-a335b246a3b6" />

---

## 🧠 Insight

Large uploads to external bucket = exfiltration

---

## ✅ Conclusion

Sensitive data has been exfiltrated.

---

# 🔍 Subcase 10: Full Timeline Reconstruction

## ❓ Why This Matters

SOC must understand entire attack chain.

---

## 🔍 Query

```spl
index="soc_project"
| stats count by sourcetype
```
<img width="1881" height="826" alt="image" src="https://github.com/user-attachments/assets/f6230d3e-cfc9-443d-b381-679cb866d97e" />

---

## 🔍 Query

```spl
index="soc_project"
| transaction user maxspan=2h
| table _time user sourcetype
```
<img width="1787" height="669" alt="image" src="https://github.com/user-attachments/assets/29062deb-4e86-4050-8e65-f8655dc6067e" />

---

### 🔧 Function

* `transaction` → groups related events
Group together all events from the same user that happen within 2 hours, then show them in a clean table.
---

## 🧠 Insight

Combines all logs into a single attack story

---

## ✅ Final Conclusion

Attack Flow:

1. Phishing email → entry
2. Execution → malware runs
3. File activity spike → encryption
4. DNS + cloud → exfiltration
5. Persistence → long-term access

---

## 🚨 Severity: CRITICAL

---
## Author:
Varrun Vashisht
