# 🛡️ Case 7: Living-off-the-Land (LotL) Attacks

**Splunk SOC Project – Advanced Threat Hunting Guide**
---

# 📌 Overview

Living-off-the-Land (LotL) attacks occur when attackers use **legitimate system tools** (like PowerShell, WMI, or scheduled tasks) instead of malware.

👉 This makes them dangerous because:

* No malware files are required
* Activity looks "normal"
* Traditional antivirus often misses it

---

## 🧾 Data Sources in This Case

This dataset shows suspicious activity across multiple logs:

* **Authentication logs** → High-frequency logins
* **DNS logs** → Suspicious domain: `data.exfil.evil.com`
* **Email logs** → Repeated `.docm` attachments (macro malware)
* **Cloud logs** → Large outbound uploads
* **File logs** → Unusual file access spikes
* **Windows logs** → Process execution (EventCode 4688)

---

# 🔎 Subcase 1: Legitimate Tool Abuse Detection

## 🎯 Goal

Detect abnormal usage of normal programs (browsers, tools, etc.).

---

## 🔍 Query

```spl
index=soc_project sourcetype=windows.log EventCode=4688
| stats count by User, ProcessName
| sort - count
```
<img width="1895" height="803" alt="image" src="https://github.com/user-attachments/assets/2d91a66c-3190-40de-9598-b6abaf4f858f" />

### 🧠 Explanation

* `sourcetype=windows` → Search Windows logs
* `EventCode=4688` → Process creation events
* `stats count by User, ProcessName`
  → Count how many times each process runs per user
* `sort - count` → Show highest activity first

👉 This helps identify **which processes are used the most**

---

## ⚡ Advanced Query

```spl
index=soc_project sourcetype=windows.log EventCode=4688
| stats count as total_process_run dc(ParentProcess) as parent_variation 
by User, ProcessName
| where count > 20 OR parent_variation > 2
| sort - count
```

### 🧠 Explanation

* `dc(ParentProcess)` → Counts unique parent processes
  👉 Detects unusual execution chains
* `parent_variation > 2` → Same process launched by many parents = suspicious
* `count > 20` → High execution volume = possible automation

## Explanation
ProcessName (chrome.exe) - What is running
This is the program that is running.
👉 In this case, it means Google Chrome is running.

ParentProcess (explorer.exe) - Who started it
This is the program that started (launched) the process.
👉 Here, explorer.exe (Windows File Explorer) started Chrome.

✅ Normal:
explorer.exe → chrome.exe

🚨 Suspicious: 
powershell.exe-> chrome.exe 
ransomware.exe-> chrome.exe

---
<img width="1888" height="696" alt="image" src="https://github.com/user-attachments/assets/f47fd14f-1b8c-4751-929e-27bdf3906e47" />


## 📊 Insight

High execution of `chrome.exe` suggests:

* Scripted browsing
* Possible command-and-control (C2)
* Phishing automation

---

# 🔥 Subcase 2: PowerShell Misuse

## 🎯 Goal

Detect hidden or encoded PowerShell commands.

---

## 🔍 Query

```spl
index=windows EventCode=4688 ProcessName="*powershell*"
```

### 🧠 Explanation

* Filters only PowerShell executions

---

## ⚡ Query

```spl
index=soc_project sourcetype=windows.log ProcessName="*powershell*"
| search CommandLine="*EncodedCommand*" OR CommandLine="*-enc*"
| stats count 
by User, CommandLine
| sort - count
```

### 🧠 Explanation

* `EncodedCommand` / `-enc` → PowerShell obfuscation flags
* Attackers encode commands to:
  * Hide payloads
  * Evade detection

---

## 📊 Insight

Encoded PowerShell = 🚨 **Strong indicator of malicious activity**

---
<img width="1888" height="719" alt="image" src="https://github.com/user-attachments/assets/e94459e5-bf10-4f23-aa82-b0d0670b7a31" />


# 🧬 Subcase 3: WMI Execution Analysis

## 🎯 Goal

Detect remote execution using WMI.

---

## 🔍  Query

```spl
index=soc_project sourcetype=windows.log ProcessName="wmic.exe"
```

### 🧠 Explanation

* Finds all WMI command executions

---

## ⚡ Advanced Query

```spl
index=soc_project sourcetype=windows.log ProcessName="wmic.exe"
| stats count by User, CommandLine
| where count > 5
```

### 🧠 Explanation

* Repeated commands indicate:

  * Automation
  * Remote execution

---

## 📊 Insight

Likely **lateral movement or remote control**

---

# ⏰ Subcase 4: Scheduled Task Abuse

## 🎯 Goal

Detect persistence via scheduled tasks.

---

## 🔍 Query

```spl
index=soc_project sourcetype=windows.log CommandLine="*schtasks*"
```

### 🧠 Explanation

* Finds task scheduler usage

---

## ⚡ Query

```spl
index=soc_project sourcetype=windows.log CommandLine="*schtasks*"
| rex "schtasks\s+/create\s+/tn\s+(?<task_name>\S+)"
| stats count by User, task_name
```

### 🧠 Explanation

* `rex` → Extracts task name from command
* `/create` → Indicates task creation
* Attackers use this to **run malware at startup**

---

## 📊 Insight

Frequent task creation = 🚨 persistence

---

# 🧾 Subcase 5: Registry Manipulation

## 🎯 Goal

Detect registry-based persistence.

---

## 🔍 Intermediate Query

```spl
index=soc_project sourcetype=windows.log CommandLine="*reg add*"
```

### 🧠 Explanation

* Detects registry modifications

---

## ⚡ Query

```spl
index=soc_project sourcetype=windows.log CommandLine="*reg add*"
| stats count by User, CommandLine
| where count > 3
```

### 🧠 Explanation

* Multiple registry edits = suspicious
* Common persistence location:

  * `Run` keys (startup execution)

---

## 📊 Insight

Registry abuse = stealth persistence

---

# 🧠 Subcase 6: Fileless Malware Indicators

## 🎯 Goal

Detect attacks without files.

---

## 🔍  Query

```spl
index=soc_project sourcetype=windows.log EventCode=4688
```
---

## ⚡ Query

```spl
index=soc_project sourcetype=windows.log EventCode=4688
| stats count by User
| join User [
    search index=dns.log query="*.evil.com"
    | stats count by src_ip
]
```

### 🧠 Explanation

* Combines:

  * Process activity (Windows logs)
  * DNS queries (network logs)
* `join` → Correlates activity across datasets

---

## 📊 Insight

* DNS → `evil.com` (exfiltration)
* No malware files detected
  👉 Likely **fileless attack**

---

# 🧵 Subcase 7: Command-Line Anomalies

## 🎯 Goal

Detect suspicious command-line usage.

---

## 🔍  Query

```spl
index=soc_project sourcetype=windows.log EventCode=4688
| table User, ProcessName, CommandLine
```

<img width="1895" height="754" alt="image" src="https://github.com/user-attachments/assets/53ddb971-7252-471b-b16b-d197d5fecb2d" />

### 🧠 Explanation

* Displays raw command-line activity

---

## ⚡  Query

```spl
index=soc_project sourcetype=windows.log EventCode=4688
| search CommandLine="*http*" OR CommandLine="*base64*" OR CommandLine="*download*"
| stats count by User, CommandLine
```

### 🧠 Explanation

* `http` → Possible downloads
* `base64` → Obfuscation
* `download` → Payload retrieval

---

## 📊 Insight

Command-line patterns reveal:

* Payload delivery
* Data exfiltration
* Hidden execution

---

# 🌐 Subcase 8: Lateral Movement

## 🎯 Goal

Detect movement across systems.

---

## 🔍  Query

```spl
index=soc_project sourcetype=auth.log action=login status=success
| stats count by user, src_ip
```
<img width="1902" height="762" alt="image" src="https://github.com/user-attachments/assets/5e9c00a6-f3c6-4b96-ad21-c63f08ef3843" />

---

## ⚡ Advanced Query

```spl
index=auth action=login status=success
| stats dc(src_ip) as unique_ips count by user
| where unique_ips > 5
```
<img width="1892" height="715" alt="image" src="https://github.com/user-attachments/assets/6df01cbe-5d30-419e-9542-00a7b89cc95f" />

### 🧠 Explanation

* `dc(src_ip)` → Unique login sources
* Many IPs = abnormal behavior

---

## 📊 Insight

User `alice` logging in from many IPs
👉 🚨 Likely lateral movement

---

# 🔐 Subcase 9: Native Tool Persistence

## 🎯 Goal

Detect chaining of built-in tools.

---

## 🔍 Intermediate Query

```spl
index=soc_project sourcetype="windows.log" EventCode=4688
| stats count by ProcessName
```
<img width="1910" height="610" alt="image" src="https://github.com/user-attachments/assets/6f80dcaa-3664-4b62-9bcf-9db51e12a0b5" />

---

## ⚡  Query

```spl
index=soc_project sourcetype="windows.log" EventCode=4688
| stats count by ProcessName, ParentProcess
| where ProcessName IN ("powershell.exe","wmic.exe","schtasks.exe")
```
<img width="1891" height="495" alt="image" src="https://github.com/user-attachments/assets/b90eea5a-ff5a-4490-8e8f-6bb0a44697f9" />

### 🧠 Explanation

* Focuses on known LotL tools
* Parent-child relationships reveal attack chains
* ParentProcess is "winword.exe", doubtful.

---

## 📊 Insight

Tool chaining = stealth persistence technique

---

# 🕒 Subcase 10: Attack Timeline Reconstruction

## 🎯 Goal

Rebuild the full attack story.

---

## 🔍 Intermediate Query

```spl
index=soc_project
| sort _time
| table _time, index, user, action
```

---

## ⚡  Query

```spl
(index=auth OR index=dns OR index=email OR index=cloud OR index=file)
| eval activity=coalesce(action, query, file, bucket)
| stats values(activity) as activities by _time, user, src_ip
| sort _time
```

### 🧠 Explanation

* `coalesce()` → Combines fields into one
* `stats values()` → Groups activities together
* Builds a **timeline of attacker behavior**

<img width="1842" height="828" alt="image" src="https://github.com/user-attachments/assets/7099ba7f-b908-4056-a82a-39e40ec16e91" />

---

## 📊 Full Attack Chain

1. Phishing email (`.docm`)
2. User opens file (macro execution)
3. PowerShell / tools executed
4. Files accessed (`finance.xlsx`)
5. DNS beacon → `data.exfil.evil.com`
6. Data uploaded to cloud

---

# 🚨 Final SOC Assessment

## 🔥 Threat Summary

This is clearly malicious activity involving:

* Phishing initial access
* Fileless execution
* Living-off-the-Land techniques
* Data exfiltration

---

## 🎯 Risk Level: CRITICAL

---

# 🛠️ Recommended Actions

## 🚑 Immediate

* Isolate infected hosts
* Block `data.exfil.evil.com`
* Disable compromised accounts

## 🔍 Investigation

* Memory forensics
* PowerShell logs
* Endpoint telemetry

## 🏗️ Long-Term

* Enable PowerShell logging
* Deploy EDR rules for LotL
* Use email sandboxing
* Monitor DNS traffic

---

# ✅ Conclusion

Attackers are:

* Avoiding malware
* Using trusted tools
* Blending into normal activity

👉 Detection must rely on:

* Behavior analysis
* Log correlation
* Anomaly detection

---

## Author:
Varrun Vashisht
