# 🚨 Case 1: Phishing Attack Investigation

---

## 🎯 Objective

Investigate a phishing-based compromise and reconstruct the full attack lifecycle using multi-source logs:

* 📧 Email Logs
* 🌐 Web Logs
* 💻 Windows Event Logs
* 🌍 DNS Logs
* 📦 File Activity Logs
* ☁️ Cloud Logs

---

## 🧠 Investigation Strategy

This case follows a **user-centric + kill chain reconstruction approach**:

> Identify → Validate → Correlate → Confirm → Reconstruct Timeline

---

# 🧩 Subcase 1: Phishing Domain Identification

## ❓ Why

The attack begins with a malicious domain. Missing this = missing the entire attack.

## 🎯 What

Identify suspicious or non-baseline domains.

## 🔍 SPL Query

```spl
index=web
| stats count by url
| sort count
```

## 🧠 Analysis

* Normal domains observed: 
  google.com, 
  linkedin.com, 
  acme.com,
  youtube.com

* Suspicious domain detected: **secure-login-acme.com**
* 
<img width="1129" height="777" alt="image" src="https://github.com/user-attachments/assets/6cbd62c2-fe4e-497d-930e-e483facf57c2" />


## ✅ Conclusion

Phishing domain identified (lookalike domain used for deception).

---

# 🧩 Subcase 2: Email Campaign Analysis

## ❓ Why

Phishing attacks are typically mass campaigns.

## 🔍 SPL Query

```spl
index=email
| stats count by sender, attachment
```

## 🧠 Analysis

* Sender: `it-support@secure-login.com`
* Attachment: `reset.docm`
* Same email sent to multiple users rapidly
  
<img width="1125" height="398" alt="image" src="https://github.com/user-attachments/assets/7093172e-7f30-4d76-b17c-35be21aa1a08" />


## ✅ Conclusion

Mass phishing campaign confirmed.

---


# 🧩 Subcase 3: User Click Behavior

## ❓ Why

Only users who interact are compromised.

## 🔍 SPL Query

```spl
index=web url="*secure-login*"
| stats count by user
```

## 🧠 Analysis

* Not all recipients clicked
* Only subset interacted with phishing domain

<img width="1119" height="568" alt="image" src="https://github.com/user-attachments/assets/3e4a5d61-c539-4722-95ec-2d021fc1b02a" />

## ✅ Conclusion

Compromised users identified (initial victims).

---

# 🧩 Subcase 4: Malicious Attachment Execution

## ❓ Why

Execution is the true compromise point.

## 🔍 SPL Query

```spl
index=web file="*.docm"
```

## 🧠 Analysis

* Macro-enabled `.docm` file executed
* Strong indicator of malicious payload delivery

## ✅ Conclusion

Macro-based execution confirmed.

---

# 🧩 Subcase 5: Suspicious Process Creation

## ❓ Why

Attack transitions from user-level to system-level.

## 🔍 SPL Query

```spl
index=windows EventCode=4688
| stats count by ProcessName, ParentProcess
```

## 🧠 Analysis

* Normal: explorer.exe → chrome.exe
* Suspicious: **winword.exe → powershell.exe**

## 🚨 Indicator

Office spawning PowerShell = high-confidence compromise signal

<img width="1110" height="495" alt="image" src="https://github.com/user-attachments/assets/f6862bc9-50bf-45f7-a3d7-0347202024df" />


## ✅ Conclusion

Malicious process chain detected.

---

# 🧩 Subcase 6: PowerShell Abuse Detection

## ❓ Why

PowerShell is commonly used for payload execution.

## 🔍 SPL Query

```spl
index=windows CommandLine="*powershell*"
```

## 🧠 Analysis

* Encoded and hidden commands observed
* Indicates obfuscated execution

## ✅ Conclusion

PowerShell used as attack execution mechanism.

---

# 🧩 Subcase 7: Persistence Mechanism Identification

## ❓ Why

Attackers establish persistence to maintain access.

## 🔍 SPL Query

```spl
index=windows EventCode=4657 OR EventCode=7045
```

## 🧠 Analysis

* Registry Run key modifications
* Suspicious service creation

  4657 = registry change
  7045 = new service installed

## ✅ Conclusion

Persistence successfully established.

---

# 🧩 Subcase 8: DNS Callback Analysis

## ❓ Why

Compromised systems communicate with attacker infrastructure.

## 🔍 SPL Query

```spl
index=dns
| stats count by query
```

## 🧠 Analysis

* Repeated queries to: `data.exfil.evil.com`
* High-frequency + abnormal domain

## 🚨 Indicator

DNS-based command & control / exfiltration channel

<img width="1122" height="549" alt="image" src="https://github.com/user-attachments/assets/bdde9ced-cf6a-408f-a2d6-e43e66ba643a" />


## ✅ Conclusion

DNS callback activity confirmed.

---

# 🧩 Subcase 9: Data Exfiltration Detection

## ❓ Why

Final attacker objective = data theft.

## 🔍 SPL Query

```spl
index="soc_project"  
(sourcetype="cloud.log" OR sourcetype="file.log" OR sourcetype="dns.log")   
| stats sum(bytes) by user
```

## 🧠 Analysis

### 📦 File Access

* Large data volume read

### 🌍 DNS Exfiltration

* High outbound traffic spikes

### ☁️ Cloud Upload

* Repeated uploads to external bucket

## 🚨 Indicator

Multi-channel data exfiltration

## ✅ Conclusion

Sensitive data exfiltrated via:

* file.log
* dns.log
* cloud.log

<img width="1111" height="577" alt="image" src="https://github.com/user-attachments/assets/7ae833b9-d290-4e8f-acc4-0ab4649d86c4" />

---

# 🧩 Subcase 10: Full Attack Timeline Reconstruction

## ❓ Why

SOC must understand full attack lifecycle.

## 🔍 SPL Query

```spl
(index=email OR index=web OR index=windows OR index=dns OR index=file OR index=cloud)
| sort _time
```

---

## 🧠 Attack Timeline

| ⏰ Time      | 📌 Event                          |
| ----------- | --------------------------------- |
| 08:25       | Phishing emails sent              |
| 08:30       | Normal user activity              |
| 08:35       | User interacts with phishing link |
| 08:40       | Malicious attachment executed     |
| 08:41       | Sensitive file access spike       |
| 08:25–08:28 | DNS exfiltration begins           |
| 09:23+      | Cloud data exfiltration           |

---

## 🎯 Full Attack Chain

1. 📧 Phishing Email Delivered
2. 🌐 User Clicks Malicious Link
3. 📎 Macro File Executed
4. 💻 PowerShell Payload Runs
5. 🔒 Persistence Established
6. 📦 Sensitive Data Accessed
7. 🌍 DNS Exfiltration
8. ☁️ Cloud Upload Exfiltration

---

# 🚨 Final Incident Summary

## 🔴 Severity: HIGH

## 📌 Impact

* Multiple users targeted
* Endpoint compromise confirmed
* Sensitive data exfiltrated

---

## 🔍 Root Cause

Successful phishing attack with macro-enabled attachment.

---

# 🛡️ Recommendations

### 🔐 Immediate Actions

* Block malicious domain
* Isolate affected endpoints
* Disable compromised accounts

### 🧪 Investigation Improvements

* Monitor PowerShell usage
* Alert on Office → PowerShell execution

### 🧰 Preventive Controls

* Block macro-enabled attachments (.docm)
* Implement email filtering & sandboxing
* Deploy DNS monitoring rules
* Enable Data Loss Prevention (DLP)

---

# 💡 Key Takeaways

* Phishing remains the most effective initial access vector
* Behavioral detection is more reliable than signature-based detection
* Multi-source log correlation is critical in SOC investigations

---

# 🏁 Outcome

This investigation demonstrates:

✅ End-to-end SOC analysis
✅ Multi-log correlation
✅ Threat detection using SPL
✅ Real-world incident response workflow

---
## Author
Varrun Vashisht
