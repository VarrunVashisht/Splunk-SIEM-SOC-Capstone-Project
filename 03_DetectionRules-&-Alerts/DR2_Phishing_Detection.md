# 🥇 DETECTION 2 — Advanced Phishing Campaign 

We’re not just detecting “emails”…
We’re detecting a **multi-stage attack chain**:

> 📧 Phishing Email → 📎 Macro Execution → 💻 User Activity

---

## 📌 Why This Detection is ADVANCED

Most beginners stop at:

> “attachment = .docm → alert”

❌ That’s weak.

We will:

* Correlate **email + endpoint + behavior**
* Detect **campaign pattern**
* Reduce false positives significantly

---

# 🧠 1. Attack Understanding 

### 🔥 Attack Flow

1. Attacker sends phishing email
2. Attachment: `.docm` (macro-enabled)
3. User opens file
4. Macro executes → spawns process
5. System compromised

---

## 📂 Evidence from YOUR logs

### Email Logs

* Same sender → multiple users
* Macro attachment: `.docm` 

### Windows Logs

* Process creation events (EventCode 4688) 

👉 This allows **cross-source detection (VERY POWERFUL)**

---

# 🔍 2. Detection Hypothesis

> If a sender distributes macro attachments to multiple users AND those users execute processes shortly after → high-confidence phishing attack

---

# 🔎 3. Beginner Detection (Baseline)

```spl
index=soc_project sourcetype =email.log attachment="*.docm"
| stats count by sender
| where count > 5
```
<img width="1899" height="541" alt="image" src="https://github.com/user-attachments/assets/6a4df986-4a12-4633-a9b8-ad0a114f5b96" />


### ❌ Problem:

* No execution confirmation
* High false positives (IT emails, training, etc.)

---

# ⚙️ 4. Intermediate Detection

```spl
index=soc_project sourcetype =email.log attachment="*.docm"
| stats values(recipient) as users count by sender
| where count > 5
```
<img width="1911" height="737" alt="image" src="https://github.com/user-attachments/assets/e6a4f2da-7a81-4d25-aff3-4cd76cb70781" />


### ✅ Better:

* Detects campaign pattern
* Still lacks endpoint validation

---

# 🚀 5. ADVANCED DETECTION (Correlation-Based)

```spl
index=soc_project sourcetype =email.log attachment="*.docm"
| rename recipient as user
| stats count values(user) as targeted_users by sender
| where count > 5
| join user [
    search index=windows.log EventCode=4688
    | stats count by User
    | rename User as user
]
| stats values(user) as affected_users count by sender
| where count > 2
```

---

## 🧠 Why this is POWERFUL

* Detects **mass phishing**
* Confirms **user interaction (process execution)**
* Reduces noise dramatically
* Moves from **signal → evidence**

---

# 💡 EVEN MORE ADVANCED (Time Correlation)

```spl
index=soc_project sourcetype =email.log attachment="*.docm"
| rename recipient as user
| bin _time span=5m
| stats count values(user) as users by sender, _time
| where count > 5
| join user [
    search index=windows.log EventCode=4688
    | bin _time span=5m
    | stats count by User, _time
    | rename User as user
]
```

👉 Now you’re detecting:
**“User executed something within 5 minutes of phishing email”**

---

# 📄 Detection-as-Code (YAML)

📂 `detections/phishing_macro_advanced.yaml`

```yaml
title: Advanced Phishing Campaign with Macro Execution
id: DET-002

description: >
  Detects phishing campaigns distributing macro-enabled attachments (.docm)
  and correlates with endpoint process execution to confirm user interaction.

spl: |
  index=email attachment="*.docm"
  | rename recipient as user
  | stats count values(user) as targeted_users by sender
  | where count > 5
  | join user [
      search index=windows EventCode=4688
      | stats count by User
      | rename User as user
  ]
  | stats values(user) as affected_users count by sender
  | where count > 2

severity: Critical
confidence: High

mitre:
  - T1566.001
  - T1204.002

data_sources:
  - Email Logs
  - Windows Event Logs

false_positives:
  - Internal IT campaigns with macro-enabled documents
  - Software deployment scripts

tuning:
  - Exclude trusted senders
  - Add domain reputation filtering
  - Add process filtering (e.g., winword.exe → powershell.exe)

tags:
  - phishing
  - macro
  - initial-access
```

---

# 📉 Before vs After 

### ❌ Before (Basic Detection)

```spl
index=soc_project sourcetype =email.log attachment="*.docm"
```

👉 Result:
* Tons of alerts
* Not actionable

---

### ✅ After (Advanced Detection)

```spl
email + endpoint correlation
```

👉 Result:

* Only **real attack signals**
* High confidence
* SOC actionable

---

# 🗺️ MITRE ATT&CK Mapping

| Technique | Description                     |
| --------- | ------------------------------- |
| T1566.001 | Spearphishing Attachment        |
| T1204.002 | User Execution (Malicious File) |

---

# 🧪 Validation (From YOUR Logs)

* Sender repeatedly sends `.docm` files 
* Users generate process events after login 

👉 This detection will **trigger correctly**

---

# 🧱 WHAT YOU JUST BUILT

This is now **mid-to-senior level detection engineering**:

✅ Multi-source correlation
✅ Behavioral validation
✅ MITRE mapping
✅ Detection-as-code
✅ SOC-ready logic

---

## Author:
Varrun Vashisht
