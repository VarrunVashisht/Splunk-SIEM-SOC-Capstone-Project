# 🧪 Dataset Generation Engine (SOC Simulation)

## 🎯 Objective

To simulate a real-world Security Operations Center (SOC) environment, a custom Python-based dataset generator was developed.

This script creates **realistic, multi-source security logs** that replicate enterprise-level attack scenarios across multiple domains.

---

## 🧠 Why This Approach?

In real environments:

* Logs are generated from **multiple systems**
* Data is **noisy and unstructured**
* Attacks happen over **time, not instantly**
* Multiple users and systems are involved

This generator simulates all of the above, making the dataset:

✅ Realistic
✅ Correlated
✅ Suitable for deep investigation

---

## ⚙️ How the Script Works

The script generates logs using:

* Randomized users and IPs
* Time-based event progression
* Separation of baseline vs attack activity

Each log entry is timestamped and mapped to a specific **index/source type**.

---

## 📂 Log Sources Generated

| Log Type      | Description                        |
| ------------- | ---------------------------------- |
| `web.log`     | Web traffic, URLs, attacks         |
| `windows.log` | Process creation, system activity  |
| `dns.log`     | DNS queries, C2 communication      |
| `email.log`   | Phishing emails                    |
| `auth.log`    | Login activity (success/failure)   |
| `cloud.log`   | Cloud API usage                    |
| `file.log`    | File access, downloads, ransomware |

---

## 🔄 Data Generation Flow

The script follows a **timeline-based simulation**:

### 🟢 Phase 1: Baseline Activity

* Normal user browsing
* Legitimate processes
* Successful logins

👉 Purpose: Create realistic noise

---

### 🔴 Phase 2–11: Attack Scenarios

Each block simulates a different attack case:

---

## ⚔️ Case 1: Phishing Attack

* Phishing emails sent
* Users click malicious links
* Macro-enabled files executed
* PowerShell launched
* DNS callbacks triggered

---

## 🌐 Case 2: Web Application Attack

* SQL injection attempts
* Web shell upload
* Remote command execution

---

## 🧑‍💼 Case 3: Insider Threat

* Abnormal login times
* Large file downloads
* Sensitive data access

---

## 🔐 Case 4: Brute Force Attack

* Multiple failed logins
* Eventual successful compromise

---

## 🦠 Case 5: Ransomware

* Suspicious process execution
* File encryption activity

---

## 🌍 Case 6: Command & Control (C2)

* Repeated DNS queries to malicious domains
* Beaconing behavior

---

## 🛠️ Case 7: Privilege Escalation

* Admin privilege assignment
* Elevated access events

---

## ☁️ Case 8: Cloud Attack

* Suspicious API calls
* Large data uploads

---

## 🔄 Case 9: Living-off-the-Land (LOLBins)

* Abuse of legitimate tools (e.g., certutil)

---

## 🧬 Case 10: Advanced Persistent Threat (APT)

* Multi-stage attack:

  * Initial access
  * Lateral movement
  * Data exfiltration

---

## ⏱️ Time-Based Simulation

Each log entry is generated with:

* Incremental timestamps
* Sequential attack stages
* Overlapping activities across users

👉 This allows:

* Timeline reconstruction
* Correlation across events

---

## 🧪 Realism Features

The dataset includes:

* Noise (normal activity)
* Partial attacks (not all users compromised)
* Multiple users and endpoints
* Mixed benign and malicious patterns

---

## 📦 Output Files

After execution, the script generates:

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

---

## 🔗 Combined Log

The `combined.log` file merges all sources into one stream.

👉 Useful for:

* Correlation queries
* Timeline reconstruction
* Quick testing

---

## 🛠️ How to Run

```bash
python generate_soc_dataset.py
```

---

## 📥 Splunk Ingestion Strategy

Upload logs into separate indexes:

| File        | Index   |
| ----------- | ------- |
| web.log     | web     |
| windows.log | windows |
| dns.log     | dns     |
| email.log   | email   |
| auth.log    | auth    |
| cloud.log   | cloud   |
| file.log    | file    |

---

## 🧠 Key Learning Outcome

This dataset enables:

* Multi-source log correlation
* Real-world attack investigation
* Detection engineering using SPL
* SOC-style incident analysis

---

## 🚀 Summary

This custom dataset generator transforms the project from a basic lab into a:

🔥 Realistic SOC simulation
🔥 Multi-scenario investigation platform
🔥 Portfolio-ready security project
