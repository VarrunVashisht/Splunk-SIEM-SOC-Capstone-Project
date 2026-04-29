# 🛡️ Case 2: Brute Force Attack Investigation

## 🎯 Objective

Detect and investigate a potential brute force attack using authentication logs within `index="soc_project"`.

---

## 🔍 Subcase 1: Failed Login Spike Detection

### ❓ Why

Brute force attacks typically begin with a spike in failed login attempts.

### 🔍 SPL Query

```spl
index="soc_project" sourcetype=auth.log action=login status=failed
| timechart span=1m count by user
```

### 🧠 Analysis

Baseline logs show normal successful logins early 
A spike in failures later indicates anomalous behavior.

👉 A spike in failures = automated attack pattern

### ✅ Conclusion

Abnormal surge in failed logins detected → **initial brute force indicator**

---

## 🌍 Subcase 2: Source IP Analysis

### ❓ Why

Attackers often originate from a single IP or rotating IPs.

### 🔍 SPL Query

```spl
index="soc_project" sourcetype=auth.log status=failed
| stats count by src_ip
| sort -count
```

### 🧠 Analysis

* High volume from one IP → targeted attack
* Distributed IPs → botnet / credential stuffing

### ✅ Conclusion

Identified attacker origin pattern.

---

## 👤 Subcase 3: Username Enumeration

### ❓ Why

Attackers test valid usernames before brute forcing passwords.

### 🔍 SPL Query

```spl
index="soc_project" sourcetype=auth.log status=failed
| stats count by user
| sort -count
```

### 🧠 Analysis

* Repeated attempts on same users
* Indicates attacker knows valid accounts

### ✅ Conclusion

High-frequency users = **targeted victims**

---

## 🔓 Subcase 4: Successful Login After Failures

### ❓ Why

Critical indicator of account compromise.

### 🔍 SPL Query

```spl
index="soc_project" sourcetype=auth.log
| transaction user maxspan=5m
| search status=failed status=success
```

### 🧠 Analysis

Sequence pattern:
failed → failed → success

👉 Indicates password eventually guessed.

### ✅ Conclusion

Confirmed **account takeover event**

---

## 🚫 Subcase 5: Account Lockout Events

### ❓ Why

Security controls trigger lockouts after multiple failures.

### 🔍 SPL Query

```spl
index="soc_project" sourcetype=auth.log action=lockout
```

### 🧠 Analysis

* Lockouts = brute force threshold reached
* Highlights impacted accounts

### ✅ Conclusion

Multiple lockouts → attack intensity is high.

---

## 🌐 Subcase 6: Geographic Anomalies

### ❓ Why

Login from unusual location indicates suspicious activity.

### 🔍 SPL Query

```spl
index="soc_project" sourcetype=auth.log
| iplocation src_ip
| stats count by Country user
```

### 🧠 Analysis

* Users appearing from foreign regions
* Impossible travel scenarios

### ✅ Conclusion

Potential attacker using external infrastructure.

---

## 🔁 Subcase 7: Credential Stuffing Patterns

### ❓ Why

Attackers reuse leaked credentials across multiple accounts.

### 🔍 SPL Query

```spl
index="soc_project" sourcetype=auth.log status=failed
| stats dc(user) as unique_users by src_ip
| where unique_users > 5
```

### 🧠 Analysis

* One IP targeting many users
* Classic credential stuffing behavior

### ✅ Conclusion

Detected **automated credential reuse attack**

---

## 🎯 Subcase 8: Multi-Account Targeting

### ❓ Why

Brute force attacks often scale horizontally.

### 🔍 SPL Query

```spl
index="soc_project" sourcetype=auth.log status=failed
| stats values(user) by src_ip
```

### 🧠 Analysis

* Same IP attacking multiple accounts
* Confirms broad attack scope

### ✅ Conclusion

Wide attack surface targeted.

---

## 🧬 Subcase 9: Persistence After Access

### ❓ Why

Attackers attempt to maintain access after compromise.

### 🔍 SPL Query

```spl
index="soc_project" sourcetype=auth.log status=success
| stats count by user src_ip
```

### 🧠 Analysis

* Repeated successful logins post-compromise
* Same IP reused → persistence

### ✅ Conclusion

Attacker maintaining foothold.

---

## 🧭 Subcase 10: Attack Timeline Reconstruction

### ❓ Why

SOC must reconstruct the full attack sequence.

### 🔍 SPL Query

```spl
index="soc_project" sourcetype=auth.log
| sort _time
| table _time user src_ip status
```

### 🧠 Analysis

From logs :

* Early phase: normal activity
* Mid phase: spike in failures
* Later phase: successful compromise

### 📊 Timeline

| Time         | Event              |
| ------------ | ------------------ |
| 08:00        | Normal logins      |
| Attack Start | Failed login spike |
| Later        | Successful login   |
| Post         | Persistent access  |

### ✅ Conclusion

Full brute force lifecycle identified.

---

## 🚨 Final Verdict (SOC Summary)

* **Attack Type:** Brute Force / Credential Stuffing
* **Impact:** Account Compromise
* **Risk Level:** 🔴 HIGH

### Indicators

* Failed login spikes
* Multi-user targeting
* Success after failures

---

## 🛡️ Recommended Actions

* Enforce MFA
* Block attacker IPs
* Reset compromised credentials
* Enable lockout policies
* Monitor for persistence

---

## 💥 Why This Stands Out

This investigation demonstrates:

* Detection logic
* Behavioral analysis
* Event correlation
* Timeline reconstruction
* SOC-level reporting

👉 Reflects real Tier 1 → Tier 2 analyst workflow
