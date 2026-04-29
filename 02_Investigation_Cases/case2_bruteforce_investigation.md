# 🛡️ Case 2: Brute Force Attack Investigation

## 🎯 Objective

Detect and investigate a potential brute force attack using authentication logs within `index="soc_project"`.

---

## 🔍 Subcase 1: Failed Login Spike Detection

### ❓ Why

Brute force attacks typically begin with a spike in failed login attempts.

### 🔍 SPL Query

```spl
index="soc_project" sourcetype=combined action=login status=failed
| timechart span=1m count by user
```
<img width="1907" height="723" alt="image" src="https://github.com/user-attachments/assets/edb3b8fc-d670-4508-98b6-39f928bbc052" />


### What timechart does
At its core, timechart:

Groups events into time buckets (like minutes, hours, days)

Applies an aggregation function (count, sum, avg, etc.)

Outputs a table ready for time-series charts

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
index="soc_project" sourcetype=combined status=failed
| stats count by src_ip
| sort -count
```
<img width="1883" height="834" alt="image" src="https://github.com/user-attachments/assets/5ffd1e40-862d-496d-89e2-d5743dd6b6e8" />

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
index="soc_project" sourcetype=combined status=failed
| stats count by src_ip, user
| sort -count
```
<img width="1891" height="774" alt="image" src="https://github.com/user-attachments/assets/85402f2e-4d8d-4726-ba15-5cae396e32d7" />

### 🧠 Analysis

* Repeated attempts on same users from same src_ip
* Indicates attacker knows valid accounts

### ✅ Conclusion

High-frequency users = **targeted victims**

---

## 🔓 Subcase 4: Successful Login After Failures

### ❓ Why

Critical indicator of account compromise.

### 🔍 SPL Query

```spl
index="soc_project" sourcetype=combined
| transaction user maxspan=5m
| search status=failed status=success
```

### Breakdown


**transaction user maxspan=5m**

* Groups events by `user`
* Combines events that occur within a 5-minute window
* Each result represents a single user transaction (session-like)

**search status=failed status=success**

* Filters transactions that contain:

  * at least one `status=failed`
  * AND at least one `status=success`
* Both conditions must exist in the same transaction

### Result

Returns users who had both failed and successful events within 5 minutes
(e.g., failed login followed by success)

### Notes

* `transaction` is resource-intensive on large datasets
* Useful for detecting retry or suspicious login behavior

<img width="1863" height="842" alt="image" src="https://github.com/user-attachments/assets/b804e7ce-2a2d-48e8-b9eb-da8d39454d2b" />

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
index="soc_project" sourcetype=combined action=lockout
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
index="soc_project" sourcetype=combined
| iplocation src_ip
| stats count by Country user
```
#### To find non-local/ private IPs
```spl
index="soc_project" sourcetype=combined
| where NOT cidrmatch("192.168.0.0/16", src_ip)
| iplocation src_ip
| stats count by Country user
```

### SPL Query Explanation

**iplocation src_ip**

* Adds geographic info based on `src_ip`
* Creates fields like:

  * `Country`
  * `City`
  * `Region`
  * `lat`, `lon`
    
**cidrmatch** = “Is this IP inside this network range?”

**stats count by Country user**

* Groups events by:

  * `Country`
  * `user`
* Counts number of events for each combination

### Result

Shows how many events each **user** generated from each **country**

Example:

* user A → 50 events from USA
* user A → 10 events from India
* user B → 30 events from Australia

### Use Cases

* Detect logins from unusual countries
* Monitor user activity by location
* Identify suspicious geo behavior

### Notes

* `iplocation` depends on IP-to-geo database accuracy
* Private/internal IPs may not return location data


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
index="soc_project" sourcetype=combined status=failed
| stats dc(user) as unique_users by src_ip
| where unique_users > 5
```
### SPL Query Explanation

```spl
index="soc_project" sourcetype=combined status=failed
| stats dc(user) as unique_users by src_ip
| where unique_users > 1
```

### SPL Query Breakdown

**Base search**

* Searches failed events only:

```spl
status=failed
```

**stats dc(user) as unique_users by src_ip**

* Groups events by `src_ip`
* `dc(user)` = **distinct count** of users
* Renames result as `unique_users`

👉 Meaning:

* Count how many **different users** failed login from each IP

**where unique_users > 1**

* Filters results to only show:

  * IPs that tried **more than 1 unique user**

### Result

Shows IP addresses that attempted failed logins for **multiple users**

### Use Case (SOC 🔐)

* Detects **brute-force attacks**
* Detects **credential stuffing**
* Identifies suspicious IPs targeting multiple accounts

### Example Output

```
src_ip         unique_users
192.168.1.10   5
192.168.1.15   3
```

👉 These IPs attempted failed logins on multiple users

### Notes

* `dc()` = distinct count (very important for detection logic)
* Works best when `user` field is properly extracted
* Combine with time filters for better detection (e.g., last 5m)


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
index="soc_project" sourcetype=combined status=failed
| stats values(user) by src_ip
```
**stats values(user) by src_ip**

### SPL Query Explanation

**Base search**

* Filters only failed events:

```spl
status=failed
```

**stats values(user) by src_ip**

* Groups events by `src_ip`
* `values(user)` = returns **unique list of users** (no duplicates)

👉 Meaning:

* For each IP, show **which users had failed attempts**

### Result

Displays each IP with the list of users it tried:

### Example Output
```
src_ip         values(user)
192.168.1.10   [user1, user2, admin]
192.168.1.11   [user3]
```

### Use Case (SOC 🔐)

* Identify which accounts an IP is targeting
* Spot **credential stuffing / brute-force attempts**
* Investigate suspicious IP behavior
  
### Notes
* `values()` = unique list (unordered)
* Use `dc(user)` if you only need the count
* Use `list(user)` if you want all values (including duplicates)

👉 Meaning:

For each IP, show which users had failed attempts

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
index="soc_project" sourcetype=combined status=success
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
index="soc_project" sourcetype=combined
| sort _time
| table _time user src_ip status
```
### SPL Query Explanation


**sort _time**

* Sorts events by time (`_time`)
* Default = **ascending order (oldest → newest)**
* Use `sort - _time` for newest first

---

**table _time user src_ip status**

* Selects and displays only these fields:

  * `_time` → event timestamp
  * `user` → username
  * `src_ip` → source IP
  * `status` → success/failed

👉 Removes all other fields for a clean view

---

### Result

Displays a **timeline of events** with key fields:

<img width="1881" height="746" alt="image" src="https://github.com/user-attachments/assets/d571d56a-0444-4d4c-9de2-0059878c4844" />


---

### Use Case (SOC 🔐)

* Investigate **event sequence over time**
* Track login attempts (fail → success)
* Correlate user activity with IPs
* Build timelines during incident analysis

---

### Notes

* `_time` is the default timestamp field in Splunk
* `table` is used for **display only** (not aggregation)
* Sorting large datasets can be **slow** — use with time filters when possible


### 🧠 Analysis

From logs :

* Early phase: normal activity
* Mid phase: spike in failures
* Later phase: successful compromise

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

## Author:
Varrun Vashisht

