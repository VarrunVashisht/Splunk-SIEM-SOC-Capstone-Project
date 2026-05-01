# 🚨 Case 6: Cloud Attack Investigation (Splunk SIEM)

---

## 📌 Overview

This case simulates a **real-world cloud attack lifecycle**, where an attacker:

1. Gains initial access via phishing
2. Compromises user credentials
3. Abuses cloud privileges
4. Stages sensitive data
5. Exfiltrates data using covert techniques

All analysis is performed using:

```spl
index="soc_project"
```

---

## 🎯 Learning Objectives

By completing this case, you will understand:

* How attackers abuse cloud APIs
* How to detect credential compromise patterns
* How to correlate logs across multiple sources
* How to identify data exfiltration techniques
* How to reconstruct a full attack timeline

---

## 📂 Data Sources

| Source       | Purpose                           |
| ------------ | --------------------------------- |
| Auth Logs    | Login activity                    |
| Cloud Logs   | API calls (PutObject, AssumeRole) |
| DNS Logs     | Data exfiltration indicators      |
| Email Logs   | Phishing detection                |
| File Logs    | Sensitive data access             |
| Web Logs     | User browsing                     |
| Windows Logs | Endpoint execution                |

---

# 🔥 Subcase 1: Suspicious API Calls

## 🎯 Use Case

Detect abnormal usage of cloud APIs such as `PutObject`.

### Why This Matters

Attackers often:

* Upload stolen data to external buckets
* Stage data before exfiltration
* Abuse APIs to bypass traditional defenses

---

## 🔎 Query

```spl
index=soc_project sourcetype=cloud.log action=PutObject
| stats count as total_record sum(bytes) as total_bytes 
by bucket
```
<img width="1907" height="495" alt="image" src="https://github.com/user-attachments/assets/aa48b86d-408e-4a16-b452-8e240dd54db5" />

## 🧠 Explanation

 **Aggregate Data**

   ```spl
   action=PutObject
   stats count as total_record sum(bytes) as total_bytes 
   ```

   * `count` → number of upload events
   * `sum(bytes)` → total data transferred
   * grouped by `bucket`
   * `PutObject` = putting a file from local machine into that cloud storage folder
   ---

## 🚀 Advanced Query

```spl
index=soc_project sourcetype=cloud.log action=PutObject
| bucket _time span=5m
| stats count sum(bytes) as total_bytes by _time, bucket
| eventstats avg(total_bytes) as avg_bytes stdev(total_bytes) as stdev_bytes by bucket
| eval anomaly=if(total_bytes > avg_bytes + (stdev_bytes), "Yes", "No")
| where anomaly="Yes"
```
<img width="1879" height="607" alt="image" src="https://github.com/user-attachments/assets/89404aca-0fc6-408b-ab5c-0d79f2663375" />

## 🧠 Deep Explanation

* `bucket _time span=5m`
  → Groups events into time windows of 5 minutes (trend analysis)

* `eventstats`
  → Calculates baseline without losing raw events

* `avg + stdev`
  → Statistical anomaly detection (standard deviation model)
👉 Standard deviation (stdev) tells you how much your data usually “moves around” from the average.

* `eval`
  → Creates flag field

* `where`
  → Filters only anomalies

---

## 📊 Analyst Insight

* Sudden spike = **data staging or exfiltration**
* Same bucket repeatedly = **controlled attacker destination**

---

# 🔥 Subcase 2: Unauthorized Access Attempts

## 🎯 Use Case

Detect brute force and credential compromise.

---

## 🔎 Query

```spl
index=soc_project sourcetype=auth.log status=failed
| stats count by user, src_ip
| sort -count
```

## 🧠 Explanation

* Filters failed logins
* Groups by:

  * user
  * source IP

👉 High count = brute force attempt

---

## 🚀 Advanced Query

```spl
index=soc_project sourcetype=auth.log
| stats 
count(eval(status="failed")) as failed 
count(eval(status="success")) as success 
by user, src_ip
| eval compromise=if(failed>5 AND success>0, "Yes","No")
| where compromise="Yes"
```
<img width="1876" height="599" alt="image" src="https://github.com/user-attachments/assets/bc537302-1a8f-45df-8c67-f34729e1a6f2" />

## 🧠 Deep Explanation

* `eval(status="failed")`
  → Converts condition into countable metric

* Detects:
  * many failures → then success

👉 Classic attacker behavior:
* Password guessing → success → access gained

---

## 📊 Analyst Insight

This indicates:

* Not just brute force
* **Confirmed account compromise**

---

# 🔥 Subcase 3: IAM Role Abuse

## 🎯 Use Case

Detect privilege escalation.

---

## 🔎 Intermediate Query

```spl
index=soc_project sourcetype=cloud.log action=AssumeRole
| stats count by user, role
```

## 🧠 Explanation

* Tracks how often users assume roles

---

## 🚀 Advanced Query

```spl
index=soc_project sourcetype=cloud action=AssumeRole
| stats dc(role) as role_count values(role) by user
| where role_count > 3
```

## 🧠 Deep Explanation

* `dc(role)` → distinct roles count
* `values(role)` → list of roles used

👉 More roles = more privilege exploration

---

## 📊 Analyst Insight

* Normal: 1–2 roles
* Suspicious: many roles

👉 Indicates **lateral movement / privilege escalation**

---

# 🔥 Subcase 4: Data Exposure Events

## 🎯 Use Case

Detect excessive data storage.

---

## 🔎 Query

```spl
index=soc_project sourcetype=cloud.log action=PutObject
| stats sum(bytes) by bucket
```
<img width="1895" height="476" alt="image" src="https://github.com/user-attachments/assets/337b509d-2b6b-4fd4-93e4-d3fcc5d36d73" />

---

## 🚀 Advanced Query

```spl
index=soc_project sourcetype=cloud.log action=PutObject
| stats sum(bytes) as total_bytes by bucket
| where total_bytes > 500000000
```

---

## 🧠 Explanation

* Identifies buckets storing large volumes of data

---

## 📊 Analyst Insight

* Could indicate:

  * Data aggregation
  * Public exposure risk
  * Pre-exfil staging

---

# 🔥 Subcase 5: Unusual Resource Creation

## 🎯 Use Case

Detect attacker-created infrastructure.

---

## 🔎 Intermediate Query

```spl
index=soc_project sourcetype=cloud.log action=Create*
| stats count by action
```

---

## 🚀 Advanced Query

```spl
index=soc_project sourcetype=cloud.log action=Create*
| bucket _time span=10m
| stats count by _time, action
| where count > 20
```

---

## 🧠 Explanation

* `Create*` matches all resource creation actions
* Spike detection highlights abnormal provisioning

---

## 📊 Analyst Insight

* Attackers create:

  * Backdoors
  * Compute resources
  * Persistence mechanisms

---

# 🔥 Subcase 6: Geographic Access Anomalies

## 🎯 Use Case

Detect impossible travel.

---

## 🔎  Query

```spl
index=soc_project sourcetype=auth.log
| stats dc(src_ip) by user
```
<img width="1898" height="683" alt="image" src="https://github.com/user-attachments/assets/5bad24ae-e2c9-4b4f-a89c-36fcf5f3c1c6" />

---

## 🚀 Advanced Query

```spl
index=soc_project sourcetype=auth.log
| iplocation src_ip
| stats dc(Country) as country_count values(Country) by user
| where country_count > 2
```

---

## 🧠 Explanation

* `iplocation` enriches logs with geolocation
* Multiple countries = anomaly
* Make sure src_ip should not be private ips, it should be public.

---

## 📊 Analyst Insight

* Same user across countries quickly
  👉 **credential theft confirmed**

---

# 🔥 Subcase 7: Credential Leakage Detection

## 🎯 Use Case

Detect phishing campaigns.

---

## 🔎 Query

```spl
index=soc_project sourcetype=email.log attachment=*.docm
| stats count by sender
```

---

## 🚀 Advanced Query

```spl
index=soc_project sourcetype=email.log attachment=*.docm
| stats count as total dc(recipient) as users_targeted 
by sender
| where users_targeted > 3
```

---
<img width="1903" height="522" alt="image" src="https://github.com/user-attachments/assets/01885811-c18d-4eef-a55b-d089fdddf52b" />

## 🧠 Explanation

* `.docm` = macro-enabled malware
* Counts spread across users

---

## 📊 Analyst Insight

* Single sender targeting many users
  👉 **phishing campaign**

---

# 🔥 Subcase 8: Storage Access Patterns

## 🎯 Use Case

Detect abnormal file access.

---

## 🔎 Query

```spl
index=soc_project sourcetype=file.log
| stats count sum(bytes) by user, file
```
<img width="1908" height="715" alt="image" src="https://github.com/user-attachments/assets/b3264b84-c95c-4f83-8919-944baaa5883b" />

---

## 🚀 Advanced Query

```spl
index=soc_project sourcetype=file.log
| bucket _time span=5m
| stats sum(bytes) as total_bytes by _time, user
| where total_bytes > 200000000
```
<img width="1877" height="576" alt="image" src="https://github.com/user-attachments/assets/428e7264-03e6-414d-914d-94544d9e22f6" />

---

## 📊 Analyst Insight

* High data access volume
  👉 insider threat OR compromised account

---

# 🔥 Subcase 9: Data Exfiltration

## 🎯 Use Case

Detect covert exfiltration via DNS.

---

## 🔎 Intermediate Query

```spl
index=soc_project sourcetype=dns.log query="*exfil*"
| stats sum(bytes_out) by src_ip
```

---

## 🚀 Advanced Query

```spl
index=soc_project sourcetype=dns.log query="*exfil*"
| bucket _time span=5m
| stats sum(bytes_out) as total_bytes by _time, src_ip
| where total_bytes > 100000000
```

<img width="1875" height="669" alt="image" src="https://github.com/user-attachments/assets/f07c0b5b-ce50-4762-9ed8-55d027b25a97" />

---

## 🧠 Explanation

* DNS used as covert channel
* Large outbound traffic = suspicious

---

## 📊 Analyst Insight

* Confirms **data exfiltration activity**

---

# 🔥 Subcase 10: Attack Timeline

## 🎯 Use Case

Reconstruct full attack lifecycle.

---

## 🔎 Query

```spl
index=soc_project
| stats count by _time, sourcetype
| sort _time
```

---

## 🚀 Advanced Query

```spl
index=soc_project
| eval stage=case(
    sourcetype="email.log","Initial Access",
    sourcetype="auth.log","Execution",
    sourcetype="cloud.log","Persistence/Exfiltration",
    sourcetype="dns.log","Exfiltration",
    true(),"Other"
)
| stats count by _time, stage
| sort _time
```

---

## 📊 Final Attack Story

1. Phishing emails delivered
2. Credentials compromised
3. Cloud APIs abused
4. Data staged
5. Data exfiltrated via DNS

---

# 🧠 Final Conclusion

```text
Phishing → Credential Theft → Privilege Abuse → Data Staging → Exfiltration
```

---

# 🚨 Recommended Actions

* Reset credentials
* Block malicious domains
* Audit IAM roles
* Restrict storage access
* Implement anomaly detection

---

## ⭐ Project Value

This case demonstrates:

* Real-world SOC investigation
* Threat hunting methodology
* Detection engineering skills
* Multi-source correlation

---

## Author:
Varrun Vashisht
