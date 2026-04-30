# 🚨 Case 4: Command & Control (C2) Investigation

## 🎯 Objective

This investigation focuses on identifying Command & Control (C2) communication patterns using DNS, web, and system logs within Splunk.

C2 activity is a critical stage of an attack where compromised systems communicate with attacker-controlled infrastructure for:

* Receiving commands
* Exfiltrating data
* Maintaining persistence

---

# 🧩 Subcase 1: Suspicious DNS Queries

## ❓ Why

DNS is commonly abused because it is allowed in most networks. Attackers use it to:

* Communicate with malicious domains
* Exfiltrate data covertly

## 🎯 What

Identify domains that:

* Appear frequently
* Transfer unusually high data

## 🔍 Query

```spl
index="soc_project" sourcetype="dns.log"
| stats count by query
| sort -count
```

## 🔍 Query

```spl
index="soc_project" sourcetype="dns.log"
| stats count sum(bytes_out) as total_bytes by src_ip, query
| where total_bytes > 10000000
| sort -total_bytes
```
<img width="1881" height="862" alt="image" src="https://github.com/user-attachments/assets/940d3092-4f0e-4125-b2cf-197e99a8533b" />

## 🧠 How It Works

* `stats count by query` → counts how often each domain is queried
* `sum(bytes_out)` → calculates data sent out
* `where total_bytes > threshold` → filters abnormal traffic

## 📊 Analysis

Observed repeated queries to:

* suspicious domain with high outbound data → 

## ✅ Conclusion

This strongly indicates DNS-based data exfiltration or C2 communication.

---

# 🧩 Subcase 2: Beaconing Behavior Detection

## ❓ Why

C2 malware communicates at regular intervals (beaconing), unlike human-driven traffic.

## 🎯 What

Detect periodic (automated) communication patterns.

## 🔍 Query

```spl
index="soc_project" sourcetype="dns.log"
| bin _time span=5s
| stats count by _time, src_ip
```

## 🔍 Query

```spl
index="soc_project" sourcetype="dns.log"
| sort _time
| streamstats current=f last(_time) as prev_time 
by src_ip
| eval interval=_time - prev_time
| stats avg(interval) as avg_interval by src_ip
| where avg_interval < 10
```

## 🧠 How It Works

* `streamstats` → tracks previous event timestamp
* `eval interval` → calculates time difference
* `avg(interval)` → identifies consistent communication gaps

## 📊 Analysis

Consistent time intervals = automated beaconing behavior

## ✅ Conclusion

Detected potential malware beaconing to C2 infrastructure.

---

# 🧩 Subcase 3: Known Malicious Communication Patterns

## ❓ Why

Compromised systems communicate repeatedly with attacker infrastructure.

## 🎯 What

Identify systems with:

* High frequency communication
* High data transfer

## 🔍 Query

```spl
index="soc_project" sourcetype="dns.log"
| stats count by src_ip
| sort -count
```
<img width="1883" height="803" alt="image" src="https://github.com/user-attachments/assets/27138628-ceac-41a8-a453-96edc25ed73c" />

## 🔍 Query

```spl
index="soc_project" sourcetype="dns.log"
| stats count as ip_frequency, sum(bytes_out) as exfiltrate
by src_ip
| where exfiltrate > 30000000 and ip_frequency >3
| sort -exfiltrate
```
<img width="1888" height="864" alt="image" src="https://github.com/user-attachments/assets/90437fd0-a969-449c-b41c-6fda4ea006e3" />

## 🧠 How It Works

* Combines frequency + volume for risk detection

## 📊 Analysis

Multiple internal IPs show heavy activity → 

## ✅ Conclusion

Identified potentially compromised hosts.

---

# 🧩 Subcase 4: Encrypted Traffic Anomalies

## ❓ Why

Attackers hide communication inside encrypted web traffic.

## 🎯 What

Detect abnormal repeated connections to same domain.

## 🔍 Query

```spl
index="soc_project" sourcetype="web.log"
| stats count by url
```
<img width="1907" height="886" alt="image" src="https://github.com/user-attachments/assets/33519c81-e36c-4775-8b11-14416e8351e0" />


## 🔍 Advanced Query

```spl
index="soc_project" sourcetype="web.log"
| stats count
by user, url
| where count >20
| sort - count
```
<img width="1894" height="723" alt="image" src="https://github.com/user-attachments/assets/b7e15a23-9148-4ba3-8af2-3a614bb8595e" />

## 🧠 How It Works

* Repeated access to same URL = automated traffic

## 📊 Analysis

Baseline shows normal browsing behavior 
Outliers indicate suspicious communication

## ✅ Conclusion

Possible encrypted C2 over HTTP/HTTPS.

---

# 🧩 Subcase 5: Domain Generation Algorithm (DGA)

## ❓ Why

Malware uses randomly generated domains to evade detection.

## Domain Generation Algorithm (DGA) 

## What is it?
A DGA is a technique malware uses to automatically create lots of domain names.

## Why?
To avoid being blocked.
If one domain is taken down, it just uses another.

## How it works
- Malware and attacker share the same formula
- They use things like date + secret key
- Both generate the same list of domains each day
- Malware tries them until one works

## Simple example
Day 1:
abc123.com, test456.net

Day 2:
xyz789.com, hello321.org

## Key idea
DGA = malware keeps changing its "contact address" so it can always reconnect.

## 🎯 What

Identify unusual domain patterns.

## 🔍  Query

```spl
index="soc_project" sourcetype="dns.log"
| stats count by query
```
<img width="1898" height="619" alt="image" src="https://github.com/user-attachments/assets/4379240e-cafd-4327-ade1-8ae68df2a692" />

## 🔍 Advanced Query

```spl
index="soc_project" sourcetype="dns.log"
| eval length=len(query)
| where length > 13
| stats count by query
```
<img width="1903" height="641" alt="image" src="https://github.com/user-attachments/assets/ab4aaaea-edcc-47f0-8e2e-2c876b1c48cb" />

## 🧠 How It Works

* `len(query)` → measures domain complexity
* Longer/random domains = suspicious
* eval = Creates a new field `length` that stores the number of characters in `query`.
  
## 📊 Analysis

Suspicious domains differ from normal patterns

## ✅ Conclusion

Possible DGA-based communication.

---

# 🧩 Subcase 6: Unusual Port Usage

## ❓ Why

C2 often avoids standard ports (80, 443).

## 🎯 What

Detect abnormal port usage.

## 🔍 Query

```spl
index="soc_project"
| stats count by src_ip
```

## 🔍 Advanced Query

```spl
index="soc_project"
| stats count by src_ip, dest_port
| where dest_port!=80 AND dest_port!=443
```

## 🧠 Analysis

Non-standard ports = stealth communication channels

## ✅ Conclusion

Suspicious network activity identified.

---

# 🧩 Subcase 7: Persistent Outbound Connections

## ❓ Why

C2 requires continuous communication.

## 🎯 What

Find systems with repeated outbound connections.

## 🔍 Query

```spl
index="soc_project" sourcetype="dns.log"
| stats count by src_ip
```

## 🔍 Advanced Query

```spl
index="soc_project" sourcetype="dns.log"
| stats count by src_ip
| where count > 4
```
<img width="1894" height="581" alt="image" src="https://github.com/user-attachments/assets/c182274c-1fb5-4a78-a60e-532d6138a340" />

## 📊 Analysis

High-frequency activity detected

## ✅ Conclusion

Likely persistent C2 communication.

---

# 🧩 Subcase 8: Data Transfer Patterns

## ❓ Why

C2 often used for data exfiltration.

## 🎯 What

Identify abnormal data transfers.

## 🔍 Query

```spl
index="soc_project" sourcetype="dns.log"
| stats sum(bytes_out) by src_ip
```

## 🔍 Advanced Query

```spl
index="soc_project" sourcetype="dns.log"
| stats sum(bytes_out) as total by src_ip
| where total > 20000000
```
<img width="1883" height="791" alt="image" src="https://github.com/user-attachments/assets/bf47abf1-87d3-42ae-85cf-bdb568257eb3" />


## 🧠 How It Works

* Aggregates outbound data
* Filters high-value transfers

## 📊 Analysis

Large transfers observed → 

## ✅ Conclusion

Confirmed potential data exfiltration.

---

# 🧩 Subcase 9: Endpoint Correlation

## ❓ Why

Need to map suspicious activity to users.

## 🎯 What

Identify which users are affected.

## 🔍 Query

```spl
index="soc_project"
| stats values(user) by src_ip
```

## 🔍 Advanced Query

```spl
index="soc_project"
| stats values(user) values(query) by src_ip
```
<img width="1458" height="962" alt="image" src="https://github.com/user-attachments/assets/270c9c1a-3736-4193-8233-83514755f81f" />


## 🧠 Analysis

Links network activity to user identity

## ✅ Conclusion

Identified compromised endpoints and users.

---

# 🧩 Subcase 10: C2 Timeline Reconstruction

## ❓ Why

SOC must understand full attack progression.

## 🎯 What

Reconstruct sequence of events.

## 🔍 Query

```spl
index="soc_project"
| sort _time
| table _time user src_ip query
```

## 🔍 Advanced Query

```spl
index="soc_project"
| transaction src_ip maxspan=30m
| table _time src_ip duration eventcount
```
<img width="1868" height="1013" alt="image" src="https://github.com/user-attachments/assets/28afccd4-df63-450d-aa98-9cd5c6e8f29e" />

## 🧠 How It Works

* `transaction` groups related events
* `maxspan` defines investigation window
* 'duration & eventcount' - They are created automatically by the `transaction` command.
                            It groups multiple events with the same `src_ip` into one transaction.                            
                            * eventcount → number of events in that transaction  
                            * duration   → time difference between first and last event 

## 📊 Analysis

Shows complete lifecycle of attack

## ✅ Conclusion

Successfully reconstructed C2 communication timeline.

---

# 🔥 Final Summary

This investigation demonstrated:

* Detection of DNS-based C2 activity
* Identification of beaconing behavior
* Detection of data exfiltration
* Correlation across users and endpoints
* Full attack timeline reconstruction

---

## 🧠 Key Analyst Takeaways

* DNS is a critical detection point
* Behavioral patterns are stronger than signatures
* Correlation across logs is essential
* Volume + frequency = strong indicators of compromise

---

## 🚀 Outcome

This case demonstrates real-world SOC analyst capabilities including:

* Threat detection
* Log correlation

## Author:
Varrun Vashisht
* Incident investigation
* Attack reconstruction
