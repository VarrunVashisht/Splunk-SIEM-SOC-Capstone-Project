# 📊 DNS Data Exfiltration Detection Dashboard

## 🎯 Objective

The purpose of this dashboard is to **detect potential data exfiltration over DNS traffic**.

Attackers often exploit DNS as a covert communication channel because it is:

* Widely allowed across networks
* Rarely inspected deeply
* Capable of carrying encoded data

This dashboard helps security teams:

* Identify **compromised hosts**
* Detect **suspicious domains**
* Monitor **abnormal outbound data transfers**

---

## 📂 Data Source

| Attribute       | Value                          |
| --------------- | ------------------------------ |
|**index**        | `soc_project`                  |
|**sourcetype**   | `dns.log`                      |
| **Fields Used** | `src_ip`, `query`, `bytes_out` |

---

## 🔍 Problem Statement

Traditional security tools may fail to detect DNS-based exfiltration because:

* DNS traffic is considered **legitimate by default**
* Data can be hidden inside **subdomains**
* Exfiltration often occurs in **small bursts to avoid detection**

**Example attack pattern:**

```
sensitive-data.chunk1.evil.com
sensitive-data.chunk2.evil.com
```

---

## 🧠 Detection Strategy

This dashboard uses **five complementary detection techniques** to identify exfiltration activity.

---

### 1️⃣ Volume Analysis

#### 🔎 Query

```spl
index=soc_project sourcetype=dns.log
| stats sum(bytes_out) as total_bytes
```

#### 📌 Explanation

* Aggregates total outbound data sent to suspicious domains

#### 🎯 Why it matters

* DNS queries are typically **small**
* Large data transfer volumes may indicate **data exfiltration**

#### ✅ Outcome

* Total volume of potentially exfiltrated data
* 
<img width="1478" height="575" alt="image" src="https://github.com/user-attachments/assets/3040897a-e6c5-4cd4-a345-2af3f57bca21" />

---

### 2️⃣ Host-Based Analysis

#### 🔎 Query

```spl
index=soc_project sourcetype=dns.log query="*.evil.com"
| stats sum(bytes_out) as total_bytes by src_ip
| sort - total_bytes
```

#### 📌 Explanation

* Groups traffic by source IP address

#### 🎯 Why it matters

* Compromised hosts tend to generate **higher outbound traffic**

#### ✅ Outcome

* Ranked list of **potentially infected systems**

<img width="476" height="264" alt="image" src="https://github.com/user-attachments/assets/5118fdd6-b8ff-447c-8981-9c31469f33f7" />


---

### 3️⃣ Time-Based Analysis

#### 🔎 Query

```spl
index=soc_project sourcetype=dns.log query="*.evil.com"
| timechart span=3m sum(bytes_out)
```

#### 📌 Explanation

* Visualizes traffic trends over time

#### 🎯 Why it matters

* Exfiltration often occurs in:

  * **Bursts**
  * **Scheduled intervals**
  * **Low-and-slow patterns**

#### ✅ Outcome

* Timeline showing **when suspicious activity occurred**

<img width="1428" height="283" alt="image" src="https://github.com/user-attachments/assets/f71f57f2-9330-4af1-b332-d95dc8e4677d" />


---

### 4️⃣ Domain Frequency Analysis

#### 🔎 Query

```spl
index=soc_project sourcetype=dns.log query="*.evil.com"
| stats count by query
| sort - count
```

#### 📌 Explanation

* Counts how often each domain is queried

#### 🎯 Why it matters

* Malicious domains are often:

  * Reused frequently
  * Programmatically generated

#### ✅ Outcome

* Identification of **high-frequency suspicious domains**

<img width="643" height="136" alt="image" src="https://github.com/user-attachments/assets/09dcfc4b-122f-4067-9e74-5322d3831d94" />

---

### 5️⃣ Anomaly Detection

#### 🔎 Query

```spl
index=soc_project sourcetype=dns.log query="*.evil.com"
| where bytes_out > 10000000
| stats count by src_ip, query
```

#### 📌 Explanation

* Filters unusually large DNS responses

#### 🎯 Why it matters

* Normal DNS traffic is:

  * Lightweight (~bytes to KB)
* Large payloads are **highly suspicious**

#### ✅ Outcome

* Detection of **high-risk exfiltration events**

<img width="1440" height="406" alt="image" src="https://github.com/user-attachments/assets/d6ffde0d-991e-4c07-aa6c-21fe5d7d5461" />

---

## 📊 Complete Dashboard 

[D2_Data_Exfiltration.pdf](https://github.com/user-attachments/files/27401714/D2_Data_Exfiltration.pdf)


---

##  Key Findings

The dashboard may reveal:

* Multiple hosts communicating with a suspicious domain
  → `data.exfil.evil.com`

* High outbound data volumes
  → Strong indicator of data leakage

* Burst-based activity patterns
  → Suggest controlled attacker behavior

* Multiple affected systems
  → Indicates **possible lateral movement or widespread compromise**

---


## 💼 Business Value

This dashboard enables organizations to:

* Detect **covert exfiltration techniques**
* Reduce **mean time to detect (MTTD)**
* Accelerate **incident response**
* Prevent **large-scale data loss**

---

## 🛠️ Recommended Actions

1. **Isolate affected hosts (`src_ip`)**
2. **Block malicious domains** (e.g., `*.evil.com`)
3. **Inspect DNS logs for encoded payloads**
4. **Perform endpoint forensic analysis**
5. **Deploy DNS monitoring & filtering controls**

---

## 🧾 Author:
Varrun Vashisht

Cybersecurity Professional
